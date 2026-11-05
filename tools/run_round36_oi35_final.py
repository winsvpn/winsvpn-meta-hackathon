#!/usr/bin/env python3
"""Round 36 final vote on OI-35 only, after both objectors' resolution."""

import concurrent.futures
import importlib.util

spec = importlib.util.spec_from_file_location(
    "r36", "/Users/owner/xprize/winsvpnv3/tools/run_round36_surface_audit.py"
)
r36 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r36)

FINAL = """FINAL OI-35 TEXT (Arbiter-reconciled; supersedes all prior wording):
server/spain_crypto_payments_setup.sh dependency provisioning: two independent
checks, each binary name paired only with its own package name:
  command -v docker >/dev/null 2>&1 || apt-get install -y docker.io
  command -v git    >/dev/null 2>&1 || apt-get install -y git
No shared or disjunctive gate; docker present plus git absent installs git only
and never reinvokes the docker.io package. This adopts both objectors' stated
resolution verbatim. Vote: OI-35-FINAL: AGREE or OI-35-FINAL: DISAGREE: <one
falsifiable reason>. Nothing else is in scope."""


def prompt_fn(seat, cache):
    return r36.clean_text(
        "ROUND 36, FINAL VOTE ON OI-35 ONLY. Sealed rules apply.\n\n" + FINAL
    ), r36.SYSTEM_SEATS[seat]


def main():
    cache = r36.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = "stage6_" + seat
            if cache.get(key):
                print(f"[{seat}] stage6 cached", flush=True)
                continue
            prompt, system_role = prompt_fn(seat, cache)
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, prompt, "stage6"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, prompt, "stage6"))
            else:
                tasks[key] = (seat, ex.submit(r36.query_openrouter, prompt, system_role, 4000))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r36.update_cache(key, result)
            fname = f"debate_round36_stage6_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 36 stage6: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete", flush=True)
    for seat in r36.SEAT_KEYS:
        text = cache.get("stage6_" + seat, "")
        if not text:
            fname = r36.DOCS_EVIDENCE / f"debate_round36_stage6_{seat.replace('claude-opus5', 'opus5')}.md"
            text = fname.read_text(errors="replace")
        line = next(
            (l for l in text.splitlines() if "OI-35-FINAL" in l.upper()),
            "(no vote line found)",
        )
        print(f"{seat}: {line[:200]}")


if __name__ == "__main__":
    main()
