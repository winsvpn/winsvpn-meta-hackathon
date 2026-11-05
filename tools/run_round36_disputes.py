#!/usr/bin/env python3
"""Round 36 dispute cycle: Turn 2 cross-exam plus Turn 3 vote on the four
amended items, dispatched per seat through the stage runner's helpers."""

import importlib.util
import pathlib
import sys

RUNNER = "/Users/owner/xprize/winsvpnv3/tools/run_round36_surface_audit.py"
spec = importlib.util.spec_from_file_location("r36", RUNNER)
r36 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r36)

AMENDED = """
DISPUTED ITEM AMENDMENTS (Arbiter-reconciled after Turn 3 objections; all four
objections were verified as technically sound):

AMENDED OI-2 (Monero RPC credential placement): the objection stands: with
User=monero-wallet in the unit, a root:root 0600 config file is unreadable
(EACCES on open). Amended fix: write the wallet RPC config file owned
monero-wallet:monero-wallet mode 0600 containing rpc-login=user:pass, pass it
via --config-file, keep the unit itself root:root 0640 without any credential
in it, delete the stdout printf, and rotate the deployed password. Credential
stays out of argv and out of the unit; the service UID can read it.

AMENDED OI-18 (local rate limiter eviction): the objection stands: evicting
expired-first still evicts a fresh entry once all C entries are unexpired, so
entry C+1 resets the oldest client's window. Amended fix: evict expired
entries first; when no entry is expired (all fresh), refuse the request with
429 rate_limited instead of evicting a fresh entry. No fresh entry ever loses
its window to capacity pressure.

AMENDED OI-34 (stale asset pin vs download availability): both objections
stand: serving bytes that fail the pinned digest bypasses release review, and
hard-failing kills downloads. Amended fix: on digest mismatch, serve the most
recent still-pinned reviewed asset version (the previous reviewed release kept
in the versioned store) so downloaders only ever receive reviewed bytes;
record the mismatch loudly in the response's debug header and the ops log;
only when no reviewed prior version is available does the route fail closed
with 503. The deploy gate updates the pin atomically at release time.

AMENDED OI-35 (docker install names): the objection stands: command -v checks
a binary name, not a package name. Amended fix: detect the binary with
command -v docker and install the distro packages docker.io and git when the
binary or git is absent; the two names are separate constants, never substituted
into each other's checks.
"""

OBJECTIONS = {}
d = r36.DocsEvidences if hasattr(r36, "DocsEvidences") else None
for seat in r36.SEAT_KEYS:
    fname = f"debate_round36_stage3_{seat.replace('claude-opus5', 'opus5')}.md"
    OBJECTIONS[seat] = (r36.DOCS_EVIDENCE / fname).read_text(errors="replace")


def turn2_prompts(seat: str, cache: dict):
    others = []
    for other in r36.SEAT_KEYS:
        if other == seat:
            continue
        body = cache.get(f"stage3_{other}", "(missing)")
        others.append(f"=== SEAT {r36.SEAT_KEYS.index(other)+1}: {other.upper()} (Turn 3 objections and ratification) ===\n{body[:20000]}")
    prompt = (
        "ROUND 36 DISPUTE CYCLE, TURN 2: CROSS-EXAMINATION ON FOUR AMENDED ITEMS. "
        "Sealed rules apply: your sources are your own Turn 3 file (below), the "
        "other seats' Turn 3 files (below), and the Arbiter's amendments. No "
        "tools, no network.\n\n"
        + AMENDED
        + "\n\nYour Turn 3 file:\n"
        + OBJECTIONS[seat][:20000]
        + "\n\nOther seats' Turn 3 files:\n\n"
        + "\n\n".join(others)
        + "\n\nMandate: confirm or attack each of the four amended fixes. A "
        "'cannot work' claim must carry a concrete mechanism (errno, arithmetic, "
        "or quoted behavior). End with a one-line position per item: AMENDED "
        "OI-<n>: ACCEPT or AMENDED OI-<n>: REJECT: <reason>."
    )
    return r36.clean_text(prompt), r36.SYSTEM_SEATS[seat]


def turn3_prompts(seat: str, cache: dict):
    others = []
    for other in r36.SEAT_KEYS:
        if other == seat:
            continue
        body = cache.get(f"stage4_{other}", "(missing)")
        others.append(f"=== SEAT {r36.SEAT_KEYS.index(other)+1}: {other.upper()} (dispute-cycle Turn 2) ===\n{body[:15000]}")
    prompt = (
        "ROUND 36 DISPUTE CYCLE, TURN 3: FINAL VOTE ON THE FOUR AMENDED ITEMS "
        "ONLY (OI-2, OI-18, OI-34, OI-35 as amended). All other items are "
        "already unanimous and out of scope. Sealed rules apply.\n\n"
        + AMENDED
        + "\n\nYour dispute-cycle Turn 2 positions and the other seats' are "
        "reproduced below.\n\n=== YOUR DISPUTE-CYCLE TURN 2 ===\n"
        + cache.get(f"stage4_{seat}", "(missing)")[:15000]
        + "\n\n=== OTHER SEATS' DISPUTE-CYCLE TURN 2 ===\n"
        + "\n\n".join(others)
        + "\n\nVote exactly one line per item:\n"
        "AMENDED OI-<n>: AGREE\nor\nAMENDED OI-<n>: DISAGREE: <one falsifiable "
        "reason>. Then a one-paragraph ratification statement for Round 36 as "
        "a whole."
    )
    return r36.clean_text(prompt), r36.SYSTEM_SEATS[seat]


def dispatch(stage_name, prompt_fn):
    cache = r36.load_cache()
    import concurrent.futures
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"{stage_name}_{seat}"
            if cache.get(key):
                print(f"[{seat}] {stage_name} cached", flush=True)
                continue
            prompt, system_role = prompt_fn(seat, cache)
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, prompt, stage_name))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, prompt, stage_name))
            else:
                tasks[key] = (seat, ex.submit(r36.query_openrouter, prompt, system_role, 12000))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r36.update_cache(key, result)
            fname = f"debate_round36_{stage_name}_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 36 {stage_name}: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    if which in ("both", "turn2"):
        dispatch("stage4", turn2_prompts)
    if which in ("both", "turn3"):
        dispatch("stage5", turn3_prompts)
    print("DISPUTE CYCLE COMPLETE", flush=True)


if __name__ == "__main__":
    main()
