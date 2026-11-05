#!/usr/bin/env python3
"""Round 41 Turn 3: convergence vote on the amended text with the new council
roster (agy re-vote; Qwen 3.8 Max 0902 as the Opus-limited seat, full
catch-up; Astra via Codex CLI as the Sol Pro replacement, polling until the
weekly limit resets). Full texts are assembled from the round's own receipts
per the H-1 lesson (no excerpting). The Qwen seat reuses the audited
r36.query_openrouter plumbing (model + effort parameterized)."""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import subprocess
import time

_spec = importlib.util.spec_from_file_location(
    "r37", "/Users/owner/xprize/winsvpnv3/tools/run_round37_verify.py"
)
r37 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r37)
r36 = r37.r36

DOCS = r36.DOCS_EVIDENCE
ROUND41_DIR = r37.RECEIPTS.parent / "round41"
QWEN_MODEL = "qwen/qwen3.8-max-0902"
ASTRA_POLL_ATTEMPTS = 10
ASTRA_POLL_SECONDS = 600

AMENDMENTS = """
ARBITER AMENDMENTS ADOPTED FOR THE TURN 3 TEXT (from the Turn 2 review):
1. OI-3 sentence three is replaced verbatim with opus's text: "Of the 14,548
   shortfall, 471 are wire loss (0.12%) and 14,077 were received by the
   carrier and rejected by the accept path during the burst; the clamp in
   OI-2(1) is expected to recover most of those as well, and only the
   terminal latch was fatal." (The 471 figure is sample-dependent: gateway
   outbound at the last pre-failure sample minus phone carrier receives.
   The material claim, that accept-path rejections dwarf wire loss, holds
   across samples.)
2. OI-5 verification clause is replaced verbatim with opus's text: "pass
   requires both (a) post-burst rx_packets continuing to track
   messages_received within the wire-loss delta for at least 120 s after
   burst end, and (b) a forced rekey within 20 s of burst end completing
   without StateFailed; drop-reason instrumentation on the post-burst
   receive path is recorded in both cases."
3. Arbiter source verification for OI-2 part (2): only core.RejectAfterMessages
   is enforced today (session/batch.go:135). No RejectAfterBytes/Time
   terminal enforcement exists for the old epoch. Fix part (2) therefore
   includes ADDING those epoch bounds, not merely enforcing existing ones.
Opus pre-committed: with the arithmetic confirmed and the replacements
adopted verbatim, it votes AGREE on all five without a further cycle. Its
Turn 2 votes stand as its position.
"""


def turn3_packet() -> str:
    parts = []
    for name in ("packet_dispatched.txt", "packet_stage2_dispatched.txt"):
        p = ROUND41_DIR / name
        parts.append(f"=== {name} ===\n{p.read_text(encoding='utf-8')}")
    verdicts = []
    for stage in (1, 2):
        for seat in ("agy", "opus5", "solpro"):
            p = DOCS / f"debate_round41_stage{stage}_{seat}.md"
            if p.exists():
                verdicts.append(
                    f"=== TURN {stage} VERDICT: {seat} ===\n{p.read_text(encoding='utf-8')}"
                )
    base = "\n\n".join(parts) + "\n\n" + "\n\n".join(verdicts)
    return (
        "ROUND 41, TURN 3 (CONVERGENCE VOTE ON THE AMENDED TEXT, NEW ROSTER). "
        "You are the full record's reader: everything below is the round's "
        "dispatched packets and every seat verdict to date. "
        + AMENDMENTS
        + "\n\nVOTE: for each OI-1 through OI-5, exactly AGREE or DISAGREE "
        "with ONE falsifiable reason, on the text as amended. Zero em/en "
        "dashes; banned cliches; bold only list keys. End with NEXT.\n\n"
        + base
    )


def query_qwen(packet: str, system_role: str, max_tokens: int) -> str:
    return r36.query_openrouter(
        packet, system_role, max_tokens,
        model=QWEN_MODEL, reasoning_effort="xhigh",
    )


def query_astra(prompt: str, system_role: str, max_tokens: int) -> str:
    """Codex CLI seat. Polls for the weekly-limit reset; raises the
    distinctive ASTRA-UNAVAILABLE marker the dispatcher records without
    killing the sibling seats (the H-2 lesson)."""
    del system_role, max_tokens
    last = ""
    for attempt in range(ASTRA_POLL_ATTEMPTS):
        proc = subprocess.run(
            ["codex", "exec", "-m", "astra",
             "-c", 'model_reasoning_effort="xhigh"',
             "--sandbox", "read-only", "-"],
            input=prompt, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600,
        )
        out = proc.stdout or ""
        if proc.returncode == 0 and out.strip():
            return out
        combined = (proc.stderr or "") + out
        last = combined[:400]
        lowered = combined.lower()
        if any(marker in lowered for marker in (
                "weekly limit", "rate limit", "usage limit", "upgrade",
                "not supported", "credit")):
            print(f"[astra] attempt {attempt + 1}: gated, retrying in "
                  f"{ASTRA_POLL_SECONDS}s", flush=True)
            time.sleep(ASTRA_POLL_SECONDS)
            continue
        raise RuntimeError(f"astra exec failed: {last}")
    raise RuntimeError(f"ASTRA-UNAVAILABLE: never unlocked in the poll window: {last}")


SYSTEM = {
    "agy": r36.SYSTEM_SEATS["agy"],
    "qwen": (
        "You are Seat 2 (Qwen 3.8 Max 0902, standing in for Claude Opus 5) of "
        "the Winthos Debate Council. You are an independent auditor with the "
        "full round record in front of you. Produce exact, evidence-quoted "
        "findings and votes. Zero em dashes or en dashes; ban AI cliches "
        "(delve, testament, tapestry, crucial, leverage, furthermore, "
        "moreover, in summary, seamless, robust, comprehensive, streamline, "
        "unlock)."
    ),
    "astra": (
        "You are Seat 3 (Astra via Codex CLI, standing in for GPT-5.6 Sol "
        "Pro) of the Winthos Debate Council. You are an independent auditor. "
        "Every claim must carry empirical proof or arithmetic. Zero em/en "
        "dashes; ban AI cliches (delve, testament, tapestry, crucial, "
        "leverage, furthermore, moreover, in summary, seamless, robust, "
        "comprehensive, streamline, unlock)."
    ),
}


def stage3() -> None:
    print("=== ROUND 41 STAGE 3 (TURN 3, NEW ROSTER) ===", flush=True)
    packet = r36.clean_text(turn3_packet())
    ROUND41_DIR.mkdir(parents=True, exist_ok=True)
    (ROUND41_DIR / "packet_stage3_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}",
          flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in ("agy", "qwen", "astra"):
            key = f"r41_stage3_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r41stage3"))
            elif seat == "qwen":
                tasks[key] = (seat, ex.submit(query_qwen, packet, SYSTEM["qwen"], 12000))
            else:
                tasks[key] = (seat, ex.submit(query_astra, packet, SYSTEM["astra"], 12000))
        for key, (seat, fut) in tasks.items():
            try:
                result = fut.result()
                r37.update_cache(key, result)
                fname = f"debate_round41_stage3_{seat}.md"
                (DOCS / fname).write_text(
                    f"# Round 41 stage3 (turn 3): {seat}\n\n{result}\n", encoding="utf-8"
                )
                print(f"-> {key} complete ({len(result)} bytes)", flush=True)
            except Exception as exc:  # noqa: BLE001 - H-2 lesson: never kill siblings
                err = f"SEAT-ERROR {seat}: {exc}"
                r37.update_cache(key, err)
                print(err, flush=True)
    print("ROUND 41 STAGE 3 COMPLETE", flush=True)


def main() -> None:
    stage3()


if __name__ == "__main__":
    main()
