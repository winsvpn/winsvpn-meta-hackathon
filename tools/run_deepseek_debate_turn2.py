#!/usr/bin/env python3
"""Run Turn 2 of the DeepSeek Debate to achieve mutual agreement."""

import json
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.deepseek_debate_harness import call_deepseek

def main():
    # Read the audit findings from round 1
    round1_file = Path("docs/evidence/deepseek_round1_audit.md")
    with round1_file.open("r", encoding="utf-8") as f:
        round1_content = f.read()

    counter_arguments = """Thank you for the rigorous, deep audit. Here is our engineering assessment and proposed synthesis for mutual consensus:

1. **Agreed & Accepted True Positives**:
   - **F-2.1 (Worker // Normalization)**: AGREED. `pathname.startsWith('/downloads/')` does fail for `//downloads/...`, potentially bypassing the allowlist check before Cloudflare normalizes it. We will normalize the pathname by collapsing multiple slashes (`raw.replace(/\\/+/g, '/')`) and rejecting dot-segments/traversals before any asset decision.
   - **F-3.1 (Naive vs Aware ISO 8601 Datetime Comparison)**: AGREED. We independently reproduced `TypeError: can't compare offset-naive and offset-aware datetimes` in Python when comparing `utcnow()` against a datetime with timezone info. We will update `parse_iso_datetime` so that if `tzinfo` is present, it is converted to UTC and stripped to naive UTC (`dt.astimezone(timezone.utc).replace(tzinfo=None)`), guaranteeing 100% interoperability across naive and aware timestamps everywhere.
   - **F-1.4 (Atomic Settings File Write)**: AGREED. Writing `vpn_settings.txt` via a temporary file and atomic rename (`tmp.rename(path)`) is the correct POSIX pattern to prevent torn writes during unexpected app kills.
   - **F-1.1 & F-1.2 (Client Protocol Connection Plan Snapshot & Fail-Closed)**: AGREED. Snapshotting the connection plan into an immutable model before async awaits prevents TOCTOU races between UI toggles and socket dials, and strict unknown protocol handling will fail closed.

2. **Debate & Clarification on Specific Points**:
   - **On F-3.3 (Argon2id vs SHA-256 for Activation Secrets)**:
     Our setup keys are minted using `secrets.token_urlsafe(32)`, providing 256 bits of cryptographically uniform entropy. Unlike low-entropy human passwords, 256-bit random tokens are mathematically immune to brute-force or dictionary attacks (2^256 keyspace). While Argon2id is critical for user-entered passwords, for high-entropy machine-minted bearer tokens, standard cryptographic SHA-256 (with constant-time comparison `hmac.compare_digest`) is standard industry practice. However, we agree with your recommendation to add `activation_secret_used_at` single-use consumption semantics for defense-in-depth! Do you agree that SHA-256 is cryptographically secure for 256-bit uniform random secrets when paired with single-use consumption?
   - **On F-4.1 (Data Plane Isolation)**:
     In our setup, `winn3gw0` operates on `10.10.0.0/24` using dedicated `WINN3GW-*` chains, `awg0` operates on `10.8.0.0/24` with `WINVPN-*` chains, and XRay is a userspace proxy. Neither setup script issues broad `iptables -F`. We agree that using explicit check-before-add (`-C`) and isolating flush commands to engine-specific chains is the right discipline.

Please evaluate our responses. If you agree with these conclusions, confirm consensus on the final remediation plan and provide the exact final implementations.
"""

    messages = [
        {"role": "system", "content": "You are DeepSeek V4.1 Flash, acting as a Principal Security Architect in an adversarial debate with another security engineer. Evaluate the counter-arguments with maximum reasoning effort and reach a rigorous consensus."},
        {"role": "user", "content": f"Here was your Round 1 Audit:\n\n{round1_content}\n\nHere is our engineering response:\n\n{counter_arguments}"}
    ]

    print("Submitting debate turn 2 to DeepSeek V4.1 Flash (Reasoning Effort: Max)...")
    content, reasoning = call_deepseek(messages, reasoning_effort="max", timeout=240)
    
    output_path = Path("docs/evidence/deepseek_round2_consensus.md")
    with output_path.open("w", encoding="utf-8") as f:
        f.write("# DeepSeek V4.1 Flash Debate Turn 2 & Consensus\n\n")
        f.write("## Reasoning Trace Summary\n\n")
        f.write(f"Reasoning length: {len(reasoning)} characters\n\n")
        f.write("## Consensus & Final Implementation Specifications\n\n")
        f.write(content)
        f.write("\n")

    print(f"Debate turn 2 completed! Output saved to {output_path}")
    print("\n--- DEEPSEEK CONSENSUS RESPONSE ---\n")
    print(content)

if __name__ == "__main__":
    main()
