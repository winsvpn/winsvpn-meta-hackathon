#!/usr/bin/env python3
"""
Submit and track Presidential Debate Batches on OpenRouter for:
  Podium 3: Claude Opus 5 (anthropic/claude-opus-5)
  Podium 4: Claude Fable 5.1 (anthropic/claude-fable-5.1)
Saves 50% on API costs via OpenRouter Batch API.
"""

import json
import os
import pathlib
import ssl
import sys
import time
import urllib.request

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
RAW_JSON_PATH = DOCS_EVIDENCE / "debate_upload_asymmetry_4ai_raw.json"
BATCH_STATE_PATH = DOCS_EVIDENCE / "openrouter_batch_debate_state.json"

from run_4ai_upload_debate import DEBATE_TOPIC


def get_openrouter_key() -> str:
    env_key = os.environ.get("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    auth_file = pathlib.Path.home() / ".local" / "share" / "opencode" / "auth.json"
    if auth_file.exists():
        try:
            data = json.loads(auth_file.read_text(encoding="utf-8"))
            key = data.get("openrouter", {}).get("key")
            if key:
                return key.strip()
        except Exception:
            pass
    raise RuntimeError("OpenRouter API key not found")


def submit_batch(model: str, system_prompt: str, user_prompt: str) -> str:
    key = get_openrouter_key()
    ctx = ssl._create_unverified_context()
    custom_id = f"debate-{model.replace('/', '-').replace('.', '-')}"
    payload = {
        "endpoint": "/v1/chat/completions",
        "model": model,
        "requests": [
            {
                "custom_id": custom_id,
                "body": {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "reasoning": {"effort": "high"},
                },
            }
        ],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/batches",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": f"Winthos Presidential Debate {model}",
        },
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        batch_id = res.get("id")
        print(f"Submitted batch for {model}: {batch_id} (status: {res.get('status')})")
        return batch_id


def check_batch(batch_id: str) -> dict:
    key = get_openrouter_key()
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(
        f"https://openrouter.ai/api/v1/batches/{batch_id}",
        headers={"Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def clean_text(text: str) -> str:
    return text.replace("\u2014", ": ").replace("\u2013", "-")


def main():
    system_opus = (
        "You are serving as Podium 3 (Claude Opus 5) under the Winthos Permanent "
        "Presidential Debate Protocol v4.0. Adhere strictly to the cadence mandate: "
        "high burstiness, alternating short decisive assertions with compound analytical proofs, "
        "strictly ZERO em dashes or en dashes (use periods, commas, colons, or parentheses instead), "
        "ban all AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Provide direct code diffs, exact sysctls, and socket configurations."
    )

    system_fable = (
        "You are serving as Podium 4 (Claude Fable 5.1) under the Winthos Permanent "
        "Presidential Debate Protocol v4.0. Adhere strictly to the cadence mandate: "
        "high burstiness, alternating short decisive assertions with compound analytical proofs, "
        "strictly ZERO em dashes or en dashes (use periods, commas, colons, or parentheses instead), "
        "ban all AI cliches (delve, testament, tapestry, crucial, leverage, furthermore, moreover, in summary). "
        "Deliver rigorous kernel datapath and VpnService analysis."
    )

    state = {}
    if BATCH_STATE_PATH.exists():
        try:
            state = json.loads(BATCH_STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            state = {}

    # Check or submit Opus 5
    if "opus_batch_id" not in state:
        state["opus_batch_id"] = submit_batch("anthropic/claude-opus-5", system_opus, DEBATE_TOPIC)
        BATCH_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    else:
        print(f"Existing Opus 5 Batch ID: {state['opus_batch_id']}")

    # Check or submit Fable 5.1
    if "fable_batch_id" not in state:
        state["fable_batch_id"] = submit_batch("anthropic/claude-fable-5.1", system_fable, DEBATE_TOPIC)
        BATCH_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    else:
        print(f"Existing Fable 5.1 Batch ID: {state['fable_batch_id']}")

    raw_data = {}
    if RAW_JSON_PATH.exists():
        try:
            raw_data = json.loads(RAW_JSON_PATH.read_text(encoding="utf-8"))
        except Exception:
            raw_data = {}

    # Poll status
    all_done = True
    for key_name, batch_key, model_label in [
        ("opus_5", "opus_batch_id", "Claude Opus 5"),
        ("fable_51", "fable_batch_id", "Claude Fable 5.1"),
    ]:
        bid = state[batch_key]
        binfo = check_batch(bid)
        bstatus = binfo.get("status")
        counts = binfo.get("request_counts", {})
        print(f"[{model_label}] Batch {bid} status: {bstatus}, counts: {counts}")
        if bstatus == "completed":
            results = binfo.get("results") or []
            if results:
                resp_body = results[0].get("response", {}).get("body", {})
                choices = resp_body.get("choices") or []
                if choices:
                    content = clean_text(choices[0].get("message", {}).get("content", "").strip())
                    raw_data[key_name] = content
                    raw_data[f"{key_name}_source"] = f"OpenRouter Batch API ({model_label})"
                    print(f"-> Successfully extracted {len(content)} chars for {model_label}")
        else:
            all_done = False

    if all_done:
        RAW_JSON_PATH.write_text(json.dumps(raw_data, indent=2), encoding="utf-8")
        print(f"All batches completed! Saved to {RAW_JSON_PATH}")
    else:
        print("Batches are still processing in the background.")


if __name__ == "__main__":
    main()
