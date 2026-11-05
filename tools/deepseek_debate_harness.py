#!/usr/bin/env python3
"""Automated DeepSeek V4.1 Flash Audit and Debate Harness.

Connects to OpenRouter using credentials in ~/.local/share/opencode/auth.json,
setting model to deepseek/deepseek-v4.1-flash with reasoning.effort: max.
Sends sanitized context and diffs to DeepSeek for a comprehensive security and
architecture audit, and facilitates multi-turn debate until consensus.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

try:
    import certifi
    CAFILE = certifi.where()
except ImportError:
    CAFILE = None


def get_openrouter_key() -> str:
    auth_file = Path(os.path.expanduser("~/.local/share/opencode/auth.json"))
    if not auth_file.is_file():
        raise RuntimeError(f"Auth file missing: {auth_file}")
    with auth_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    key = data.get("openrouter", {}).get("key")
    if not key:
        raise RuntimeError("OpenRouter key not found in ~/.local/share/opencode/auth.json")
    return key


def call_deepseek(
    messages: list[dict[str, str]],
    model: str = "deepseek/deepseek-v4.1-flash",
    reasoning_effort: str = "max",
    timeout: int = 180,
) -> tuple[str, str]:
    """Call DeepSeek via OpenRouter with max reasoning effort.
    
    Returns (content, reasoning_trace).
    """
    key = get_openrouter_key()
    ctx = ssl.create_default_context(cafile=CAFILE) if CAFILE else ssl.create_default_context()
    
    payload = {
        "model": model,
        "messages": messages,
        "extra_body": {
            "reasoning": {
                "effort": reasoning_effort
            }
        }
    }
    
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://opencode.ai",
            "X-Title": "WinsVPN Security Audit Debate",
        }
    )
    
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        msg = body["choices"][0]["message"]
        content = msg.get("content", "")
        reasoning = msg.get("reasoning", "")
        return content, reasoning


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Testing connection to DeepSeek V4.1 Flash...")
        content, reasoning = call_deepseek([
            {"role": "user", "content": "Respond with: DEEPSEEK_READY"}
        ])
        print("Response:", content.strip())
        print("Reasoning length:", len(reasoning))
