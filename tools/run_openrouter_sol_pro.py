#!/usr/bin/env python3
"""Run Sol Pro audit agent via OpenRouter with extra high reasoning over openai/flex.

Exposes bash, read_file, and write_file tools so Sol Pro can inspect files,
execute verification commands in its assigned workspace, and write the report.
Handles upstream 429 rate limits with exponential backoff retry.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute a shell command inside the assigned workspace directory. Returns stdout and stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The command line to execute."}
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file inside the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative or absolute file path to read."}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write text content to a file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write."},
                    "content": {"type": "string", "description": "Text content to write."},
                },
                "required": ["path", "content"],
            },
        },
    },
]


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
    raise RuntimeError("OpenRouter API key not found in environment or ~/.local/share/opencode/auth.json")


def get_ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl._create_unverified_context()


def send_chat_completion(
    messages: list[dict],
    model: str = "openai/gpt-5.6-sol-pro",
    effort: str = "xhigh",
    max_retries: int = 120,
    tools: list[dict] | None = TOOLS,
) -> dict:
    key = get_openrouter_key()
    ctx = get_ssl_context()

    payload: dict = {
        "model": model,
        "messages": messages,
        "provider": {
            "order": ["OpenAI", "Azure"],
            "allow_fallbacks": True,
        },
        "reasoning": {
            "effort": effort,
        },
    }
    if tools:
        payload["tools"] = tools

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": "WinsVPN Sol Pro Tripartite Audit",
        },
    )

    base_delay = 2.0
    for attempt in range(1, max_retries + 1):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=3600) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                if "choices" in res and len(res["choices"]) > 0:
                    return res
                error_obj = res.get("error", {})
                error_msg = error_obj.get("message", "Unknown error")
                error_code = error_obj.get("code")
                sys.stderr.write(f"[Sol Pro] Upstream notice (attempt {attempt}/{max_retries}): {error_msg} (code: {error_code})\n")
                sys.stderr.flush()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            sys.stderr.write(f"[Sol Pro] HTTP error {exc.code} (attempt {attempt}/{max_retries}): {err_body}\n")
            sys.stderr.flush()
        except Exception as exc:
            sys.stderr.write(f"[Sol Pro] Request error (attempt {attempt}/{max_retries}): {exc}\n")
            sys.stderr.flush()

        jitter = random.uniform(0.5, 1.5)
        delay = min(60.0, base_delay * (1.6 ** (attempt - 1)) + jitter)
        sys.stderr.write(f"[Sol Pro] Retrying in {delay:.1f}s...\n")
        sys.stderr.flush()
        time.sleep(delay)

    raise RuntimeError(f"Sol Pro failed after {max_retries} attempts.")


def execute_tool(workspace: pathlib.Path, name: str, args: dict) -> str:
    if name == "bash":
        cmd = args.get("command", "")
        if not cmd:
            return "Error: command is required"
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=300,
            )
            out = proc.stdout
            if proc.stderr:
                out += f"\n[stderr]\n{proc.stderr}"
            if proc.returncode != 0:
                out += f"\n[exit code: {proc.returncode}]"
            if len(out) > 30000:
                out = out[:15000] + f"\n... [truncated {len(out) - 30000} chars] ...\n" + out[-15000:]
            return out.strip() or "(command executed with no output)"
        except subprocess.TimeoutExpired:
            return "Error: command timed out after 300 seconds"
        except Exception as exc:
            return f"Error executing command: {exc}"

    elif name == "read_file":
        raw_path = args.get("path", "")
        if not raw_path:
            return "Error: path is required"
        target = (workspace / raw_path).resolve() if not pathlib.Path(raw_path).is_absolute() else pathlib.Path(raw_path).resolve()
        if not target.exists():
            return f"Error: file not found at {target}"
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
            if len(content) > 40000:
                content = content[:20000] + f"\n... [truncated {len(content) - 40000} chars] ...\n" + content[-20000:]
            return content
        except Exception as exc:
            return f"Error reading file: {exc}"

    elif name == "write_file":
        raw_path = args.get("path", "")
        content = args.get("content", "")
        if not raw_path:
            return "Error: path is required"
        target = (workspace / raw_path).resolve() if not pathlib.Path(raw_path).is_absolute() else pathlib.Path(raw_path).resolve()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return f"Successfully wrote {len(content)} bytes to {target}"
        except Exception as exc:
            return f"Error writing file: {exc}"

    return f"Error: unknown tool {name}"


def run_agent_loop(
    prompt: str,
    workspace: pathlib.Path,
    report_path: pathlib.Path,
    model: str = "openai/gpt-5.6-sol-pro",
    effort: str = "xhigh",
    max_turns: int = 60,
) -> tuple[str, str, dict]:
    messages = [
        {"role": "user", "content": prompt}
    ]

    accumulated_reasoning: list[str] = []
    final_content = ""
    total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    for turn in range(1, max_turns + 1):
        sys.stderr.write(f"[Sol Pro] Turn {turn}/{max_turns} dispatching to {model} via openai/flex...\n")
        sys.stderr.flush()

        res = send_chat_completion(messages, model=model, effort=effort)

        usage = res.get("usage", {})
        for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
            total_usage[k] = total_usage.get(k, 0) + usage.get(k, 0)

        choice = res["choices"][0]
        message = choice.get("message", {})
        content = message.get("content", "") or ""
        reasoning = message.get("reasoning", "") or ""
        tool_calls = message.get("tool_calls", [])

        if reasoning:
            accumulated_reasoning.append(reasoning)

        # Emit reasoning event to stdout for stream logger
        if reasoning:
            reasoning_event = {
                "type": "item.completed",
                "item": {
                    "type": "reasoning",
                    "text": reasoning,
                },
            }
            sys.stdout.write(json.dumps(reasoning_event) + "\n")
            sys.stdout.flush()

        if tool_calls:
            # Append assistant message with tool calls
            messages.append({
                "role": "assistant",
                "content": content if content else None,
                "tool_calls": tool_calls,
            })

            # Execute tool calls
            for tc in tool_calls:
                call_id = tc.get("id")
                fn = tc.get("function", {})
                fn_name = fn.get("name", "")
                try:
                    fn_args = json.loads(fn.get("arguments", "{}"))
                except Exception:
                    fn_args = {}

                sys.stderr.write(f"[Sol Pro] Executing tool {fn_name}({list(fn_args.keys())})...\n")
                sys.stderr.flush()

                tool_result = execute_tool(workspace, fn_name, fn_args)

                messages.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": tool_result,
                })

                # Check if report was written and exceeds minimum length
                if report_path.exists() and report_path.stat().st_size > 1000:
                    sys.stderr.write(f"[Sol Pro] Target report verified at {report_path} ({report_path.stat().st_size} bytes).\n")
                    sys.stderr.flush()
        else:
            final_content = content
            # If report is written and adequate, we are done
            if report_path.exists() and report_path.stat().st_size > 500:
                break
            # If model produced full text directly, write it to report
            if len(content) > 500 and (not report_path.exists() or report_path.stat().st_size < len(content)):
                report_path.parent.mkdir(parents=True, exist_ok=True)
                clean_text = content.replace("\u2014", ": ").replace("\u2013", "-")
                report_path.write_text(clean_text, encoding="utf-8")
                sys.stderr.write(f"[Sol Pro] Model response written directly to {report_path} ({len(clean_text)} bytes).\n")
                sys.stderr.flush()
                break

    all_reasoning = "\n\n".join(accumulated_reasoning)
    return final_content, all_reasoning, total_usage


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Sol Pro audit agent via OpenRouter")
    parser.add_argument("--workspace", type=pathlib.Path, required=True, help="Path to assigned workspace")
    parser.add_argument("--report", type=pathlib.Path, required=True, help="Path to write report")
    parser.add_argument("--model", type=str, default="openai/gpt-5.6-sol-pro", help="OpenRouter model slug")
    parser.add_argument("--effort", type=str, default="xhigh", help="Reasoning effort")
    args = parser.parse_args()

    prompt = sys.stdin.read()
    if not prompt.strip():
        sys.stderr.write("Sol Pro: Prompt on stdin is empty.\n")
        sys.exit(1)

    sys.stderr.write(f"[Sol Pro] Starting audit agent for {args.model} via OpenRouter (provider: openai/flex, effort: {args.effort})...\n")
    sys.stderr.write(f"[Sol Pro] Workspace: {args.workspace}\n")
    sys.stderr.write(f"[Sol Pro] Target report: {args.report}\n")
    sys.stderr.flush()

    content, reasoning, usage = run_agent_loop(
        prompt,
        workspace=args.workspace,
        report_path=args.report,
        model=args.model,
        effort=args.effort,
    )

    clean_content = content.replace("\u2014", ": ").replace("\u2013", "-")
    json_event = {
        "type": "item.completed",
        "item": {
            "type": "agent_message",
            "text": clean_content,
        },
    }
    sys.stdout.write(json.dumps(json_event) + "\n")
    sys.stdout.flush()

    turn_event = {
        "type": "turn.completed",
        "usage": usage,
    }
    sys.stdout.write(json.dumps(turn_event) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
