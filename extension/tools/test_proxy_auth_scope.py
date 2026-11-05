#!/usr/bin/env python3
"""Exact reproductions of the browser proxy-auth credential-scope defect.

An adapter that answers any proxy 407 with the Wins session token hands that
token to an arbitrary challenger. These tests execute the adapter decision
function without a network and without a browser: the challenger host, port,
scheme, and realm must all match the active Wins proxy or the token stays put.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
EXT = TOOLS.parent
ROOT = EXT.parent
CHROMIUM = EXT / "src" / "adapters" / "chromium.js"
FIREFOX = EXT / "src" / "adapters" / "firefox.js"
PROXY_DART = ROOT / "lib" / "browser_bridge_proxy.dart"

SCOPE_BEGIN = "// --- proxy auth scope"
SCOPE_END = "// --- end proxy auth scope ---"
JSC = Path(
    "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
)

WINS_CREDENTIAL = {
    "endpoint": {"kind": "http", "host": "127.0.0.1", "port": 45678},
    "token": "sekrit-token",
}
WINS_CHALLENGE = {
    "isProxy": True,
    "scheme": "basic",
    "realm": "wins-bridge",
    "challenger": {"host": "127.0.0.1", "port": 45678},
}


def _scope_block(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(SCOPE_BEGIN)
    end = text.index(SCOPE_END) + len(SCOPE_END)
    return text[start:end]


def _scope_body(path: Path) -> str:
    block = _scope_block(path)
    lines = block.splitlines()
    # Drop the per-file lockstep comment so the two adapters can be compared.
    kept = [
        line
        for line in lines
        if "keep in lockstep" not in line and not line.startswith("// ---")
    ]
    return "\n".join(kept).replace("export ", "")


def _js_runtime() -> list[str]:
    if JSC.is_file() and os.access(JSC, os.X_OK):
        return [str(JSC)]
    node = shutil.which("node")
    if node:
        return [node]
    pytest.skip("no local JavaScript runtime for adapter scope tests")


def _run_decisions(cases: list[dict]) -> list[dict]:
    body = _scope_body(CHROMIUM)
    harness = f"""
{body}
const cases = {json.dumps(cases)};
const out = [];
for (const c of cases) {{
  const got = proxyAuthDecision(c.details, c.credential);
  out.push({{
    name: c.name,
    action: got && got.action,
    username: (got && got.authCredentials && got.authCredentials.username) || null,
    password: (got && got.authCredentials && got.authCredentials.password) || null,
    matched: challengerMatchesWinsProxy(c.details, c.credential),
  }});
}}
if (typeof print === 'function') print(JSON.stringify(out));
else console.log(JSON.stringify(out));
"""
    runtime = _js_runtime()
    with tempfile.TemporaryDirectory(prefix="wv-proxy-auth-scope-") as tmp:
        script = Path(tmp) / "scope_harness.js"
        script.write_text(harness, encoding="ascii")
        completed = subprocess.run(
            runtime + [str(script)],
            check=False,
            capture_output=True,
            text=True,
        )
    if completed.returncode != 0:
        raise AssertionError(
            f"js runtime failed: {completed.stderr or completed.stdout}"
        )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_chromium_and_firefox_scope_blocks_are_identical():
    assert _scope_body(CHROMIUM) == _scope_body(FIREFOX)


def test_dart_realm_contract_matches_adapters():
    dart = PROXY_DART.read_text(encoding="utf-8")
    assert 'kBridgeProxyAuthScheme = \'basic\'' in dart
    assert 'kBridgeProxyAuthRealm = \'wins-bridge\'' in dart
    for adapter in (CHROMIUM, FIREFOX):
        text = adapter.read_text(encoding="utf-8")
        assert "WINS_PROXY_AUTH_SCHEME = 'basic'" in text
        assert "WINS_PROXY_AUTH_REALM = 'wins-bridge'" in text
        assert "proxyAuthDecision(details, active)" in text
        assert "decision.action === 'answer'" in text


def test_exact_wins_challenger_is_answered():
    got = _run_decisions(
        [
            {
                "name": "exact-wins",
                "details": WINS_CHALLENGE,
                "credential": WINS_CREDENTIAL,
            }
        ]
    )[0]
    assert got["matched"] is True
    assert got["action"] == "answer"
    assert got["username"] == "extension"
    assert got["password"] == "sekrit-token"


def test_arbitrary_407_does_not_receive_the_token():
    cases = [
        {
            "name": "foreign-host",
            "details": {
                **WINS_CHALLENGE,
                "challenger": {"host": "198.51.100.7", "port": 45678},
            },
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "foreign-port",
            "details": {
                **WINS_CHALLENGE,
                "challenger": {"host": "127.0.0.1", "port": 80},
            },
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "digest-scheme",
            "details": {**WINS_CHALLENGE, "scheme": "digest"},
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "scheme-case",
            "details": {**WINS_CHALLENGE, "scheme": "Basic"},
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "foreign-realm",
            "details": {**WINS_CHALLENGE, "realm": "evil"},
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "origin-401",
            "details": {**WINS_CHALLENGE, "isProxy": False},
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "localhost-not-literal",
            "details": {
                **WINS_CHALLENGE,
                "challenger": {"host": "localhost", "port": 45678},
            },
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "string-port",
            "details": {
                **WINS_CHALLENGE,
                "challenger": {"host": "127.0.0.1", "port": "45678"},
            },
            "credential": WINS_CREDENTIAL,
        },
        {
            "name": "missing-challenger",
            "details": {
                "isProxy": True,
                "scheme": "basic",
                "realm": "wins-bridge",
            },
            "credential": WINS_CREDENTIAL,
        },
    ]
    results = {row["name"]: row for row in _run_decisions(cases)}
    for name in results:
        row = results[name]
        assert row["matched"] is False, name
        assert row["action"] == "ignore", name
        assert row["password"] is None, name


def test_matching_challenge_without_token_cancels_instead_of_prompting():
    got = _run_decisions(
        [
            {
                "name": "no-token",
                "details": WINS_CHALLENGE,
                "credential": {
                    "endpoint": WINS_CREDENTIAL["endpoint"],
                    "token": "",
                },
            }
        ]
    )[0]
    assert got["action"] == "cancel"
    assert got["password"] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
