#!/usr/bin/env python3
"""The data plane gives a fresh install a random Xray WebSocket path, keeps
the persisted path on a rerun, and keeps unknown paths on the ordinary 404.

The fixed default path ships in every client binary. Randomization removes that
universal probe path on fresh installs only; the per-node path is still in the
hub's public /nodes listing, and the known-path 101/404 oracle is unresolved.
This test executes the installer's own
XRAY_PATH_DEFAULT assignment, load_existing_node_env and
maybe_prompt_or_default in a Bash 4 subshell, in the order the installer runs
them. The only stubs are `stat` and `find` inside load_existing_node_env's
root-ownership and mode gate, which a non-root test cannot satisfy. No network,
no writes outside a private temp dir.
"""
from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import os
import re
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "wins_data_plane_setup_ONETOUCH.sh")
BASH = _toolchain.bash4()
FAILURES = []
PASSED = [0]
FIXED_BRAND_PATH = "/wins-stealth-tunnel"


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def _function(src: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, f"{name}() not found in the installer"
    return m.group(0)


def _default_line(src: str) -> str:
    lines = [l for l in src.splitlines() if l.startswith("XRAY_PATH_DEFAULT=")]
    assert len(lines) == 1, f"expected one XRAY_PATH_DEFAULT assignment, found {len(lines)}"
    return lines[0]


def resolved_path(node_env_text=None, env=None) -> str:
    src = open(SCRIPT, encoding="utf-8").read()
    with tempfile.TemporaryDirectory(prefix="l19-xray-path-") as tmp:
        node_env = os.path.join(tmp, "node.env")
        if node_env_text is not None:
            with open(node_env, "w", encoding="utf-8") as fh:
                fh.write(node_env_text)
            os.chmod(node_env, 0o600)
        prog = "\n".join([
            "set -u",
            # Harness-only: the ownership/mode gate needs root.
            "stat() { echo 0; }",
            "find() { :; }",
            _function(src, "load_existing_node_env"),
            _function(src, "maybe_prompt_or_default"),
            f'load_existing_node_env "{node_env}"',
            _default_line(src),
            'maybe_prompt_or_default XRAY_PATH "WebSocket path" "$XRAY_PATH_DEFAULT"',
            'printf "%s" "$XRAY_PATH"',
        ])
        run_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "WINSVPN_INTERACTIVE": "0"}
        run_env.update(env or {})
        out = subprocess.run([BASH, "-c", prog], env=run_env, capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        return out.stdout


def test_fresh_install_gets_random_path():
    a, b = resolved_path(), resolved_path()
    assert a != FIXED_BRAND_PATH, f"fresh install still defaults to the fixed path {a!r}"
    assert re.fullmatch(r"/assets/[0-9a-f]{16}", a), a
    assert re.fullmatch(r"/assets/[0-9a-f]{16}", b), b
    assert a != b, "two fresh installs produced the same path"


def test_fresh_path_passes_installer_validation():
    p = resolved_path()
    assert p.startswith("/") and not re.search(r"\s", p), p


def test_rerun_keeps_persisted_path():
    assert resolved_path('XRAY_PATH="/wins-stealth-tunnel"\n') == FIXED_BRAND_PATH
    assert resolved_path('XRAY_PATH="/assets/00112233aabbccdd"\n') == "/assets/00112233aabbccdd"


def _vhost(src: str) -> str:
    m = re.search(r"cat > /etc/nginx/sites-available/wins-node.conf <<EOF\n(.*?)\nEOF\n", src, re.S)
    assert m, "wins-node.conf vhost heredoc not found"
    return m.group(1)


def test_unknown_paths_keep_the_ordinary_404():
    vhost = _vhost(open(SCRIPT, encoding="utf-8").read())
    # The tunnel location is an exact match on the configured path ...
    assert re.search(r"^\s*location = \$\{XRAY_PATH\} \{", vhost, re.M), "tunnel location is not an exact match"
    # ... that answers a non-upgrade request with the same bare 404 ...
    block = vhost.split("location = ${XRAY_PATH} {", 1)[1].split("\n    }\n", 1)[0]
    assert re.search(r"if \(\\\$wins_ws_handshake = 0\) \{\s*return 404;", block), block[:200]
    # ... as the catch-all every other path hits.
    assert re.search(r"location / \{\s*return 404;\s*\}", vhost), "catch-all no longer returns 404"


def test_operator_env_still_wins():
    assert resolved_path(env={"XRAY_PATH": "/operator-chosen"}) == "/operator-chosen"
    assert resolved_path(env={"XRAY_PATH_DEFAULT": "/pinned-default"}) == "/pinned-default"


TESTS = [
    test_fresh_install_gets_random_path,
    test_fresh_path_passes_installer_validation,
    test_rerun_keeps_persisted_path,
    test_unknown_paths_keep_the_ordinary_404,
    test_operator_env_still_wins,
]


def main():
    print("data-plane Xray path default")
    for fn in TESTS:
        check(fn.__name__, fn)
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
