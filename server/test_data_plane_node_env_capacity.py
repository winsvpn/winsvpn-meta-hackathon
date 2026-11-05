#!/usr/bin/env python3
"""Lane L85 (Round LD): a data-plane installer rerun keeps the operator's
load-bar capacities in node.env, and never invents them.

wins-node-register reads NODE_LINK_CAPACITY_MBPS (optional: adds a WAN term to
the load bar since Round LD2, never required) and NODE_SESSION_CAPACITY
(optional: replaces the user capacity derived from the CPU count) from
/root/node.env, and collect_inputs()
rewrites node.env wholesale from its write_env_kv buffer. This test executes
the installer's own load_existing_node_env, err, write_env_kv,
atomic_replace_file and validate_optional_positive_int, plus every
non-comment line of collect_inputs() that names either key, in the order the
installer runs them, in a Bash 4 subshell. The only stubs are `stat` and
`find` inside load_existing_node_env's root-ownership and mode gate, which a
non-root test cannot satisfy. No network, no writes outside a private temp dir.

Usage: python3 server/test_data_plane_node_env_capacity.py [installer path]
"""
from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import os
import re
import stat as statmod
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "wins_data_plane_setup_ONETOUCH.sh")
BASH = _toolchain.bash4()
FAILURES = []
PASSED = [0]
KEYS = ("NODE_LINK_CAPACITY_MBPS", "NODE_SESSION_CAPACITY")
BASE_ENV = 'NODE_SLUG="lab-node"\nNODE_TOKEN="fixture-token-not-a-secret"\nNODE_MAX_PEERS="4096"\n'


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


def _err_line(src: str) -> str:
    # The installer's own err(), the first top-level one; later copies live in
    # heredocs of scripts it installs on the node.
    lines = [l for l in src.splitlines() if l.startswith("err() {")]
    assert lines, "err() not found in the installer"
    return lines[0]


def _collect_inputs_capacity_lines(src: str) -> list[str]:
    body = _function(src, "collect_inputs")
    lines = [l for l in body.splitlines()
             if any(k in l for k in KEYS) and not l.lstrip().startswith("#")]
    assert lines, "collect_inputs() never mentions the capacity keys"
    return lines


def rerun(node_env_text=None, env=None):
    """Simulate the node.env part of an installer rerun. Returns (rc, out_env_text, stderr, mode)."""
    src = open(SCRIPT, encoding="utf-8").read()
    with tempfile.TemporaryDirectory(prefix="l85-node-env-") as tmp:
        node_env = os.path.join(tmp, "node.env")
        if node_env_text is not None:
            with open(node_env, "w", encoding="utf-8") as fh:
                fh.write(node_env_text)
            os.chmod(node_env, 0o600)
        out_env = os.path.join(tmp, "node.env.rerun")
        prog = "\n".join([
            "set -Eeuo pipefail",
            # Harness-only: the ownership/mode gate needs root.
            "stat() { echo 0; }",
            "find() { :; }",
            _err_line(src),
            _function(src, "load_existing_node_env"),
            _function(src, "write_env_kv"),
            _function(src, "atomic_replace_file"),
            _function(src, "validate_optional_positive_int"),
            f'load_existing_node_env "{node_env}"',
            'NODE_ENV_KV_BUFFER=""',
            'write_env_kv NODE_SLUG "${NODE_SLUG:-lab-node}"',
            'write_env_kv NODE_TOKEN "${NODE_TOKEN:-}"',
            *_collect_inputs_capacity_lines(src),
            f'atomic_replace_file "{out_env}" "${{NODE_ENV_KV_BUFFER}}" 600',
        ])
        run_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "WINSVPN_INTERACTIVE": "0"}
        run_env.update(env or {})
        out = subprocess.run([BASH, "-c", prog], env=run_env, capture_output=True, text=True, timeout=30)
        text = open(out_env, encoding="utf-8").read() if os.path.exists(out_env) else None
        mode = statmod.S_IMODE(os.stat(out_env).st_mode) if text is not None else None
        return out.returncode, text, out.stdout + out.stderr, mode


def sourced(text: str) -> dict:
    """What wins-node-register sees after `source /root/node.env`."""
    with tempfile.TemporaryDirectory(prefix="l85-source-") as tmp:
        p = os.path.join(tmp, "node.env")
        open(p, "w", encoding="utf-8").write(text)
        out = subprocess.run([BASH, "-c", f'source "{p}"; for k in {" ".join(KEYS)}; do '
                                         'printf "%s=%s|" "$k" "${!k-<unset>}"; done'],
                             env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                             capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        return dict(kv.split("=", 1) for kv in out.stdout.strip("|").split("|"))


def test_both_keys_survive_a_rerun():
    rc, text, log, mode = rerun(BASE_ENV + 'NODE_LINK_CAPACITY_MBPS="900"\nNODE_SESSION_CAPACITY="50"\n')
    assert rc == 0, log
    assert 'NODE_LINK_CAPACITY_MBPS="900"\n' in text, text
    assert 'NODE_SESSION_CAPACITY="50"\n' in text, text
    assert mode == 0o600, oct(mode)
    assert sourced(text) == {"NODE_LINK_CAPACITY_MBPS": "900", "NODE_SESSION_CAPACITY": "50"}


def test_unquoted_legacy_values_survive_too():
    rc, text, log, _ = rerun(BASE_ENV + "NODE_LINK_CAPACITY_MBPS=800\n")
    assert rc == 0, log
    assert sourced(text) == {"NODE_LINK_CAPACITY_MBPS": "800", "NODE_SESSION_CAPACITY": "<unset>"}


def test_absent_keys_are_not_added():
    rc, text, log, _ = rerun(BASE_ENV)
    assert rc == 0, log
    for key in KEYS:
        assert key not in text, text
    assert sourced(text) == {k: "<unset>" for k in KEYS}


def test_fresh_install_without_node_env_adds_nothing():
    rc, text, log, _ = rerun(None)
    assert rc == 0, log
    for key in KEYS:
        assert key not in text, text


def test_environment_input_is_accepted_and_wins():
    rc, text, log, _ = rerun(BASE_ENV + 'NODE_LINK_CAPACITY_MBPS="900"\n',
                             env={"NODE_LINK_CAPACITY_MBPS": "800", "NODE_SESSION_CAPACITY": "40"})
    assert rc == 0, log
    assert sourced(text) == {"NODE_LINK_CAPACITY_MBPS": "800", "NODE_SESSION_CAPACITY": "40"}


def test_empty_environment_value_removes_the_key():
    rc, text, log, _ = rerun(BASE_ENV + 'NODE_LINK_CAPACITY_MBPS="900"\nNODE_SESSION_CAPACITY="50"\n',
                             env={"NODE_LINK_CAPACITY_MBPS": ""})
    assert rc == 0, log
    assert "NODE_LINK_CAPACITY_MBPS" not in text, text
    assert 'NODE_SESSION_CAPACITY="50"\n' in text, text


def test_bounds_are_accepted():
    for link, sess in (("1", "1"), ("400000", "1000000")):
        rc, text, log, _ = rerun(BASE_ENV, env={"NODE_LINK_CAPACITY_MBPS": link, "NODE_SESSION_CAPACITY": sess})
        assert rc == 0, (link, sess, log)
        assert sourced(text) == {"NODE_LINK_CAPACITY_MBPS": link, "NODE_SESSION_CAPACITY": sess}


BAD = ["0", "-5", "09", "1.5", "900 ", " 900", "abc", "400001", "1000000000", "9" * 30,
       "1e3", "0x10", "$(id)", "900;id"]


def test_invalid_values_refuse_the_run_and_never_echo_the_value():
    for key, bad in [("NODE_LINK_CAPACITY_MBPS", v) for v in BAD] + [
            ("NODE_SESSION_CAPACITY", v) for v in ("0", "1000001", "x1", "-1")]:
        # Via the environment (installer input) ...
        rc, text, log, _ = rerun(BASE_ENV, env={key: bad})
        assert rc != 0, (key, bad, "accepted")
        assert text is None, (key, bad, "node.env was rewritten")
        assert key in log, log
        if bad.strip() and bad not in key and bad not in ("1", "0"):
            assert bad.strip() not in log.replace(key, ""), (key, bad, log)
        # ... and via the persisted file (a hand-edited node.env).
        esc = bad.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
        rc, text, log, _ = rerun(BASE_ENV + f'{key}="{esc}"\n')
        assert rc != 0, (key, bad, "accepted from node.env")
        assert text is None, (key, bad, "node.env was rewritten")


def test_call_sites_are_pinned_in_collect_inputs():
    src = open(SCRIPT, encoding="utf-8").read()
    body = _function(src, "collect_inputs")
    pos = {name: body.find(needle) for name, needle in {
        "probe_token_check": 'validate_health_probe_token "${NODE_HEALTH_PROBE_TOKEN}" || exit 1',
        "validate_link": "validate_optional_positive_int NODE_LINK_CAPACITY_MBPS 400000 || exit 1",
        "validate_sess": "validate_optional_positive_int NODE_SESSION_CAPACITY 1000000 || exit 1",
        "write_max_peers": 'write_env_kv NODE_MAX_PEERS "${NODE_MAX_PEERS}"',
        "write_link": 'write_env_kv NODE_LINK_CAPACITY_MBPS "${NODE_LINK_CAPACITY_MBPS}"',
        "write_sess": 'write_env_kv NODE_SESSION_CAPACITY "${NODE_SESSION_CAPACITY}"',
        "replace": 'atomic_replace_file "${NODE_ENV_FILE}" "${NODE_ENV_KV_BUFFER}" 600',
    }.items()}
    assert all(v >= 0 for v in pos.values()), pos
    assert pos["probe_token_check"] < pos["validate_link"] < pos["validate_sess"] < pos["write_max_peers"], pos
    assert pos["write_max_peers"] < pos["write_link"] < pos["write_sess"] < pos["replace"], pos
    # The installer loads node.env before collect_inputs runs, at top level.
    assert re.search(r'^load_existing_node_env "\$\{NODE_ENV_FILE\}"$', src, re.M), "load call missing"
    # Neither value is ever logged: no log/echo/printf line names either key.
    for line in src.splitlines():
        s = line.strip()
        if s.startswith(("log ", "echo ", "printf ", "warn ", "info ")) and any(k in s for k in KEYS):
            raise AssertionError(f"capacity value may be logged: {s}")


def main():
    print(f"installer: {SCRIPT}")
    for name, fn in sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)):
        check(name, fn)
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print(f"--- {name}\n{tb}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
