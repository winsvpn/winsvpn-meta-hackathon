#!/usr/bin/env python3
"""Acceptance gate for tools/winn3_sign_announcement.py (ruling IA-CP-06).

The tool is run as a REAL subprocess with a throwaway Ed25519 key, and its
output is fed to the REAL hub verifier (store_verified_announcement from the
installer's main.py heredoc). If the hub refuses what the tool emits, the
offline ceremony is broken and this suite fails. Same shape as
test_winn3_sign_descriptor_tool.py. No network, no host contact.

Run:  python3 server/test_winn3_sign_announcement_tool.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(REPO_ROOT, "tools", "winn3_sign_announcement.py")

FAILURES = []
PASSED = [0]
WORK = tempfile.mkdtemp(prefix="announce-tool-test-")


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def genkey(name):
    path = os.path.join(WORK, f"{name}.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", path],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


KEY_A1 = genkey("a1")
KEY_A2 = genkey("a2")


def run_tool(*argv):
    return subprocess.run([sys.executable, TOOL, *argv], capture_output=True,
                          text=True, timeout=60)


def pubkey(path):
    proc = run_tool("pubkey", "--key", path, "--bare")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def tool_module():
    spec = importlib.util.spec_from_file_location("winn3_sign_announcement", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hub(**env):
    for slot in ("A1", "A2", "A3"):
        os.environ.pop(f"ANNOUNCE_PUBKEY_{slot}", None)
    return harness.load_hub(**env)


def hub_store(mod, envelope):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        result = mod.store_verified_announcement(conn, envelope["payload"], envelope["sig"])
        fields = mod.announcement_fields(conn)
    return result, fields


def test_hub_accepts_what_the_tool_signs():
    mod = hub(ANNOUNCE_PUBKEY_A1=pubkey(KEY_A1))
    text = "Maintenance tonight: 02:00 UTC. ကခ non-ASCII survives."
    proc = run_tool("sign", "--key", KEY_A1, "--text", text, "--seq", "4")
    assert proc.returncode == 0, proc.stderr
    envelope = json.loads(proc.stdout)
    assert set(envelope) == {"payload", "sig"}
    (seq, kid), fields = hub_store(mod, envelope)
    assert (seq, kid) == (4, "a1")
    assert fields["announcement"] == text
    assert fields["announcement_signed"] == envelope
    raw = base64.b64decode(envelope["payload"])
    payload = json.loads(raw)
    assert set(payload) == {"kid", "seq", "iat", "text"}
    # The one serialisation the hub and the descriptor tool already use.
    assert raw == json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_text_file_and_a2_slot():
    mod = hub(ANNOUNCE_PUBKEY_A1=pubkey(KEY_A1), ANNOUNCE_PUBKEY_A2=pubkey(KEY_A2))
    path = os.path.join(WORK, "text.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("From a file\n")
    proc = run_tool("sign", "--key", KEY_A2, "--kid", "a2", "--text-file", path,
                    "--seq", "9", "--prev-seq", "8", "--iat", "1700000000")
    assert proc.returncode == 0, proc.stderr
    (seq, kid), fields = hub_store(mod, json.loads(proc.stdout))
    assert (seq, kid) == (9, "a2") and fields["announcement"] == "From a file"
    # Same inputs, same bytes: the serialisation is deterministic.
    again = run_tool("sign", "--key", KEY_A2, "--kid", "a2", "--text-file", path,
                     "--seq", "9", "--iat", "1700000000")
    assert json.loads(again.stdout)["payload"] == json.loads(proc.stdout)["payload"]
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_hub_refuses_a_key_it_was_not_given():
    mod = hub(ANNOUNCE_PUBKEY_A1=pubkey(KEY_A1))
    proc = run_tool("sign", "--key", KEY_A2, "--text", "x", "--seq", "1")
    assert proc.returncode == 0, proc.stderr
    try:
        hub_store(mod, json.loads(proc.stdout))
    except mod.AnnouncementContractError as exc:
        assert exc.reason == "announcement-signature-invalid"
    else:
        raise AssertionError("a signature by an unconfigured key was accepted")
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_tool_refusals():
    cases = (
        (["--text", "x", "--seq", "3", "--prev-seq", "3"], "STRICTLY INCREASE"),
        (["--text", "x", "--seq", "0"], "--seq must be"),
        (["--text", "   ", "--seq", "1"], "blank"),
        (["--text", "y" * 901, "--seq", "1"], "901 characters"),
        (["--text", "x", "--seq", "1", "--kid", "g1"], "--kid must be"),
        (["--seq", "1"], "exactly one of --text or --text-file"),
    )
    for extra, needle in cases:
        proc = run_tool("sign", "--key", KEY_A1, *extra)
        assert proc.returncode == 2, (extra, proc.returncode, proc.stderr)
        assert needle in proc.stderr, (needle, proc.stderr)
        assert proc.stdout == "", "nothing may be emitted on a refusal"


def test_private_key_never_leaves_openssl():
    with open(KEY_A1, "r", encoding="utf-8") as handle:
        pem = handle.read()
    body = "".join(line for line in pem.splitlines() if "-----" not in line)
    proc = run_tool("sign", "--key", KEY_A1, "--text", "x", "--seq", "1")
    pub_proc = run_tool("pubkey", "--key", KEY_A1)
    for out in (proc.stdout, proc.stderr, pub_proc.stdout, pub_proc.stderr):
        assert body not in out
        assert "PRIVATE KEY" not in out
    src = open(TOOL, encoding="utf-8").read()
    assert "genpkey" not in src.replace(
        "umask 077 && openssl genpkey -algorithm ED25519 -out a1.pem", "")
    assert "open(args.key" not in src and "read_bytes" not in src


def test_constants_do_not_drift_from_the_hub():
    tool = tool_module()
    mod = hub()
    assert tool.DOMAIN == mod.ANNOUNCE_SIGNATURE_DOMAIN
    assert tool.KEY_SLOTS == mod.ANNOUNCE_KEY_SLOTS
    assert tool.ED25519_SPKI_PREFIX == mod.ANNOUNCE_ED25519_SPKI_PREFIX
    assert tool.MAX_PAYLOAD_BYTES == mod.ANNOUNCE_MAX_PAYLOAD_BYTES
    assert tool.MAX_TEXT_CHARS == mod.ANNOUNCE_MAX_TEXT_CHARS
    assert tool.MAX_SEQ == mod.ANNOUNCE_MAX_SEQ
    assert tool.HUB_PUBKEY_ENV.format(SLOT="A1") == "ANNOUNCE_PUBKEY_A1"
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_constants_match_the_dart_client():
    dart = os.path.join(REPO_ROOT, "lib", "announcement_signature.dart")
    if not os.path.exists(dart):
        raise AssertionError(f"lib/ not present at {dart}; copy it in to run this check")
    src = open(dart, encoding="utf-8").read()
    tool = tool_module()
    assert f"kAnnouncementSignatureDomain = '{tool.DOMAIN.decode()}'" in src
    assert f"kMaxAnnouncementPayloadBytes = {tool.MAX_PAYLOAD_BYTES}" in src
    for slot in tool.KEY_SLOTS:
        assert f"'{slot}': _kWinsAnnouncePubkey{slot.upper()}" in src
        assert tool.CLIENT_PUBKEY_DEFINE.format(SLOT=slot.upper()) in src


TESTS = [
    test_hub_accepts_what_the_tool_signs,
    test_text_file_and_a2_slot,
    test_hub_refuses_a_key_it_was_not_given,
    test_tool_refusals,
    test_private_key_never_leaves_openssl,
    test_constants_do_not_drift_from_the_hub,
    test_constants_match_the_dart_client,
]


def main():
    print("offline announcement signing tool")
    try:
        for fn in TESTS:
            check(fn.__name__, fn)
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
        for slot in ("A1", "A2", "A3"):
            os.environ.pop(f"ANNOUNCE_PUBKEY_{slot}", None)
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed, {len(TESTS)} total")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
