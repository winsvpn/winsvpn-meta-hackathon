"""S3 move contracts and negative controls from design v17 2.2, 5.5 and 5.6."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
import winn3_gateway_block as block


ROOT = Path(os.environ.get("S3_TEST_ROOT", Path(__file__).resolve().parents[1]))
if "S3_TEST_ROOT" in os.environ:
    spec = importlib.util.spec_from_file_location("baseline_block", ROOT / "tools/winn3_gateway_block.py")
    block = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(block)
DP = ROOT / block.TARGET
G = ROOT / block.SOURCE


def text():
    return DP.read_text(encoding="utf-8")


def source_script(tmp_path, body=None):
    path = tmp_path / "gateway.sh"
    path.write_text(block.sourceable(text()) if body is None else body, encoding="utf-8")
    return path


def test_equivalence():
    assert block.check(G.read_text(encoding="utf-8"), text()) == []


def test_loading_preserves_dp_state_and_traps(tmp_path):
    script = source_script(tmp_path)
    harness = r'''
set -euo pipefail
BACKUP_HOST_ID=fixture-host
RCLONE_REMOTE=fixture-remote
REQUIRE_REMOTE_BACKUP=1
BACKUP_AGE_RECIPIENTS_FILE=fixture-recipients
REQUIRE_BACKUP_ENCRYPTION=1
MODE=fixture-mode
WINN_CREDENTIALS_DIR=fixture-credentials
log() { printf 'dp-log'; }
warn() { printf 'dp-warn'; }
err() { printf 'dp-err'; }
trap ':' EXIT
before=$(trap -p)
functions=$(declare -f log warn err)
source "$1"
[[ "$(trap -p)" == "$before" ]]
[[ "$(declare -f log warn err)" == "$functions" ]]
[[ "$BACKUP_HOST_ID:$RCLONE_REMOTE:$REQUIRE_REMOTE_BACKUP" == fixture-host:fixture-remote:1 ]]
[[ "$BACKUP_AGE_RECIPIENTS_FILE:$REQUIRE_BACKUP_ENCRYPTION:$MODE:$WINN_CREDENTIALS_DIR" == fixture-recipients:1:fixture-mode:fixture-credentials ]]
'''
    result = subprocess.run(["bash", "-c", harness, "fixture", str(script)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""


def test_block_has_one_owner_for_removed_code():
    body = block.block_body(text().split("\n"))
    functions = block.top_level(body, "func")
    assert not functions.intersection(block.NOT_MOVED)
    assert not functions.intersection(block.FUNCTION_RENAMES)
    assert not block.top_level(body, "assign").intersection(block.NOT_MOVED)


@pytest.mark.parametrize("old,new", [
    ('wins_fw_lock || {', 'true || {'),
    ('install -d -m 750 -o root -g "${WINN3_GATEWAY_SERVICE_USER}" /etc/winn',
     'install -d -m 755 -o root -g root /etc/winn'),
    (' winn3-gateway.service winn3-gateway-firewall.service\n', '\n'),
    ('if ! wins_fw_lock; then', 'if false; then'),
    ('HOST_ID="${BACKUP_HOST_ID:?BACKUP_HOST_ID missing; re-run the installer}"',
     'HOST_ID="${BACKUP_HOST_ID:-gateway-$(hostname -s)}"'),
    ('WINN3_GATEWAY_CREDENTIALS_DIR=', 'WINN_CREDENTIALS_DIR='),
    ('winn3gw_log()', 'log() {'),
])
def test_mutants_fail_equivalence(old, new):
    original = text()
    assert old in original
    assert block.check(G.read_text(encoding="utf-8"), original.replace(old, new))


def test_post_move_edits_each_match_the_moved_text_exactly_once():
    # Allow-list 4 (TUNNEL-SPEED-2 OI-4): every entry's old text occurs
    # exactly once in G moved under allow-lists 1 to 3, and applying them
    # all yields the block, so no edit hides behind another.
    moved = "\n".join(block.render_moved(G.read_text(encoding="utf-8")))
    assert block.POST_MOVE_EDITS, "the reset build carries post-move edits"
    for edit in block.POST_MOVE_EDITS:
        assert moved.count("\n".join(edit["old"])) == 1, edit["id"]
        assert edit["old"] != edit["new"], edit["id"]
    assert block.render_body(G.read_text(encoding="utf-8")) == block.block_body(text().split("\n"))


@pytest.mark.parametrize("field", ["old", "new"])
def test_a_stale_or_unapplied_post_move_edit_is_refused(monkeypatch, field):
    edits = [dict(e, **{field: list(e[field])}) for e in block.POST_MOVE_EDITS]
    edits[-1][field] = edits[-1][field] + ["# not in the moved text"]
    monkeypatch.setattr(block, "POST_MOVE_EDITS", edits)
    failures = block.check(G.read_text(encoding="utf-8"), text())
    assert failures
    if field == "old":
        assert any("allow-list is stale: post-move edit" in f for f in failures), failures
    else:
        assert any("differs from the moved text outside the allow-list" in f for f in failures), failures


def test_the_dedicated_default_is_the_second_allowed_statement():
    # The only two statements the block may run when DP is loaded record
    # whether the operator supplied a variable; the second is OI-4's.
    assert len(block.ALLOWED_STATEMENTS) == 2
    dedicated = [s for s in block.ALLOWED_STATEMENTS if "WINN3_GATEWAY_DEDICATED" in s]
    assert len(dedicated) == 1
    assert dedicated[0] in text()
    assert 'WINN3_GATEWAY_DEDICATED_REASON=" (payment server present)"' in dedicated[0]
    assert "$(" not in dedicated[0] and "`" not in dedicated[0] and ">" not in dedicated[0]
    without = {s for s in block.ALLOWED_STATEMENTS if "WINN3_GATEWAY_DEDICATED" not in s}
    assert block.check(G.read_text(encoding="utf-8"), text()) == []
    import unittest.mock
    with unittest.mock.patch.object(block, "ALLOWED_STATEMENTS", without):
        failures = block.check(G.read_text(encoding="utf-8"), text())
    assert any("runs a top-level statement" in f and "WINN3_GATEWAY_DEDICATED" in f for f in failures), failures


@pytest.mark.parametrize("insertion", [
    'trap ":" EXIT',
    'BACKUP_HOST_ID=collision',
    'log() { :; }',
    'write_fail2ban_sshd_jail() { :; }',
    'WINN3_GATEWAY_SIDE_EFFECT=$(touch prohibited)',
])
def test_extra_code_fails(insertion):
    modified = text().replace(block.END, insertion + "\n" + block.END)
    assert block.check(G.read_text(encoding="utf-8"), modified)


def test_dp_defaults_exist_at_installer_scope():
    outside = block.outside_block(text().split("\n"))
    assert block.dp_provided_defaults(outside) == list(block.DP_PROVIDED.values())


@pytest.mark.parametrize("name", list(block.DP_PROVIDED))
def test_heredoc_default_cannot_replace_installer_default(name):
    lines = text().split("\n")
    outside = block.outside_block(lines)
    item = next(item for item in block.segment(outside)
                if item["kind"] == "assign" and item["name"] == name)
    lines[item["start"]] = ""
    changed = "\n".join(lines)
    if block.DP_PROVIDED[name] not in changed:
        changed += "\ncat <<'DEFAULT_FIXTURE'\n" + block.DP_PROVIDED[name] + "\nDEFAULT_FIXTURE\n"
    assert block.DP_PROVIDED[name] in changed
    assert block.check(G.read_text(encoding="utf-8"), changed)
    with pytest.raises(block.BlockError):
        block.sourceable(changed)


@pytest.mark.parametrize("name", list(block.DP_PROVIDED))
def test_duplicate_dp_default_is_refused(name):
    changed = text().replace(block.END, block.END + "\n" + name + '="override"')
    assert block.check(G.read_text(encoding="utf-8"), changed)
    with pytest.raises(block.BlockError):
        block.sourceable(changed)


def unpin(monkeypatch, source):
    # Pin the mutated source so check() reaches the structural checks, which
    # must refuse it on their own (the pin is tested separately below).
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    monkeypatch.setattr(block, "SOURCE_SHA256", digest, raising=False)


def test_shared_source_change_cannot_hide_top_level_command(monkeypatch):
    # Alter both sides so an equivalence-only checker would falsely pass.
    original = G.read_text(encoding="utf-8")
    for old, new in (
        ('  WINN3_GATEWAY_MAX_SESSIONS_SUPPLIED=1', '  touch prohibited'),
        ('WINN3_GATEWAY_MODE=""', 'WINN3_GATEWAY_MODE=$(touch prohibited)'),
        ('MODE=""', 'MODE=""; printf S3_SIDE_EFFECT >&2'),
        ('MODE=""', 'MODE=<(printf S3_SIDE_EFFECT >&2)'),
        ('MODE=""', 'MODE="" > prohibited'),
        ('MODE=""', 'MODE="${BACKUP_HOST_ID:=collision}"'),
        ('MODE=""', 'MODE="${WINN3_GATEWAY_ID@P}"'),
        ('ipt_gw() { iptables -w 10 "$@"; }',
         'ipt_gw() { iptables -w 10 "$@"; }; { printf S3_SIDE_EFFECT >&2; }'),
        ('ipt_gw() { iptables -w 10 "$@"; }',
         'ipt_gw() { iptables -w 10 "$@"; } > prohibited'),
        ('commands."\n}\n\n# ipt_gw, ensure_jump_gw',
         'commands."\n}; printf S3_SIDE_EFFECT >&2\n\n# ipt_gw, ensure_jump_gw'),
        ('commands."\n}\n\n# ipt_gw, ensure_jump_gw',
         'commands."\n} && { printf S3_SIDE_EFFECT >&2; }\n\n# ipt_gw, ensure_jump_gw'),
    ):
        source = original.replace(old, new)
        if source == original:
            # The standalone name is renamed by render_body.
            source = original.replace('MODE=""', 'MODE=$(touch prohibited)')
        assert source != original
        start, end = block.find_block(text().split("\n"))
        lines = text().split("\n")
        dp = "\n".join(lines[:start] + block.render_block(source) + lines[end + 1:])
        unpin(monkeypatch, source)
        failures = block.check(source, dp)
        assert not any("reviewed snapshot" in failure for failure in failures)
        assert any("top-level" in failure or "file top" in failure
                   for failure in failures)


CLOSERS = [
    "}; printf S3_SIDE_EFFECT >&2",
    "} && printf S3_SIDE_EFFECT >&2",
    "}; { printf S3_SIDE_EFFECT >&2; }",
    "} >/dev/null; printf S3_SIDE_EFFECT >&2",
    "  }; printf S3_SIDE_EFFECT >&2; { :\n}",
    "  :; }; printf S3_SIDE_EFFECT >&2; { :\n}",
    "  : '<<true'\n  }; printf S3_SIDE_EFFECT >&2; { :\ntrue\n}",
    # Closers that closes_early() miscounts: a literal or escaped "{" word, a
    # "<<" bash never reads as a here-document, and a "{" carried by a
    # continuation.
    "  : {\n  }; printf S3_SIDE_EFFECT >&2; { :\n  : }\n}",
    "  echo { >/dev/null\n  }; printf S3_SIDE_EFFECT >&2; { :\n  echo } >/dev/null\n}",
    "  : $[1<<true]\n  }; printf S3_SIDE_EFFECT >&2; { :\ntrue\n}",
    "  : \\\n  {\n  }; printf S3_SIDE_EFFECT >&2; { :\n  : \\\n  }\n}",
    "  : \\{\n  }; printf S3_SIDE_EFFECT >&2; { :\n  : \\}\n}",
]
# bash_closes_before_end() reads a prefix that leaves a here-document open as
# incomplete, so it misses this closer; closes_early() and
# bash_closes_at_last_line() refuse it, which is why all three readings stay.
HEREDOC_CLOSER = "  cat <<EOF; }; printf S3_SIDE_EFFECT >&2; { :\nEOF\n}"


@pytest.mark.parametrize("closer", [
    "}; printf S3_SIDE_EFFECT >&2",
    "} && printf S3_SIDE_EFFECT >&2",
    "}; { printf S3_SIDE_EFFECT >&2; }",
    "} >/dev/null; printf S3_SIDE_EFFECT >&2",
    "  }; printf S3_SIDE_EFFECT >&2; { :\n}",
    "  :; }; printf S3_SIDE_EFFECT >&2; { :\n}",
    "  : '<<true'\n  }; printf S3_SIDE_EFFECT >&2; { :\ntrue\n}",
])
def test_unreviewed_closer_source_is_refused(closer):
    original = G.read_text(encoding="utf-8")
    old = 'commands."\n}\n\n# ipt_gw, ensure_jump_gw'
    assert original.count(old) == 1
    source = original.replace(old, 'commands."\n' + closer + '\n\n# ipt_gw, ensure_jump_gw')
    lines = text().split("\n")
    start, end = block.find_block(lines)
    dp = "\n".join(lines[:start] + block.render_block(source) + lines[end + 1:])
    result = subprocess.run(["bash", "-n"], input=block.sourceable(dp),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert block.check(source, dp)


def test_source_pin_requires_review_even_for_a_comment_change():
    source = G.read_text(encoding="utf-8") + "\n# changed source snapshot\n"
    assert any("reviewed snapshot" in failure for failure in block.check(source, text()))


@pytest.mark.parametrize("closer", CLOSERS + [HEREDOC_CLOSER])
def test_indented_and_mid_line_closers_fail_without_the_pin(monkeypatch, closer):
    # The pin is renewed after each reviewed source change; the structural
    # check must still refuse a closer that leaves code to run on load.
    original = G.read_text(encoding="utf-8")
    old = 'commands."\n}\n\n# ipt_gw, ensure_jump_gw'
    source = original.replace(old, 'commands."\n' + closer + '\n\n# ipt_gw, ensure_jump_gw')
    lines = text().split("\n")
    start, end = block.find_block(lines)
    dp = "\n".join(lines[:start] + block.render_block(source) + lines[end + 1:])
    loaded = subprocess.run(["bash", "-u"], input=block.sourceable(dp),
                            capture_output=True, text=True, timeout=10)
    assert loaded.returncode == 0 and "S3_SIDE_EFFECT" in loaded.stderr
    unpin(monkeypatch, source)
    assert ("block function 'report_conntrack_status' is not a standalone definition at file top"
            in block.check(source, dp))


@pytest.mark.parametrize("definition,pure", [
    ('f() {\n  : { }\n}', True),
    ('f() {\n  : \\{ \\}\n}', True),
    ('f() {\n  read -r x <<<word\n}', True),
    ('f() {\n  (( n = 1 <<shift ))\n}', True),
    ('f() {\n  cat <<EOF\n}\nEOF\n}', True),
    ('f() {\n  echo "}" \'{\' "${y:-}"\n}', True),
    ('f() {\n  echo "\n}', False),
    ('f() {\n  {\n}', False),
    ('f() {\n  cat <<EOF\n}', False),
    ('f() {\n  : "<<EOF"\n  }; echo x; { :\nEOF\n}', False),
])
def test_closer_scan_reads_bash_structure(definition, pure):
    assert block.pure_function_definition(definition) is pure


@pytest.mark.parametrize("definition", [
    'f() {\n  : {\n  }; echo x; { :\n  : }\n}',
    'f() {\n  : $[1<<EOF]\n  }; echo x; { :\nEOF\n}',
    'f() {\n  :\nfi; echo x; if :; then\n  :\n}',
])
def test_bash_refuses_closers_the_scan_misreads(definition):
    assert block.pure_function_definition(definition) is False


@pytest.mark.parametrize("closer", CLOSERS[4:])
def test_each_bash_reading_refuses_a_closer_on_its_own(closer):
    # pure_function_definition() requires all three readings, so each bash
    # reading is checked here by itself: dropping either one must fail.
    lines = ("f() {\n" + closer).split("\n")
    assert block.bash_closes_at_last_line(lines) is False
    assert block.bash_closes_before_end(lines) is True


def test_bash_real_form_refuses_a_fi_closer():
    # The swapped form alone accepts a "fi" that closes it early; the
    # definition as written must be parsed as well.
    lines = 'f() {\n  :\nfi; echo x; if :; then\n  :\n}'.split("\n")
    assert block.bash_closes_at_last_line(lines) is False


def test_heredoc_closer_is_refused_without_the_prefix_scan():
    lines = ("f() {\n" + HEREDOC_CLOSER).split("\n")
    assert block.closes_early(lines) is True
    assert block.bash_closes_at_last_line(lines) is False
    assert block.pure_function_definition("\n".join(lines)) is False


@pytest.mark.parametrize("reading", ["bash_closes_at_last_line", "bash_closes_before_end"])
def test_every_reading_is_required(monkeypatch, reading):
    definition = 'f() {\n  : ok\n}'
    assert block.pure_function_definition(definition) is True
    refuse = (lambda lines: False) if reading == "bash_closes_at_last_line" else (lambda lines: True)
    monkeypatch.setattr(block, reading, refuse)
    assert block.pure_function_definition(definition) is False


def test_closer_scan_accepts_every_real_definition():
    # Anti-vacuity: the scan must not refuse any multi-line function that G
    # or DP defines today, or it would block the real tree for the wrong reason.
    for path in (G, DP):
        lines = path.read_text(encoding="utf-8").split("\n")
        functions = [item for item in block.segment(lines)
                     if item["kind"] == "func" and item["end"] > item["start"]]
        assert len(functions) > 100
        flagged = [item["name"] for item in functions
                   if block.closes_early(lines[item["start"]:item["end"] + 1])]
        assert flagged == []


def test_bash_reads_every_real_definition_as_closed_at_its_last_line():
    # Anti-vacuity for bash_closes_at_last_line: bash -n accepts every
    # function G and DP define today, in both forms.
    for path in (G, DP):
        lines = path.read_text(encoding="utf-8").split("\n")
        functions = [item for item in block.segment(lines)
                     if item["kind"] == "func" and item["end"] > item["start"]]
        assert len(functions) > 100
        flagged = [item["name"] for item in functions
                   if not block.bash_closes_at_last_line(lines[item["start"]:item["end"] + 1])]
        assert flagged == []


def test_bash_finds_no_complete_prefix_in_any_real_definition():
    # Anti-vacuity for bash_closes_before_end: no function G or DP defines
    # today parses as complete before its last "}".
    for path in (G, DP):
        lines = path.read_text(encoding="utf-8").split("\n")
        functions = [item for item in block.segment(lines)
                     if item["kind"] == "func" and item["end"] > item["start"]]
        assert len(functions) > 100
        flagged = [item["name"] for item in functions
                   if block.bash_closes_before_end(lines[item["start"]:item["end"] + 1])]
        assert flagged == []


def test_test_fixture_never_substitutes_g_moved_functions(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "test_source", Path(__file__).with_name("winn3_gateway_test_source.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / DP.name
    target.write_text(text().replace('winn3gw_log()', 'winn3gw_log_fixture()'))
    # Since slice S6 the fixture reads the frozen copy of G by the tree's own
    # path, not a G beside the target.
    result = module.fixture(target, legacy=True)
    assert 'winn3gw_log_fixture()' in result
    assert 'winn3gw_log()' not in result


def cleanup_source():
    body = block.function_text(text().split("\n"), "remove_stale_winn3_gateway_sysctls")
    assert body is not None, "S3 must retire exact legacy sysctl files"
    return re.search(r"<<'PYEOF'\n(.*?)\nPYEOF", body, re.S).group(1)


def test_sysctl_removes_only_exact_legacy_output(tmp_path):
    code = cleanup_source()
    scope = {"__name__": "fixture"}
    # Obtain the exact templates without invoking the deletion loop.
    prefix = code[:code.index('for name, accepted in (')]
    old_argv = sys.argv
    try:
        sys.argv = ["fixture", str(tmp_path)]
        exec(prefix, scope)
    finally:
        sys.argv = old_argv
    udp = tmp_path / "60-winn3-gateway-udp-buffers.conf"
    forward = tmp_path / "60-winn3-gateway-forward.conf"
    for expected in scope["known_forward"]:
        udp.write_bytes(scope["udp"])
        forward.write_bytes(expected)
        subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)], check=True, timeout=10)
        assert not udp.exists() and not forward.exists()
    # Comments, spacing and extra keys are material: preserve every byte.
    for changed in (scope["udp"] + b"# operator\n", scope["udp"].replace(b" = ", b"="),
                    scope["udp"] + b"net.core.somaxconn = 99\n"):
        udp.write_bytes(changed)
        subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)], check=True, timeout=10)
        assert udp.read_bytes() == changed
    udp.unlink()
    destination = tmp_path / "operator.conf"
    destination.write_bytes(scope["udp"])
    udp.symlink_to(destination)
    subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)], check=True, timeout=10)
    assert udp.is_symlink() and destination.read_bytes() == scope["udp"]


def test_sysctl_cleanup_is_wired_before_apply():
    setup = block.function_text(text().split("\n"), "setup_sysctl")
    assert setup.index("remove_stale_winn3_gateway_sysctls") < setup.index("sysctl --system")


def test_runtime_writer_holds_lock_until_last_mutation(tmp_path):
    runtime = re.search(r"<<'WINS_VPN_FW_EOF'\n(.*?)\nWINS_VPN_FW_EOF", text(), re.S).group(1)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "iptables"
    fake.write_text('''#!/usr/bin/env python3
import fcntl,json,os,sys
with open(os.environ["WINS_FIREWALL_LOCK"], "a") as lock:
    held = False
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        held = True
with open(os.environ["S3_TRACE"], "a") as out:
    out.write(json.dumps([sys.argv[1:], held]) + "\\n")
sys.exit(0)
''')
    fake.chmod(0o700)
    flock = ROOT / "server/testdata/winn3_gateway_fake_flock.py"
    (bin_dir / "flock").write_bytes(flock.read_bytes())
    (bin_dir / "flock").chmod(0o700)
    for name, commands in (("curl", "printf '%s\\n' " + " ".join(f"1.1.{i}.0/24" for i in range(10))),
                           ("ip", "exit 1"), ("logger", "exit 0")):
        path = bin_dir / name
        path.write_text("#!/bin/sh\n" + commands + "\n")
        path.chmod(0o700)
    transaction = tmp_path / "transaction"
    transaction.write_text("*filter\nCOMMIT\n")
    trace = tmp_path / "trace"
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
               IPTABLES_BIN=str(fake), IPTABLES_RESTORE_BIN=str(fake), S3_TRACE=str(trace),
               WINS_FIREWALL_LOCK=str(tmp_path / "lock"), WINS_FIREWALL_LOCK_WAIT="0",
               WINVPN_FW_TRANSACTION=str(transaction), WINVPN_FW_CF_CACHE=str(tmp_path / "cache"))
    env.pop("WINS_FIREWALL_LOCK_HELD", None)
    import json
    def run(body):
        trace.unlink(missing_ok=True)
        subprocess.run(["bash", "-c", body], env=env, capture_output=True, timeout=20)
        return [json.loads(line) for line in trace.read_text().splitlines()]
    calls = run(runtime)
    assert len(calls) > 10 and all(held for _, held in calls), calls
    mutant = runtime.replace("if ! wins_fw_lock; then", "if false; then")
    assert mutant != runtime
    assert any(not held for _, held in run(mutant))
    # A busy lock refuses before even the restore transaction runs.
    import fcntl
    with open(env["WINS_FIREWALL_LOCK"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        trace.unlink()
        result = subprocess.run(["bash", "-c", runtime], env=env,
                                capture_output=True, timeout=20)
        assert result.returncode != 0 and not trace.exists()


def test_replay_ruling_covers_the_data_plane_only():
    # Design v17 2.8: the S3 dual path ended in slice S6, which removed the
    # standalone installer's line in the same commit as its tombstone. The
    # frozen copy (block.SOURCE) and the tombstone are not locked.
    lock = (ROOT / "docs/rulings/RULINGS.lock").read_text()
    assert f"REQUIRE :: {block.TARGET} :: WINN3_GATEWAY_REPLAY_JOURNAL=1" in lock
    for retired in (block.SOURCE, block.TOMBSTONE):
        assert f"REQUIRE :: {retired} :: WINN3_GATEWAY_REPLAY_JOURNAL=1" not in lock


def test_inert_brace_word_in_a_definition_is_accepted():
    # Gemini, S3 Turn 5: a literal brace word inside a valid inert body is not
    # a closer; the Bash-parse checks decide structure, not a brace counter.
    assert block.pure_function_definition("f() {\n  : {\n}") is True
