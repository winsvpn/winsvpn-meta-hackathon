#!/usr/bin/env python3
"""Slice S6 (design v17 2.8, 5.4 and 6): the standalone gateway installer is a tombstone.

server/wins_winn3_gateway_install.sh is a pointer to the data-plane installer
and `exit 2`. This file holds that, and the three things that moved with it:

  * the tombstone itself: its exact shape, what it does when run in every old
    mode under a sandbox, and the mutants that must break it;
  * docs/rulings/RULINGS.lock: the standalone installer's replay-journal line
    is gone and the data-plane line stays, so tools/verify_rulings.sh is green;
  * tools/winn3_gateway_block.py: the equivalence checker proves the move
    against the frozen copy of the old installer (SOURCE), pinned by SHA-256,
    and also checks the tombstone.

It also pins which files read the frozen copy and which read the tombstone,
so the release-after-S6 deletion of both is an exact list.

Run: python3 -m pytest tools/test_winn3_gateway_tombstone.py
"""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import winn3_gateway_block as block  # noqa: E402

ROOT = Path(os.environ.get("S6_TEST_ROOT", Path(__file__).resolve().parents[1]))
TOMBSTONE = ROOT / block.TOMBSTONE
SNAPSHOT = ROOT / block.SOURCE
DP = ROOT / block.TARGET
LOCK = ROOT / "docs/rulings/RULINGS.lock"
POINTER = block.TOMBSTONE_POINTER

# Every mode the standalone installer ever accepted, plus ones it never did.
MODES = [
    [],
    ["--preflight"],
    ["--install"],
    ["--start"],
    ["--apply-listen-firewall"],
    ["--teardown-forwarding"],
    ["--help"],
    ["-h"],
    ["--bogus"],
    ["install"],
    ["--install", "--start"],
    ["--install", "--winn3-rollback"],
]
SHELLS = [s for s in dict.fromkeys(["/bin/bash", shutil.which("bash")]) if s and Path(s).exists()]
# Commands the old installer ran. Each is a canary that records its own call.
CANARIES = ["id", "iptables", "iptables-save", "iptables-restore", "ip6tables", "nft", "systemctl",
            "apt-get", "apt", "dpkg", "curl", "wget", "install", "mkdir", "cat", "tee", "sed", "awk",
            "rm", "mv", "cp", "chmod", "chown", "sysctl", "modprobe", "useradd", "groupadd", "file",
            "od", "openssl", "python3", "sha256sum", "ss", "ip", "flock", "stat", "date", "hostname",
            "logger", "nginx", "docker", "git", "ssh", "sudo", "uname", "whoami", "ls", "grep"]


def tombstone_text():
    return TOMBSTONE.read_text(encoding="utf-8")


def make_canaries(directory, mark):
    directory.mkdir()
    for name in CANARIES:
        path = directory / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >> "{mark}"\nexit 0\n', encoding="utf-8")
        path.chmod(0o755)


def tree_listing(*roots):
    entries = []
    for top in roots:
        for path in sorted(Path(top).rglob("*")):
            entries.append((str(path), path.is_dir(), path.stat().st_size if path.is_file() else 0))
    return entries


def behaviour_failures(script):
    """Run `script` (a copy of the tombstone) in every old mode under a sandbox.

    Returns a list of failures; empty means it behaves as the tombstone must:
    exit 2, a pointer on stderr, nothing on stdout, no command run, no file
    created or changed, whatever the arguments, shell or environment.
    """
    failures = []
    for shell in SHELLS:
        for env_extra in ({}, {"WINN_PROTOCOL_V3_ENABLE": "1", "WINN3_GATEWAY_FORWARD": "1",
                               "WINN3_GATEWAY_MODE": "install", "ALLOW_UNSUPPORTED_OS": "1",
                               "WINN3_GATEWAY_MANAGE_FIREWALL": "1"}):
            for args in MODES:
                with tempfile.TemporaryDirectory(prefix="winn3-tombstone-") as tmp:
                    tmp = Path(tmp)
                    work, home, canary = tmp / "cwd", tmp / "home", tmp / "bin"
                    work.mkdir()
                    home.mkdir()
                    mark = tmp / "mark.txt"
                    make_canaries(canary, mark)
                    before = tree_listing(work, home)
                    env = {"PATH": str(canary), "HOME": str(home), "TMPDIR": str(home), "LC_ALL": "C", **env_extra}
                    result = subprocess.run([shell, str(script), *args], cwd=work, env=env,
                                            capture_output=True, text=True, timeout=30)
                    label = f"{shell} {' '.join(args) or '(no args)'} env={'hostile' if env_extra else 'clean'}"
                    if result.returncode != 2:
                        failures.append(f"{label}: exit status {result.returncode}, want 2")
                    if result.stdout != "":
                        failures.append(f"{label}: wrote to stdout: {result.stdout[:80]!r}")
                    if POINTER not in result.stderr or "retired" not in result.stderr:
                        failures.append(f"{label}: stderr lacks the pointer: {result.stderr[:120]!r}")
                    if mark.exists():
                        failures.append(f"{label}: ran an external command: {mark.read_text().strip()[:80]!r}")
                    if tree_listing(work, home) != before:
                        failures.append(f"{label}: created or changed a file")
    # An empty PATH proves it needs no external command at all.
    with tempfile.TemporaryDirectory(prefix="winn3-tombstone-") as tmp:
        result = subprocess.run([SHELLS[0], str(script), "--install"], cwd=tmp, env={"PATH": ""},
                                capture_output=True, text=True, timeout=30)
        if result.returncode != 2 or POINTER not in result.stderr:
            failures.append(f"empty PATH: exit {result.returncode}, stderr {result.stderr[:80]!r}")
    # Sourcing it ends the sourcing shell with 2; nothing after it runs.
    sourced = subprocess.run([SHELLS[0], "-c", 'source "$1"; echo STILL_RUNNING', "x", str(script)],
                             capture_output=True, text=True, timeout=30)
    if sourced.returncode != 2 or "STILL_RUNNING" in sourced.stdout:
        failures.append(f"sourced: exit {sourced.returncode}, stdout {sourced.stdout[:40]!r}")
    return failures


# ---------------------------------------------------------------------------
# The tombstone, as shipped
# ---------------------------------------------------------------------------
def test_tombstone_shape_is_exact():
    assert block.tombstone_problems(tombstone_text()) == []


def test_tombstone_is_a_pointer_and_nothing_else():
    text = tombstone_text()
    assert len(text.split("\n")) <= block.TOMBSTONE_MAX_LINES
    assert len(text.encode("utf-8")) < 2500
    assert (ROOT / POINTER).is_file(), "the pointer names a file that is not in the tree"
    assert text.count("exit 2") >= 1 and text.rstrip().endswith("exit 2")
    assert "\u2014" not in text and "\u2013" not in text
    assert subprocess.run(["bash", "-n", str(TOMBSTONE)], capture_output=True).returncode == 0
    # None of the old installer's machinery is left in the text.
    for forbidden in ("main()", "require_root", "iptables", "systemctl", "apt-get", "set -e", "source ", "eval ",
                      "BASH_SOURCE", "$@", "$1", "case ", "mkdir", "install -", "cat >"):
        assert forbidden not in text, forbidden


def test_every_old_mode_exits_2_with_the_pointer_and_changes_nothing():
    failures = behaviour_failures(TOMBSTONE)
    assert failures == [], "\n".join(failures[:10])


def test_weekly_os_currency_lives_in_the_data_plane_not_in_the_tombstone():
    # HELD-INT2-1 (BV-3-C3 against S6): the gateway has no weekly maintenance
    # of its own after the move (design v17 2.1 E, 2.2 "merged into data-plane
    # code"; the checker lists write_gateway_weekly_maintenance as not moved).
    # The weekly OS-currency block lives in the data plane's weekly maintenance,
    # which runs on the gateway's host, and the tombstone stays a tombstone.
    text = tombstone_text()
    assert block.tombstone_problems(text) == []
    for needle in ("WINS-FWOS", "record_os_currency", "write_gateway_weekly_maintenance",
                   "wins-weekly-maintenance", "reboot_required"):
        assert needle not in text, needle
    assert "merged into DP's" in block.NOT_MOVED["write_gateway_weekly_maintenance"]
    dp = DP.read_text(encoding="utf-8")
    assert dp.count("# WINS-FWOS-WEEKLY-BEGIN") == 1 and dp.count("# WINS-FWOS-WEEKLY-END") == 1
    start = dp.index("\nwrite_weekly_maintenance() {\n")
    begin = dp.index("# WINS-FWOS-WEEKLY-BEGIN")
    restart = dp.index("if systemctl is-failed --quiet winn3-gateway.service; then", start)
    assert start < begin < restart < dp.index("\nEOF\n", begin)


def test_the_tombstone_is_not_the_old_installer_and_the_frozen_copy_is():
    old = SNAPSHOT.read_text(encoding="utf-8")
    assert tombstone_text() != old
    assert block.tombstone_problems(old) != [], "the checker would accept the old installer as the tombstone"
    assert "install_binary" in old and "apply_forwarding_firewall" in old


# ---------------------------------------------------------------------------
# Mutants of the tombstone. Each must be killed by the shape check, by the
# behaviour run, or by both, as declared.
# ---------------------------------------------------------------------------
def _replace(old, new):
    def mutate(text):
        assert old in text, old
        return text.replace(old, new, 1)
    return mutate


def _append_code(line):
    return lambda text: text.rstrip("\n").rsplit("exit 2", 1)[0] + line + "\nexit 2\n"


MUTANTS = {
    # name: (mutation, killed by "static", "behaviour" or "both")
    "exit 0": (_replace("\nexit 2\n", "\nexit 0\n"), "both"),
    "exit 1": (_replace("\nexit 2\n", "\nexit 1\n"), "both"),
    "exit 3": (_replace("\nexit 2\n", "\nexit 3\n"), "both"),
    "no exit": (_replace("\nexit 2\n", "\n"), "both"),
    "return instead of exit": (_replace("\nexit 2\n", "\nreturn 2\n"), "static"),
    "exit 2 then more code": (lambda text: text + "touch /tmp/after-exit\n", "static"),
    "message to stdout": (_replace(" >&2\nexit 2", "\nexit 2"), "both"),
    "no pointer": (lambda text: text.replace(POINTER, "the data-plane installer"), "both"),
    "pointer at the old installer": (_replace("  server/wins_data_plane_setup_ONETOUCH.sh'", "  server/wins_winn3_gateway_install.sh'"), "both"),
    "no marker": (_replace("# TOMBSTONE: the standalone", "# the standalone"), "static"),
    "no shebang": (lambda text: text.split("\n", 1)[1], "static"),
    "dash in the message": (_replace("It did nothing", "It did nothing \u2014 at all"), "static"),
    "set -e added": (_append_code("set -e"), "static"),
    "command added": (_append_code("iptables -F"), "both"),
    "write added": (_append_code("echo x > /etc/winn-marker"), "static"),
    "source added": (_append_code("source /etc/profile"), "static"),
    "argument read": (_append_code('[[ "${1:-}" == --install ]] && exit 0'), "both"),
    "main restored": (_append_code('main "$@"'), "static"),
    "function added": (_append_code("main() { :; }"), "static"),
    "double quoted message with expansion": (_replace("  'This file is a tombstone", '  "$(id) This file is a tombstone'), "static"),
    "message line with backslash": (_replace("changed nothing.'", "changed nothing.\\\\'"), "static"),
    "grown past the cap": (lambda text: text.replace("exit 2\n", "# pad\n" * 45 + "exit 2\n"), "static"),
    "body restored": (lambda text: SNAPSHOT.read_text(encoding="utf-8"), "both"),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_tombstone_mutants_are_killed(name, tmp_path):
    mutate, killed_by = MUTANTS[name]
    mutated = mutate(tombstone_text())
    assert mutated != tombstone_text()
    static = block.tombstone_problems(mutated)
    script = tmp_path / "mutant.sh"
    script.write_text(mutated, encoding="utf-8")
    if killed_by in ("static", "both"):
        assert static, f"{name}: the shape check accepted the mutant"
    if killed_by in ("behaviour", "both"):
        assert behaviour_failures(script), f"{name}: the behaviour run accepted the mutant"


def test_control_the_unmutated_tombstone_passes_both_checks(tmp_path):
    script = tmp_path / "control.sh"
    script.write_text(tombstone_text(), encoding="utf-8")
    assert block.tombstone_problems(script.read_text(encoding="utf-8")) == []
    assert behaviour_failures(script) == []


# ---------------------------------------------------------------------------
# The same contract in the deployment validator
# ---------------------------------------------------------------------------
def _validator():
    import validate_deployment_scripts as validator
    return validator


def test_validator_accepts_the_tombstone_and_refuses_mutants():
    validator = _validator()
    validator.validate_gateway_tombstone(tombstone_text())
    for name in ("exit 0", "main restored", "no pointer", "body restored", "no marker"):
        mutated = MUTANTS[name][0](tombstone_text())
        with pytest.raises(SystemExit) as raised:
            validator.validate_gateway_tombstone(mutated)
        assert "not the tombstone" in str(raised.value), name


def test_validator_listen_placement_reads_the_data_plane_block_and_is_not_vacuous():
    validator = _validator()
    dp = DP.read_text(encoding="utf-8")
    helper = validator.heredoc_text(dp, validator.GATEWAY_HELPER_HEREDOC)
    assert helper is not None and helper.count("\n") > 300, "the boot helper is not in the data-plane installer"
    assert validator.gateway_listen_placement_problem(dp, dp) is None
    insert = 'iptables -w 10 -I WINVPN-INPUT "$((lead + head + 1))" -p udp --dport "${port}" -j ACCEPT'
    assert insert in helper
    mutants = (
        dp.replace(helper, helper.replace(insert, 'iptables -w 10 -I WINVPN-INPUT -p udp --dport "${port}" -j ACCEPT', 1), 1),
        dp.replace(helper, helper.replace("local recovery='-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY'", "local recovery=''", 1), 1),
        dp.replace("# the boot helper: /usr/local/sbin/winn3-gateway-firewall", "# the boot helper: moved", 1),
    )
    validator.validate_gateway_listen_firewall_placement()
    for mutant in mutants:
        assert mutant != dp
        assert validator.gateway_listen_placement_problem(mutant, dp) is not None
        # The wrapper the release gate calls refuses it too, with the data plane as both inputs.
        with pytest.raises(SystemExit) as raised:
            validator.validate_gateway_listen_firewall_placement(gateway=mutant, data=dp)
        assert "gateway listen firewall" in str(raised.value)


def test_validator_v3_contract_runs_on_the_live_tombstone():
    validator = _validator()
    validator.validate_winn_protocol_v3_contract()
    with pytest.raises(SystemExit):
        validator.validate_winn_protocol_v3_contract(gateway=MUTANTS["exit 0"][0](tombstone_text()))


# ---------------------------------------------------------------------------
# docs/rulings/RULINGS.lock
# ---------------------------------------------------------------------------
LITERAL = "WINN3_GATEWAY_REPLAY_JOURNAL=1"
G_LINE = f"REQUIRE :: {block.TOMBSTONE} :: {LITERAL}"
DP_LINE = f"REQUIRE :: {block.TARGET} :: {LITERAL}"
DP_OK = f"RULINGS: ok   REQUIRE {block.TARGET} :: {LITERAL}"


def lock_entries():
    return [line for line in LOCK.read_text(encoding="utf-8").split("\n") if line and not line.startswith("#")]


def run_verify(root):
    return subprocess.run(["bash", str(ROOT / "tools/verify_rulings.sh"), str(root)],
                          capture_output=True, text=True, timeout=120).stdout.split("\n")


def test_lock_drops_the_standalone_line_and_keeps_the_data_plane_line():
    entries = lock_entries()
    assert G_LINE not in entries
    assert not [e for e in entries if f" {block.TOMBSTONE} " in e], "something still locks the tombstone"
    assert entries.count(DP_LINE) == 1
    assert [e for e in entries if LITERAL in e] == [DP_LINE]


def test_verify_rulings_is_green_on_the_tree():
    lines = run_verify(ROOT)
    bad = [line for line in lines if line.startswith("RULINGS: FAIL")]
    assert bad == []
    assert DP_OK in lines


def test_the_old_lock_line_would_fail_against_the_tombstone(tmp_path):
    # Anti-vacuity: S6 must remove the line in the same commit as the tombstone.
    (tmp_path / "docs/rulings").mkdir(parents=True)
    (tmp_path / "server").mkdir()
    (tmp_path / "docs/rulings/RULINGS.lock").write_text(G_LINE + "\n" + DP_LINE + "\n", encoding="utf-8")
    shutil.copy(TOMBSTONE, tmp_path / block.TOMBSTONE)
    (tmp_path / block.TARGET).write_text(f"main() {{\n  {LITERAL}\n}}\n", encoding="utf-8")
    lines = run_verify(tmp_path)
    assert f"RULINGS: FAIL REQUIRE {block.TOMBSTONE} :: {LITERAL} (literal absent)" in lines
    assert DP_OK in lines


def test_the_data_plane_line_fails_if_the_literal_is_commented_out(tmp_path):
    (tmp_path / "docs/rulings").mkdir(parents=True)
    (tmp_path / "server").mkdir()
    (tmp_path / "docs/rulings/RULINGS.lock").write_text(DP_LINE + "\n", encoding="utf-8")
    (tmp_path / block.TARGET).write_text(f"main() {{\n  # {LITERAL}\n}}\n", encoding="utf-8")
    assert f"RULINGS: FAIL REQUIRE {block.TARGET} :: {LITERAL} (literal absent)" in run_verify(tmp_path)


# ---------------------------------------------------------------------------
# The equivalence checker, now against the frozen copy
# ---------------------------------------------------------------------------
def run_checker(*extra):
    return subprocess.run([sys.executable, "-I", str(ROOT / "tools/winn3_gateway_block.py"), "check",
                           "--root", str(ROOT), *extra], capture_output=True, text=True, timeout=300)


def test_the_checker_pins_the_frozen_copy_not_the_tombstone():
    assert block.SOURCE != block.TOMBSTONE
    assert SNAPSHOT.is_file()
    assert hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest() == block.SOURCE_SHA256
    assert not os.access(SNAPSHOT, os.X_OK), "the frozen copy must not be executable"
    assert hashlib.sha256(TOMBSTONE.read_bytes()).hexdigest() != block.SOURCE_SHA256


def test_the_checker_is_green_and_checks_the_tombstone():
    result = run_checker()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "equivalent" in result.stdout


def test_checker_mutants_are_killed(tmp_path):
    old = SNAPSHOT.read_text(encoding="utf-8")
    cases = {
        # one byte of the frozen copy changed
        "frozen copy edited": (["--source"], old.replace("log()", "log ()", 1), "source safety"),
        # the pin repointed at the tombstone
        "pin repointed at the tombstone": (["--source"], tombstone_text(), "source safety"),
        # the tombstone replaced by the old body
        "tombstone replaced by the old installer": (["--tombstone"], old, "tombstone:"),
        "tombstone exits 0": (["--tombstone"], MUTANTS["exit 0"][0](tombstone_text()), "tombstone: the tombstone must end with exit 2"),
        "tombstone empty": (["--tombstone"], "", "tombstone:"),
    }
    for name, (flag, text, expect) in cases.items():
        path = tmp_path / (name.replace(" ", "_") + ".sh")
        path.write_text(text, encoding="utf-8")
        result = run_checker(*flag, str(path))
        assert result.returncode == 1, f"{name}: the checker accepted it\n{result.stdout}"
        assert expect in result.stdout, f"{name}: wrong failure\n{result.stdout[:400]}"
    missing = run_checker("--tombstone", str(tmp_path / "does-not-exist.sh"))
    assert missing.returncode == 1 and "tombstone" in missing.stdout


# ---------------------------------------------------------------------------
# Who reads what. The release after S6 deletes the tombstone, the frozen copy,
# this checker and every reader of the frozen copy together; the list below is
# that deletion manifest. A new reader of either file fails here until it is
# listed on purpose.
# ---------------------------------------------------------------------------
FROZEN_RE = re.compile(r"winn3_gateway_install_retired|block\.SOURCE")
TOMBSTONE_RE = re.compile(r"wins_winn3_gateway_install\.sh")
SCAN_ROOTS = ("tools", "server")
SCAN_SUFFIXES = (".py", ".sh")

# Every file that reads the frozen copy of the old installer, by path or through
# block.SOURCE. These and the frozen copy go together.
FROZEN_READERS = {
    "server/test_winn3_gateway_preflight_readonly.py",
    "server/test_winn3_gateway_udp_buffers.sh",
    "server/test_winn3_onetouch_s5.py",  # slice S5: adoption runs the real pre-tombstone installer
    "server/wins_winn3_gateway_install.sh",  # the tombstone's own comment names the directory
    "tools/gcp_proof_remote_install_test.py",
    "tools/gcp_proof_resource_role_contract_test.py",
    "tools/test_backup_recipients_provisioning.sh",
    "tools/test_data_plane_sync_contract.py",
    "tools/test_freecap.py",
    "tools/test_integ1_installer_interactions.py",
    "tools/test_sysctl_single_owner.py",  # slice P1: P-1 reads the former UDP buffer target here
    "tools/test_winn3_gateway_block.py",
    "tools/test_winn3_gateway_tombstone.py",
    "tools/winn3_gateway_block.py",
    "tools/winn3_gateway_test_source.py",
}
# Every file under tools/ and server/ that names the tombstone's path. None of
# them runs it as a source: they test the tombstone, carry the path as a
# manifest string (GCP proof tooling), or mention it in prose.
TOMBSTONE_NAMERS = {
    "server/test_winn3_gateway_preflight_exit.sh",
    "server/test_winn3_gateway_preflight_readonly.py",
    "server/test_winn3_gateway_udp_buffers.sh",
    "server/test_winn3_onetouch_s5.py",
    "server/wins_control_plane_setup_ONETOUCH.sh",
    "server/wins_data_plane_setup_ONETOUCH.sh",
    "server/wins_winn3_gateway_install.sh",
    "server/wins_winn3_gateway_install_ech_path_unit_test.sh",
    "server/wins_winn3_gateway_install_forward_loud_test.sh",
    "server/wins_winn3_gateway_install_maintenance_test.sh",
    "server/wins_winn3_gateway_install_memory_unit_test.sh",
    "server/wins_winn3_gateway_install_session_cap_unit_test.sh",
    "server/wins_winn3_gateway_install_socketbind_unit_test.sh",
    "server/wins_winn3_gateway_install_tcp53_unit_test.sh",
    "tools/build_winn_protocol_engine.sh",
    "tools/gcp_deployment_inputs.py",
    "tools/gcp_proof_deploy.py",
    "tools/gcp_proof_deploy_test.py",
    "tools/gcp_proof_fleet.py",
    "tools/gcp_proof_remote_install.py",
    "tools/gcp_proof_remote_install_test.py",
    "tools/gcp_proof_resource_role_contract_test.py",
    "tools/run_round36_surface_audit.py",
    "tools/test_backup_recipients_provisioning.sh",
    "tools/test_data_plane_sync_contract.py",
    "tools/test_installer_owned_paths_manifest.sh",
    "tools/test_require_supported_production_os.py",
    "tools/test_rulings_round8.py",
    "tools/test_sysctl_single_owner.py",
    "tools/test_winn3_gateway_tombstone.py",
    "tools/test_winn_protocol_v3_split_deploy.py",
    "tools/validate_deployment_scripts.py",
    "tools/winn3_gateway_block.py",
    "tools/winn3_gateway_provision_keys.sh",
}


def scan(pattern, root=ROOT):
    found = set()
    for top in SCAN_ROOTS:
        for path in sorted((root / top).rglob("*")):
            if path.suffix in SCAN_SUFFIXES and path.is_file() and pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                found.add(path.relative_to(root).as_posix())
    return found


def test_frozen_copy_readers_are_exactly_the_listed_files():
    assert scan(FROZEN_RE) == FROZEN_READERS


def test_files_naming_the_tombstone_are_exactly_the_listed_files():
    # A suite that took the tombstone as its default input would test nothing.
    # A new file naming it fails here until it is listed on purpose.
    assert scan(TOMBSTONE_RE) == TOMBSTONE_NAMERS


def test_the_gateway_suites_take_the_data_plane_installer_by_default():
    for path in sorted((ROOT / "server").glob("wins_winn3_gateway_install_*_test.sh")):
        text = path.read_text(encoding="utf-8")
        if path.name == "wins_winn3_gateway_install_oi5_isolation_unit_test.sh":
            assert 'DP="${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}"' in text, path.name
            assert "END { if (count != 9) exit 1 }" in text, path.name
            assert '\' "${DP}" > "${WORK}/defs.sh"' in text, path.name
        else:
            assert re.search(r'winn3_gateway_test_source\.py" "\$\{1:-\$\{HERE\}/wins_data_plane_setup_ONETOUCH\.sh\}"', text), path.name
        assert "${HERE}/wins_winn3_gateway_install.sh" not in text, path.name


def test_the_scans_are_not_vacuous(tmp_path):
    # Control: files naming the frozen copy or the tombstone are found by the same scans.
    (tmp_path / "tools").mkdir()
    (tmp_path / "server").mkdir()
    (tmp_path / "tools/probe_a.py").write_text("x = 'winn3_gateway_install_retired'\n", encoding="utf-8")
    (tmp_path / "server/probe_b.sh").write_text("bash server/wins_winn3_gateway_install.sh\n", encoding="utf-8")
    (tmp_path / "server/probe_c.txt").write_text("winn3_gateway_install_retired\n", encoding="utf-8")
    assert scan(FROZEN_RE, tmp_path) == {"tools/probe_a.py"}
    assert scan(TOMBSTONE_RE, tmp_path) == {"server/probe_b.sh"}


# ---------------------------------------------------------------------------
# Fix round T2: the tombstone is executable, and the GCP proof runbook is exact
# ---------------------------------------------------------------------------
def direct_exec_failures(script, mode):
    """Copy `script` with `mode` and run it directly, as an operator's old command would."""
    with tempfile.TemporaryDirectory(prefix="winn3-tombstone-") as tmp:
        copy = Path(tmp) / "wins_winn3_gateway_install.sh"
        copy.write_bytes(Path(script).read_bytes())
        copy.chmod(mode)
        failures = []
        if (copy.stat().st_mode & 0o777) != 0o755:
            failures.append(f"mode {oct(copy.stat().st_mode & 0o777)}, want 0o755")
        try:
            result = subprocess.run([str(copy), "--install"], cwd=tmp, env={"PATH": "/usr/bin:/bin"},
                                    capture_output=True, text=True, timeout=30)
        except OSError as exc:
            return failures + [f"direct execution failed: {exc}"]
        if result.returncode != 2:
            failures.append(f"direct execution exit status {result.returncode}, want 2")
        if POINTER not in result.stderr:
            failures.append(f"direct execution stderr lacks the pointer: {result.stderr[:80]!r}")
        if result.stdout != "":
            failures.append("direct execution wrote to stdout")
        return failures


def test_the_tombstone_is_mode_0755_and_direct_execution_prints_the_pointer():
    # Q9 of the Claude seat: git keeps the tombstone at 755, so `./server/...` prints the
    # pointer and exits 2 instead of "permission denied" (rc 126). The shipped file is checked
    # in place, and a copy at 0o755 is run directly.
    assert (TOMBSTONE.stat().st_mode & 0o777) == 0o755, oct(TOMBSTONE.stat().st_mode & 0o777)
    assert os.access(TOMBSTONE, os.X_OK)
    assert direct_exec_failures(TOMBSTONE, 0o755) == []
    assert not os.access(SNAPSHOT, os.X_OK), "the frozen copy stays a non-executable fixture"


@pytest.mark.parametrize("mode", [0o644, 0o700, 0o775])
def test_direct_execution_mutants_on_the_tombstone_mode_are_killed(mode):
    assert direct_exec_failures(TOMBSTONE, mode), oct(mode)


RUNBOOK = ROOT / "docs/runbooks/GCP_PROOF_FLEET.md"
RELEASE_GATE = ROOT / "tools/fin_release_gate.sh"
RETARGET_STEPS = (
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--preflight"),
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--deploy"),
    ("data-winn3", "server/wins_data_plane_setup_ONETOUCH.sh", "--preflight"),
    ("data-winn3", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--preflight"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),
)
RETARGET_LAST = {"control": 1, "data-winn3": 3, "data-cover": 5}
G21_INTERIM_BLOCKER = "S6 GCP deployment contract retarget is pending after S4"
GATE_NEEDLES = (
    "gcp-receipt-window-hours=6",
    "WINS_GCP_PROOF_ACCEPTANCE_RECEIPT",
    "GCP acceptance proof is an owner/external blocker; 6-hour receipt window cannot be skipped",
    G21_INTERIM_BLOCKER,
)


def runbook_problems(text):
    """What the runbook notice must say so the retired-installer state cannot be misread."""
    import ast
    problems = []
    for needle in (
        "tools/fin_release_gate.sh",
        "stays fail closed",
        "do not retire this tooling",
        "do not\nweaken the release gate",
        "Existing receipts must not be promoted",
        "post-S4 item",
        "PROOF_KEY_PROVISION_ID",
        "GATEWAY_INSTALLER",
        "/etc/winsvpn/role",
        "S6 GCP deployment contract retarget is pending after S4",
    ):
        if needle not in text:
            problems.append(f"notice lacks {needle!r}")
    if "Do not start a proof run from this runbook before that ruling" in text:
        problems.append("notice still waits on a ruling that was made")
    blocks = re.findall(r"```python\n(EXPECTED_STEPS.*?)```", text, flags=re.S)
    if len(blocks) != 1:
        return problems + [f"want exactly one EXPECTED_STEPS block, found {len(blocks)}"]
    namespace = {}
    try:
        exec(compile(ast.parse(blocks[0]), "runbook", "exec"), {"__builtins__": {}}, namespace)  # literals only
    except Exception as exc:  # noqa: BLE001
        return problems + [f"EXPECTED_STEPS block does not evaluate: {exc}"]
    if namespace.get("EXPECTED_STEPS") != RETARGET_STEPS:
        problems.append("EXPECTED_STEPS is not the six data-plane and control-plane triples")
    if namespace.get("LAST_ROLE_STEP") != RETARGET_LAST:
        problems.append("LAST_ROLE_STEP is not control 1, data-winn3 3, data-cover 5")
    return problems


def gate_problems(text):
    return [f"release gate lost {needle!r}" for needle in GATE_NEEDLES if needle not in text]


def test_the_runbook_keeps_the_gate_and_states_the_exact_retarget():
    text = RUNBOOK.read_text(encoding="utf-8")
    assert runbook_problems(text) == []
    # The retarget names real installers, and the steps match the live constants.
    for _role, script, _flag in RETARGET_STEPS:
        assert (ROOT / script).is_file(), script
    assert gate_problems(RELEASE_GATE.read_text(encoding="utf-8")) == []


def test_runbook_mutants_are_killed():
    text = RUNBOOK.read_text(encoding="utf-8")
    start = text.index("**Retired installer")
    end = text.index("Placeholders below")
    steps_line = '    ("data-winn3", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),\n'
    cases = {
        "notice removed": text[:start] + text[end:],
        "gate sentence removed": text.replace("stays fail closed", "is relaxed"),
        "tooling retirement allowed": text.replace("do not retire this tooling", "retire this tooling"),
        "old wait-for-ruling returned": text.replace("Do not\nstart a proof run", "Do not start a proof run from this runbook before that ruling. Do not\nstart a proof run", 1),
        "step dropped": text.replace(steps_line, "", 1),
        "step uses the retired installer": text.replace(steps_line, '    ("data-winn3", "server/wins_winn3_gateway_install.sh", "--install"),\n', 1),
        "last role step wrong": text.replace('"data-winn3": 3', '"data-winn3": 5', 1),
        "receipts may be promoted": text.replace("Existing receipts must not be promoted", "Existing receipts are promoted"),
    }
    for name, mutated in cases.items():
        assert mutated != text, f"mutant {name!r} changed nothing"
        assert runbook_problems(mutated), f"mutant {name!r} survived"


def test_release_gate_mutants_are_killed():
    gate = RELEASE_GATE.read_text(encoding="utf-8")
    for needle in GATE_NEEDLES:
        mutated = gate.replace(needle, "")
        assert mutated != gate, needle
        assert gate_problems(mutated), f"removing {needle!r} survived"


def g21_outcome(gate_text, receipt_kind="unrelated"):
    """Run gate_G21 from `gate_text` alone, with only its unrelated prerequisites stubbed.

    Custody, Inno and the owner proofs are stubbed as satisfied; the GCP receipt is a real
    absolute regular file whose contents are NOT a GCP acceptance receipt ("unrelated" is a
    Markdown note, "old" is an empty JSON object). Returns (status, message).
    """
    match = re.search(r"(?ms)^gate_G21\(\) \{.*?\n^}\n", gate_text)
    assert match, "gate_G21 body not found"
    with tempfile.TemporaryDirectory(prefix="g21-") as tmp:
        tmp = Path(tmp)
        receipt = tmp / "receipt.txt"
        receipt.write_text("# a debate packet, not a receipt\n" if receipt_kind == "unrelated" else "{}\n")
        owner = tmp / "owner.json"
        owner.write_text("{}\n")
        harness = tmp / "harness.sh"
        harness.write_text(
            "PASS=0; FAIL=1; BLOCKED=2\n"
            'record() { local g="$1" st="$2"; shift 2; printf "%s|%s\\n" "$st" "$*"; }\n'
            "authenticate_release_python() { return 0; }\n"
            "_require_sourced_custody_wrappers() { return 0; }\n"
            "run_release_inno_verify_pins() { echo inno-ok; return 0; }\n"
            f'run_release_python() {{ {shlex.quote(sys.executable)} -I "$@"; }}\n'
            f"SCRIPT_DIR={shlex.quote(str(ROOT / 'tools'))}\n"
            + match.group(0)
            + "gate_G21\n"
        )
        env = {
            "PATH": os.environ["PATH"],
            "WINS_FINAL_REVIEWS_RECEIPT": str(owner),
            "WINS_APPLE_INSTALLER_IDENTITY_PROOF": str(owner),
            "WINS_RELEASE_INPUT_INDEX": str(owner),
            "WINS_GCP_PROOF_ACCEPTANCE_RECEIPT": str(receipt),
        }
        result = subprocess.run(["bash", str(harness)], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    line = result.stdout.strip().splitlines()[-1]
    status, _, message = line.partition("|")
    return {"0": "PASS", "1": "FAIL", "2": "BLOCKED"}[status], message


@pytest.mark.parametrize("receipt_kind", ["unrelated", "old"])
def test_g21_cannot_pass_on_an_unvalidated_receipt_while_the_retarget_is_pending(receipt_kind):
    # Sol S6-T2: G21 accepted any absolute regular file as the GCP receipt. While the
    # post-S4 retarget is pending, even with every other proof present it must be BLOCKED.
    status, message = g21_outcome(RELEASE_GATE.read_text(encoding="utf-8"), receipt_kind)
    assert status == "BLOCKED", (status, message)
    assert G21_INTERIM_BLOCKER in message


def test_g21_harness_reproduces_the_pass_without_the_interim_blocker():
    # Anti-vacuity: the same inputs against the pre-fix gate report PASS (Sol's finding).
    gate = RELEASE_GATE.read_text(encoding="utf-8")
    line = f'    blockers+=("{G21_INTERIM_BLOCKER}; existing receipts cannot certify this tree")\n'
    assert gate.count(line) == 1
    assert g21_outcome(gate.replace(line, ""))[0] == "PASS"


def test_g21_interim_blocker_mutants_are_killed():
    gate = RELEASE_GATE.read_text(encoding="utf-8")
    line = f'    blockers+=("{G21_INTERIM_BLOCKER}; existing receipts cannot certify this tree")\n'
    cases = {
        "blocker removed": gate.replace(line, ""),
        "blocker commented out": gate.replace(line, "    # " + line.strip() + "\n"),
        "blocker only when no receipt is supplied": gate.replace(
            line, '    [[ -z "${WINS_GCP_PROOF_ACCEPTANCE_RECEIPT:-}" ]] && ' + line.strip() + "\n"),
    }
    for name, mutated in cases.items():
        assert mutated != gate, name
        assert g21_outcome(mutated)[0] != "BLOCKED", f"mutant {name!r} survived"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
