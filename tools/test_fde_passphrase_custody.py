#!/usr/bin/env python3
"""Regression checks for FDE passphrase delivery and final key custody."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IONOS = ROOT / "deploy" / "ionos_fde_reinstall.sh"
CHAIN = ROOT / "deploy" / "fde_boot_chain.sh"
HANDOFF = ROOT / "docs" / "blueprints" / "WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md"
CUSTODY = ROOT / "docs" / "FDE_CUSTODY_CLOSURE.md"
# deploy/ionos_fde_reinstall.sh is retired (LUKS-FIX, D1 (b)): a tombstone that
# names the one supported path. fde_boot_chain.sh is the only conversion entrypoint.
TOMBSTONE_POINTERS = ("deploy/make_ionos_user_data.sh", "deploy/fde_boot_chain.sh")
TOMBSTONE_MARKER = (
    "# TOMBSTONE: the standalone IONOS FDE conversion script, retired by the"
)
TOMBSTONE_MAX_LINES = 40
TOMBSTONE_FIRST_CODE_LINE = "printf '%s\\n' \\"
# One quoted message line: single-quoted, so nothing expands, and continued with
# a backslash except for the last, which redirects to stderr.
TOMBSTONE_MESSAGE_LINE = re.compile(r"^  '[^'$`\\]*'( \\| >&2)$")


def test_fde_scripts_are_valid_bash() -> None:
    for script in (IONOS, CHAIN):
        completed = subprocess.run(
            ["bash", "-n", str(script)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr


def test_embedded_boot_hook_is_valid_posix_shell() -> None:
    if shutil.which("dash") is None:
        pytest.skip("dash is required to syntax-check the embedded initramfs hook")
    text = CHAIN.read_text(encoding="utf-8")
    marker = 'cat > "${PREMOUNT_DIR}/zz-winn-fde-v4" <<\'EOS\'\n'
    start = text.index(marker) + len(marker)
    end = text.index("\nEOS\n", start)
    hook = text[start:end] + "\n"
    completed = subprocess.run(
        ["dash", "-n"],
        input=hook,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_passphrase_is_never_embedded_or_extracted_from_script() -> None:
    for script in (IONOS, CHAIN):
        text = script.read_text(encoding="utf-8")
        assert "LUKS_PASSPHRASE=" not in text
        assert "STAGED_PASSPHRASE" not in text
    text = CHAIN.read_text(encoding="utf-8")
    assert 'PASS_FILE="/root/.winn-fde-pass"' in text or (
        "PASS_FILE_ON_ROOT=/root/.winn-fde-pass" in text
    )


def test_boot_chain_enforces_exact_file_custody() -> None:
    required = (
        '[[ ! -L "${file}" ]]',
        "stat -c '%u'",
        "stat -c '%a'",
        "stat -c '%h'",
        '"${mode}" == "600"',
        '"${links}" == "1"',
        "bytes >= 32 && bytes <= 4096",
        "tr -cd '\\n'",
        "must not start or end with whitespace",
        "/root is group- or other-writable",
    )
    text = CHAIN.read_text(encoding="utf-8")
    for marker in required:
        assert marker in text


def test_boot_chain_removes_conversion_slot_before_production_secret() -> None:
    text = CHAIN.read_text(encoding="utf-8")
    kill = text.index("cryptsetup luksKillSlot")
    post_kill_verify = text.index(
        'cryptsetup open --test-passphrase --key-file "${PRODUCTION_KEY}"', kill
    )
    remove = text.index(
        "remove_secret_file /winnmnt/root/.winn-fde-pass", post_kill_verify
    )
    assert kill < post_kill_verify < remove
    assert '[ ! -e "${SECRET_FILE}" ] && [ ! -L "${SECRET_FILE}" ]' in text
    for residue in (
        "conf/winn-fde-conversion-key",
        "winn-fde-pass",
        "winn-luks-initpass",
    ):
        assert residue in text


def test_handoff_describes_the_shipped_interactive_unlock_design() -> None:
    text = HANDOFF.read_text(encoding="utf-8")
    fde = next(line for line in text.splitlines() if line.startswith("**FDE:**"))
    assert "separate `/boot`" in fde
    assert "No keyfile or GRUB cryptodisk" in fde
    assert "dropbear on port 2222" in fde
    assert "Never place it in provider user-data" in fde
    assert "docs/FDE_CUSTODY_CLOSURE.md" in fde
    assert "deploy/make_ionos_user_data.sh" in fde
    assert "`ionos_fde_reinstall.sh` is retired and refuses to run" in fde


def test_boot_chain_publishes_completion_only_after_custody_closes() -> None:
    text = CHAIN.read_text(encoding="utf-8")
    kill = text.index("cryptsetup luksKillSlot")
    negative = text.index("CONVERSION_CHALLENGE_RC=$?", kill)
    positive = text.index("PRODUCTION_CHALLENGE_RC=$?", negative)
    final_slots = text.index("FINAL_SLOT_COUNT=", positive)
    passphrase_absent = text.index(
        "remove_secret_file /winnmnt/root/.winn-fde-pass", final_slots
    )
    receipt = text.index('mv "${CUSTODY_FINAL_TMP}" "${CUSTODY_FINAL}"', passphrase_absent)
    marker = text.index(
        "mv \"${DONE_TMP}\" /winnmnt/var/lib/winn-fde-done", receipt
    )
    assert kill < negative < positive < final_slots < passphrase_absent < receipt < marker
    assert "touch /var/lib/winn-fde-done" not in text
    assert 'CONVERSION_CHALLENGE_RC}" -eq 2' in text
    assert 'PRODUCTION_CHALLENGE_RC}" -eq 0' in text


def test_boot_chain_checks_every_retained_initramfs_without_vacuous_pass() -> None:
    text = CHAIN.read_text(encoding="utf-8")
    required = (
        "find /boot -maxdepth 1 -type f -name 'initrd.img-*'",
        'LISTING_LINES}" -ge 20',
        "scripts/local-top/cryptroot",
        "^(usr/)?sbin/cryptsetup$",
        "^(usr/)?sbin/dropbear$",
        "^(usr/)?s?bin/ip$",
        "scripts/init-premount/00-winn-fde-network",
        "scripts/init-bottom/zz-winn-fde-network-handoff",
        "conf/winn-fde-conversion-key",
        "initramfs_count=",
        "sha256sum \"${CANDIDATE}\"",
        "BOOTABLE_INITRD_COUNT",
    )
    for marker in required:
        assert marker in text


def test_source_digest_receipt_has_one_producer_and_two_consumers() -> None:
    text = CHAIN.read_text(encoding="utf-8")
    assert text.count("> /var/lib/winn-fde-source.sha256") == 1
    assert 'cat /var/lib/winn-fde-source.sha256' in text
    assert 'remove_operational_file /winnmnt/var/lib/winn-fde-source.sha256' in text


def test_required_bootable_initramfs_assets_preserve_unlock_contract() -> None:
    text = CHAIN.read_text(encoding="utf-8")
    for exact_path in (
        "scripts/local-top/cryptroot",
        "scripts/init-premount/00-winn-fde-network",
        "scripts/init-bottom/zz-winn-fde-network-handoff",
        "conf/conf.d/winn-fde-network",
    ):
        assert exact_path in text
    for portable_path in (
        "^(usr/)?sbin/cryptsetup$",
        "^(usr/)?sbin/dropbear$",
        "^(usr/)?s?bin/ip$",
    ):
        assert portable_path in text


def test_boot_chain_removes_explicit_staged_scripts() -> None:
    # The retired reinstall script stays on the list: a host staged by an older
    # user-data route can still carry it, and the closure must find it absent.
    text = CHAIN.read_text(encoding="utf-8")
    assert "/root/fde.sh" in text
    assert "/root/fde_boot_chain.sh" in text
    assert "/root/ionos_fde_reinstall.sh" in text
    assert "rm -f /root/*fde*" not in text


# ---------------------------------------------------------------------------
# The retired reinstall script. It is held to the shape and the behaviour of the
# retired standalone gateway installer (tools/test_winn3_gateway_tombstone.py):
# a pointer and `exit 2`, nothing else. The 21 cases that used to slice the old
# conversion body (passphrase-file custody under hostile file shapes, the
# already-encrypted no-op, the e2fsck status dispatch) tested code that no longer
# exists. What a tombstone still owes is proved here by running it: it touches
# no passphrase file of any shape, runs no command, and cannot be revived by a
# one-line edit without a failing mutant.
# ---------------------------------------------------------------------------
def tombstone_problems(text: str) -> list[str]:
    """Why `text` is not the tombstone, as a list; empty means it is."""
    problems = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "#!/usr/bin/env bash":
        problems.append("the tombstone must start with #!/usr/bin/env bash")
    if not any(line.startswith(TOMBSTONE_MARKER) for line in lines):
        problems.append(f"the tombstone lost its marker line {TOMBSTONE_MARKER!r}")
    if len(lines) > TOMBSTONE_MAX_LINES:
        problems.append(f"the tombstone is {len(lines)} lines; at most {TOMBSTONE_MAX_LINES}")
    if "\u2014" in text or "\u2013" in text:
        problems.append("the tombstone carries an em or en dash")
    code = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not code or code[-1] != "exit 2":
        problems.append("the tombstone must end with exit 2, its only exit")
    if sum(1 for line in code if re.match(r"\s*(exit|return)\b", line)) != 1:
        problems.append("the tombstone must have exactly one exit and no return")
    if not code or code[0] != TOMBSTONE_FIRST_CODE_LINE:
        problems.append(f"the first code line must be {TOMBSTONE_FIRST_CODE_LINE!r}")
    message = code[1:-1]
    if not message:
        problems.append("the tombstone prints no message")
    for line in message:
        if not TOMBSTONE_MESSAGE_LINE.match(line):
            problems.append(f"a code line is not a quoted message line: {line.strip()!r}")
    if message and not message[-1].endswith(" >&2"):
        problems.append("the message must go to stderr (the last message line ends with >&2)")
    if any(line.endswith(" >&2") for line in message[:-1]):
        problems.append("the message is split by an early >&2")
    for pointer in TOMBSTONE_POINTERS:
        if not any(pointer in line for line in message):
            problems.append(f"the message does not name {pointer}")
    return problems


# Every command the retired script ran. Each is a canary that records its call.
CANARIES = (
    "apt-get", "awk", "basename", "blockdev", "busybox", "cat", "chmod", "cp", "cryptsetup",
    "date", "df", "dpkg", "e2fsck", "findmnt", "grep", "grub-install", "head", "id", "install",
    "ip", "lsblk", "lsinitramfs", "mkdir", "mkfifo", "mv", "od", "resize2fs", "rm", "sed",
    "shred", "shutdown", "stat", "tail", "tee", "touch", "tr", "tune2fs", "uname",
    "update-grub", "update-initramfs", "wc",
)
# Every mode the old script accepted, plus ones it never did.
MODES = ([], ["--help"], ["--force"], ["install"], ["/dev/vda1"])
SHAPES = ("regular", "symlink", "hardlink", "fifo")
HOSTILE_ENV = {
    "PASS_FILE": "/root/.winn-fde-pass",
    "WINN_FDE_PREFLIGHT_ONLY": "1",
    "DEBIAN_FRONTEND": "noninteractive",
}
SHELLS = tuple(
    dict.fromkeys(path for path in ("/bin/bash", shutil.which("bash")) if path and Path(path).exists())
)


def _make_shape(path: Path, kind: str, sibling: Path) -> None:
    """A reserved passphrase pathname in one of the shapes the old cleanup handled."""
    if kind == "regular":
        path.write_bytes(b"hostile-residue")
        path.chmod(0o600)
    elif kind == "symlink":
        sibling.write_bytes(b"unrelated-target")
        path.symlink_to(sibling)
    elif kind == "hardlink":
        sibling.write_bytes(b"unrelated-target")
        os.link(sibling, path)
    else:
        os.mkfifo(path, 0o600)


def _snapshot(*roots: Path) -> list[tuple]:
    entries = []
    for top in roots:
        for path in sorted(top.rglob("*")):
            info = path.lstat()
            target = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
            data = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            entries.append(
                (str(path), stat.S_IFMT(info.st_mode), info.st_size, info.st_nlink,
                 info.st_ino, target, data)
            )
    return entries


def behaviour_failures(script: Path, shapes: tuple[str, ...] = SHAPES) -> list[str]:
    """Run `script` in every old mode, shell and environment under a sandbox.

    An empty list means it behaves as the tombstone must: exit 2, the pointer on
    stderr, nothing on stdout, no command run, and no file created, changed,
    followed or opened, whatever the arguments, the shell, the environment or
    the shape of the reserved passphrase pathname in the working directory and
    in HOME.
    """
    failures = []
    with tempfile.TemporaryDirectory(prefix="fde-canaries-") as canary_tmp:
        bin_dir = Path(canary_tmp)
        for name in CANARIES:
            canary = bin_dir / name
            canary.write_text(f'#!/bin/sh\necho "{name} $*" >> "${{FDE_MARK}}"\nexit 0\n', encoding="utf-8")
            canary.chmod(0o755)
        failures.extend(_sandboxed_failures(script, shapes, bin_dir))
    # An empty PATH proves it needs no external command at all.
    with tempfile.TemporaryDirectory(prefix="fde-tombstone-") as tmp:
        result = subprocess.run(
            [SHELLS[0], str(script), "--force"], cwd=tmp, env={"PATH": ""},
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 2 or "retired" not in result.stderr:
            failures.append(f"empty PATH: exit {result.returncode}, stderr {result.stderr[:80]!r}")
    # Sourcing it ends the sourcing shell with 2; nothing after it runs.
    sourced = subprocess.run(
        [SHELLS[0], "-c", 'source "$1"; echo STILL_RUNNING', "x", str(script)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if sourced.returncode != 2 or "STILL_RUNNING" in sourced.stdout:
        failures.append(f"sourced: exit {sourced.returncode}, stdout {sourced.stdout[:40]!r}")
    return failures


def _sandboxed_failures(script: Path, shapes: tuple[str, ...], bin_dir: Path) -> list[str]:
    failures = []
    for shell in SHELLS:
        for kind in shapes:
            for hostile in (False, True):
                for args in MODES:
                    with tempfile.TemporaryDirectory(prefix="fde-tombstone-") as tmp:
                        tmp = Path(tmp)
                        work, home = tmp / "cwd", tmp / "home"
                        work.mkdir()
                        home.mkdir()
                        mark = tmp / "mark.txt"
                        _make_shape(work / ".winn-fde-pass", kind, work / "must-survive")
                        _make_shape(home / ".winn-fde-pass", kind, home / "must-survive")
                        before = _snapshot(work, home)
                        env = {"PATH": str(bin_dir), "HOME": str(home), "LC_ALL": "C", "FDE_MARK": str(mark)}
                        if hostile:
                            env.update(HOSTILE_ENV)
                        label = f"{shell} {' '.join(args) or '(no args)'} shape={kind} env={'hostile' if hostile else 'clean'}"
                        try:
                            result = subprocess.run(
                                [shell, str(script), *args], cwd=work, env=env,
                                capture_output=True, text=True, timeout=10, check=False,
                            )
                        except subprocess.TimeoutExpired:
                            failures.append(f"{label}: did not return (it opened a file or waited)")
                            continue
                        if result.returncode != 2:
                            failures.append(f"{label}: exit status {result.returncode}, want 2")
                        if result.stdout != "":
                            failures.append(f"{label}: wrote to stdout: {result.stdout[:80]!r}")
                        if "retired" not in result.stderr or not all(
                            pointer in result.stderr for pointer in TOMBSTONE_POINTERS
                        ):
                            failures.append(f"{label}: stderr lacks the pointer: {result.stderr[:120]!r}")
                        if mark.exists():
                            failures.append(f"{label}: ran an external command: {mark.read_text().strip()[:80]!r}")
                        if _snapshot(work, home) != before:
                            failures.append(f"{label}: created, changed or removed a file")
    return failures


def tombstone_text() -> str:
    return IONOS.read_text(encoding="utf-8")


def test_tombstone_shape_is_exact() -> None:
    assert tombstone_problems(tombstone_text()) == []


def test_tombstone_is_a_pointer_and_nothing_else() -> None:
    text = tombstone_text()
    assert len(text.encode("utf-8")) < 2500
    for pointer in TOMBSTONE_POINTERS:
        assert (ROOT / pointer).is_file(), f"the pointer names a file that is not in the tree: {pointer}"
    code = "\n".join(
        line for line in text.split("\n") if line.strip() and not line.lstrip().startswith("#")
    )
    # None of the retired converter's machinery is left in the code, and above
    # all not the kernel ip= token or any second owner of the early-boot network.
    for forbidden in (
        "cryptsetup", "grub", "GRUB_CMDLINE", "ip=", "dropbear", "update-initramfs", "apt-get",
        "PASS_FILE", "shred", "findmnt", "ip -o", "e2fsck", "resize2fs", "crypttab", "fstab",
        "shutdown", "set -", "source ", "eval ", "$@", "$1", "mkdir", "cat >",
    ):
        assert forbidden not in code, forbidden


@pytest.mark.parametrize("shape", SHAPES)
def test_tombstone_never_touches_a_passphrase_file_of_any_shape(shape: str) -> None:
    # The retired cleanup removed a reserved passphrase pathname without ever
    # following a symlink or shredding a multi-link file or a fifo. The tombstone
    # keeps the strict form of that rule: it touches nothing at all.
    failures = behaviour_failures(IONOS, shapes=(shape,))
    assert failures == [], "\n".join(failures[:10])


def test_tombstone_is_not_the_old_converter() -> None:
    old_head = (
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        'PASS_FILE="/root/.winn-fde-pass"\n'
        'cryptsetup reencrypt --encrypt --batch-mode "${ROOT_DEV}"\n'
    )
    assert tombstone_problems(old_head) != [], "the checker would accept a converter as the tombstone"


def _replace(old: str, new: str):
    def mutate(text: str) -> str:
        assert old in text, old
        return text.replace(old, new, 1)

    return mutate


def _append_code(line: str):
    return lambda text: text.rstrip("\n").rsplit("exit 2", 1)[0] + line + "\nexit 2\n"


# name: (mutation, killed by "static" or "both" static shape check and behaviour run)
MUTANTS = {
    "exit 0": (_replace("\nexit 2\n", "\nexit 0\n"), "both"),
    "exit 1": (_replace("\nexit 2\n", "\nexit 1\n"), "both"),
    "no exit": (_replace("\nexit 2\n", "\n"), "both"),
    "return instead of exit": (_replace("\nexit 2\n", "\nreturn 2\n"), "static"),
    "code after the exit": (lambda text: text + "touch /tmp/after-exit\n", "static"),
    "message to stdout": (_replace(" >&2\nexit 2", "\nexit 2"), "both"),
    "no pointer": (lambda text: text.replace("deploy/make_ionos_user_data.sh", "the user data route"), "both"),
    "no marker": (_replace("# TOMBSTONE: the standalone", "# the standalone"), "static"),
    "no shebang": (lambda text: text.split("\n", 1)[1], "static"),
    "dash in the message": (_replace("This run did nothing", "This run did nothing \u2014 at all"), "static"),
    "set -e added": (_append_code("set -e"), "static"),
    "source added": (_append_code("source /etc/profile"), "static"),
    "function added": (_append_code("main() { :; }"), "static"),
    "kernel ip token restored": (_append_code('FDE_IP_CMDLINE="ip=dhcp"'), "static"),
    "conversion restored": (_append_code('cryptsetup reencrypt --encrypt /dev/vda1'), "both"),
    "passphrase shred restored": (_append_code("shred -u /root/.winn-fde-pass"), "both"),
    "passphrase removal restored": (_append_code("rm -f /root/.winn-fde-pass"), "both"),
    "fsck restored": (_append_code("e2fsck -fy /dev/vda1"), "both"),
    "reboot restored": (_append_code('shutdown -r +1 "LUKS FDE conversion complete"'), "both"),
    "argument read": (_append_code('[[ "${1:-}" == --force ]] && exit 0'), "both"),
    "message with expansion": (_replace("  'The IONOS hub is converted", '  "$(id) The IONOS hub is converted'), "static"),
    "message line with backslash": (_replace("by the user-data route:'", "by the user-data route:\\\\'"), "static"),
    "grown past the cap": (lambda text: text.replace("exit 2\n", "# pad\n" * 45 + "exit 2\n"), "static"),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_tombstone_mutants_are_killed(name: str, tmp_path: Path) -> None:
    mutate, killed_by = MUTANTS[name]
    mutated = mutate(tombstone_text())
    assert mutated != tombstone_text()
    assert tombstone_problems(mutated), f"{name}: the shape check accepted the mutant"
    if killed_by == "both":
        script = tmp_path / "mutant.sh"
        script.write_text(mutated, encoding="utf-8")
        assert behaviour_failures(script, shapes=("regular", "fifo")), (
            f"{name}: the behaviour run accepted the mutant"
        )


def test_control_the_unmutated_tombstone_passes_both_checks(tmp_path: Path) -> None:
    script = tmp_path / "control.sh"
    script.write_text(tombstone_text(), encoding="utf-8")
    assert tombstone_problems(script.read_text(encoding="utf-8")) == []
    assert behaviour_failures(script, shapes=("regular", "fifo")) == []


def test_docs_name_the_retired_script_as_residue_only() -> None:
    custody = CUSTODY.read_text(encoding="utf-8")
    assert "`ionos_fde_reinstall.sh` (retired" in custody
    audit = (ROOT / "docs" / "audit" / "DEEP_AUDIT_PROMPT.md").read_text(encoding="utf-8")
    assert "deploy/ionos_fde_reinstall.sh` is retired" in audit


def test_custody_contract_keeps_provider_and_guest_evidence_separate() -> None:
    text = CUSTODY.read_text(encoding="utf-8")
    words = " ".join(text.split())
    assert "Provider control plane" in text
    assert "Exactly one remaining slot does not identify its credential" in words
    assert "Never convert this to PASS from guest evidence" in text
    assert "physical block erasure" in text
