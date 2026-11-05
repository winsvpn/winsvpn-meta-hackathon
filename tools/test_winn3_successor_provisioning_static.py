#!/usr/bin/env python3
"""Static guards for the successor key rotation (Round GK3 OI-GK3-2).

tools/winn3_gateway_provision_keys.sh --generate-successor, --swap-successor,
--rollback-successor and --successor-status share one node-side script,
successor_remote_script. Its security properties live in shell text, so they
are checked here as text:

  * nothing private leaves the node: of the four secrets it generates, only
    admission.key (the symmetric secret the signed descriptor carries to every
    client) comes back; static.key, both dual-auth private keys and keygen's
    client.key never appear in anything it prints;
  * staging never writes a live file; the swap backs up before it renames;
    the rollback keeps the successor set before it restores; status and every
    --dry-run change nothing; nothing restarts the gateway;
  * the operator side writes only public files, admission.key and
    digest-only records.

Every checker is also run against deliberately broken copies, so a checker
that stopped matching anything turns this suite red instead of green.

Run:  python3 tools/test_winn3_successor_provisioning_static.py
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "winn3_gateway_provision_keys.sh"

END = 'echo "---END winn3 gk2 result---"'

# Every key a stdout line of the node script may start with.
RESULT_KEYS = {
    "action", "dry_run", "stamp", "unit", "live", "staged", "backup",
    "promoted", "kept", "restored", "rolledback", "runtime",
    "would_stage", "would_backup", "would_promote", "would_keep",
    "would_restore", "static.pub", "auth_ed25519.pub", "auth_mldsa65.pub",
    "admission.key", "admission.fp", "staged.admission.fp",
}
MARKERS = {'echo "---BEGIN winn3 gk2 result---"', END}
# The only files the node script may print, all in the stage branch. The
# first three are public; admission.key is the one symmetric secret.
ALLOWED_CAT = {
    '"${TMP}/static.pub"', '"${TMP}/auth_ed25519.pub"',
    '"${TMP}/auth_mldsa65.pub"', '"${TMP}/admission.key"',
}
# cat(1) with its argument; `systemctl cat UNIT` reads the unit, not a file.
CAT = r"(?<!systemctl )\bcat\b\s*(\"[^\"]*\"|\S*)"
# Commands allowed inside $(...) on a line that prints.
ALLOWED_SUBST = {"sha", "fp", "stat", "systemctl", "cat"}
EXFIL = re.compile(r"\b(scp|rsync|sftp|curl|wget|nc|ncat|socat|tee|ssh)\b")
DUMP = re.compile(
    r"\b(base64|xxd|od|hexdump|dd|head|tail|less|more|strings|openssl|"
    r"python3?|perl|awk|sed|cut\s+-c1-[0-9]+\s+\"\$)")
WRITE_VERB = re.compile(r"\b(install|cp|mv|ln|chmod|chown|truncate|mktemp)\b")
SYSTEMCTL_CHANGE = re.compile(
    r"systemctl\s+(restart|start|stop|reload|kill|enable|disable|"
    r"daemon-reload|try-restart|reload-or-restart|mask|reset-failed)\b")

ALLOWED_RM = {
    'rm -rf "${TMP}"',
    'for f in "${CREATED[@]+"${CREATED[@]}"}"; do rm -f "${f}"; done',
    'for f in "${BACKED[@]+"${BACKED[@]}"}"; do rm -f "${f}"; done',
}
ALLOWED_PRINTF = {
    "printf '%s\\n' \"${BEFORE}\"",
    "printf '%s\\n' \"${AFTER}\"",
}
STAGE_WRITES = [
    'TMP="$(mktemp -d -p /run winn3-gk2gen.XXXXXXXX)"',
    'install -m 600 -o root -g root "${TMP}/${GEN_NAMES[$i]}" "${LIVE[$i]}.gk2-new"',
]
SWAP_WRITES = [
    'cp -p "${LIVE[$i]}" "${LIVE[$i]}.pre-gk2-${STAMP}"',
    'mv -f "${LIVE[$i]}.gk2-new" "${LIVE[$i]}"',
]
ROLLBACK_WRITES = [
    'cp -p "${LIVE[$i]}" "${LIVE[$i]}.gk2-rolledback-${STAMP}"',
    'cp -p "${LIVE[$i]}.pre-gk2-${STAMP}" "${LIVE[$i]}.gk2-rb"',
    'mv -f "${LIVE[$i]}.gk2-rb" "${LIVE[$i]}"',
]
REQUIRED_LINES = [
    "umask 077",
    'grep -q -x -F -e "LoadCredential=${IDS[$i]}:${LIVE[$i]}" <<<"${UNIT_TEXT}" \\',
    '[ "$(findmnt -n -o FSTYPE /run)" = tmpfs ] || fail "/run is not tmpfs; refusing to generate key material onto a disk"',
    '"${BIN}" -mode keygen -out "${TMP}" >/dev/null',
    'fp() { { printf %s \'winn3-admission-fingerprint-v1\'; tr -d \'\\r\\n\' < "$1"; } | sha256sum | cut -c1-16; }',
    'sha() { sha256sum < "$1" | cut -d\' \' -f1; }',
    '[ "${NEW[$i]}" = "${EXPECT[$i]}" ] || fail "${LIVE[$i]}.gk2-new is not the file recorded in staging-record.txt"',
]
LOCAL_PUBLIC_LOOP = (
    "for name in static.pub:32:static_pub auth_ed25519.pub:32:auth_ed25519 "
    "auth_mldsa65.pub:1952:auth_mldsa65; do")
SWAP_EXPECT_READ = (
    "sha=\"$(awk -v f=\"${dest}.gk2-new\" '$1==\"staged\" && $2==f {print $3; exit}' "
    "\"${record}\")\"")
RECORD_FILTER = (
    "gk2_block | grep -E '^(action|dry_run|live|staged|admission\\.fp|"
    "staged\\.admission\\.fp) ' \\")


def function_body(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}\n", text, re.S | re.M)
    if not match:
        raise AssertionError(f"{name}() not found")
    return match.group(1)


def remote_script(text: str) -> str:
    # Not function_body(): the heredoc itself holds column-0 closing braces.
    match = re.search(r"^successor_remote_script\(\) \{\n  cat <<'REMOTE'\n(.*?)^REMOTE\n\}\n",
                      text, re.S | re.M)
    if not match:
        raise AssertionError("quoted REMOTE heredoc not found in successor_remote_script")
    return match.group(1)


def branch(remote: str, name: str) -> str:
    match = re.search(rf"^{name}\)\n(.*?)^  ;;\n", remote, re.S | re.M)
    return match.group(1) if match else ""


def code_lines(block: str) -> list[str]:
    out = []
    for line in block.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def without_fail_messages(line: str) -> str:
    return re.sub(r'fail "[^"]*"', 'fail ""', line)


def substitutions(line: str) -> list[str]:
    return re.findall(r"\$\(\s*([A-Za-z_][A-Za-z0-9_.-]*)", line)


def remote_violations(remote: str) -> list[str]:
    """What in the node-side script could leak a private byte or change state."""
    problems: list[str] = []
    lines = code_lines(remote)
    for req in REQUIRED_LINES:
        if req not in lines:
            problems.append(f"required line missing: {req}")

    stage = branch(remote, "stage")
    swap = branch(remote, "swap")
    rollback = branch(remote, "rollback")
    status = branch(remote, "status")
    for name, body in (("stage", stage), ("swap", swap), ("rollback", rollback), ("status", status)):
        if not body:
            problems.append(f"case branch {name}) not found")
    stage_lines = code_lines(stage)

    for line in lines:
        bare = without_fail_messages(line)
        if EXFIL.search(bare):
            problems.append(f"transfer tool in remote script: {line}")
        if DUMP.search(bare):
            problems.append(f"dump or re-encoding tool in remote script: {line}")
        if SYSTEMCTL_CHANGE.search(bare) or re.search(r"\b(pkill|kill)\b", bare):
            problems.append(f"remote script changes a unit or process: {line}")
        for arg in re.findall(CAT, bare):
            if arg not in ALLOWED_CAT:
                problems.append(f"cat of a file outside the allowlist: {line}")
        if re.search(r"\btr\b", bare) and not line.startswith("fp() {"):
            problems.append(f"tr outside the fingerprint function: {line}")
        if re.search(r"\bgrep\b", bare) and " -q" not in bare and not (
                " -c " in bare and '<<<"${UNIT_TEXT}"' in bare):
            problems.append(f"grep that prints what it matches: {line}")
        if re.search(r"\brm\b", bare) and line not in ALLOWED_RM:
            problems.append(f"rm outside the cleanup of this run's own files: {line}")
        if re.search(r"\bprintf\b", bare) and not line.startswith("fp() {") and line not in ALLOWED_PRINTF:
            problems.append(f"printf outside the allowlist: {line}")
        # Input redirections from files: only hashing and the fingerprint.
        for m in re.finditer(r"(?<![<0-9])<(?![<(])\s*(\"[^\"]*\"|\S+)", bare):
            if m.group(1) != '"$1"':
                problems.append(f"file read by redirection outside sha/fp: {line}")
        if re.match(r"echo ", bare) and ">&2" not in bare:
            if line in MARKERS:
                continue
            key = re.match(r'echo "([a-z0-9_.]+) ', line)
            if not key or key.group(1) not in RESULT_KEYS:
                problems.append(f"stdout line outside the key allowlist: {line}")
            for cmd in substitutions(line):
                if cmd not in ALLOWED_SUBST:
                    problems.append(f"stdout line runs {cmd}: {line}")

    # Every cat sits in the stage branch. Counted, not matched by text: a copy
    # of an allowed stage line placed in another branch must still be caught.
    cats_all = sum(1 for l in lines if re.search(CAT, l))
    cats_stage = sum(1 for l in stage_lines if re.search(CAT, l))
    if cats_all != cats_stage:
        problems.append(f"{cats_all - cats_stage} cat line(s) outside the stage branch")

    # Stage: generation into tmpfs, staged names only, never a live file.
    if "trap cleanup EXIT INT TERM" not in stage_lines:
        problems.append("stage has no EXIT trap for its tmpfs work directory")
    writes = [l for l in stage_lines if WRITE_VERB.search(without_fail_messages(l))]
    if writes != STAGE_WRITES:
        problems.append(f"stage write lines are {writes}")
    # Swap and rollback: exactly their renames, in a safe order.
    for name, body, expected in (("swap", swap, SWAP_WRITES), ("rollback", rollback, ROLLBACK_WRITES)):
        blines = code_lines(body)
        writes = [l for l in blines if WRITE_VERB.search(without_fail_messages(l))]
        if writes != expected:
            problems.append(f"{name} write lines are {writes}")
    if code_lines(status) and any(
            WRITE_VERB.search(l) or re.search(r"\brm\b", l) for l in code_lines(status)):
        problems.append("status branch writes")
    # Every --dry-run exits before the branch's first write.
    for name, body in (("stage", stage), ("swap", swap), ("rollback", rollback)):
        blines = code_lines(body)
        guard = next((i for i, l in enumerate(blines) if l == 'if [ "${DRY}" = 1 ]; then'), None)
        first_write = next((i for i, l in enumerate(blines)
                            if WRITE_VERB.search(without_fail_messages(l))), None)
        if guard is None:
            problems.append(f"{name} has no --dry-run guard")
            continue
        exit_at = next((i for i in range(guard, len(blines)) if blines[i] == "exit 0"), None)
        if exit_at is None or (first_write is not None and not guard < exit_at < first_write):
            problems.append(f"{name} --dry-run guard does not exit before the first write")
    return problems


def local_violations(text: str) -> list[str]:
    """What the operator side of the successor modes writes."""
    problems: list[str] = []
    gen = function_body(text, "do_generate_successor")
    written = set(re.findall(r'>\s*"\$\{OUT_DIR\}/([^"]+)"', gen))
    if written != {"${field}", "${name##*:}.b64", "admission.key", "staging-record.txt"}:
        problems.append(f"--generate-successor writes {sorted(written)}")
    if LOCAL_PUBLIC_LOOP not in gen:
        problems.append("the public-file loop is not exactly the three public keys")
    if RECORD_FILTER not in gen:
        problems.append("staging-record.txt is not filtered by the public-line allowlist")
    for name, record in (("do_swap_successor", "swap-record-${stamp}.txt"),
                         ("do_rollback_successor", "rollback-record-${stamp}.txt")):
        body = function_body(text, name)
        found = set(re.findall(r'>\s*"\$\{OUT_DIR\}/([^"]+)"', body))
        if found != {record}:
            problems.append(f"{name} writes {sorted(found)}")
    if re.search(r">\s*\"\$\{OUT_DIR\}", function_body(text, "do_successor_status")):
        problems.append("--successor-status writes a local file")
    run = function_body(text, "run_successor")
    if "successor_remote_script | node_ssh \"bash -s -- " not in run:
        problems.append("run_successor does not pipe the one audited script into bash -s")
    if "'${AUTH_ML_DEST}' ${SWAP_EXPECT[*]+${SWAP_EXPECT[*]}}\")" not in run:
        problems.append("run_successor does not pass the recorded digests to the node")
    swap_body = function_body(text, "do_swap_successor")
    if SWAP_EXPECT_READ not in swap_body:
        problems.append("--swap-successor does not read the staged digests from staging-record.txt")
    return problems


class SuccessorRemoteStatic(unittest.TestCase):
    def setUp(self) -> None:
        self.text = TOOL.read_text()
        self.remote = remote_script(self.text)

    def test_node_side_never_emits_private_material_or_changes_live_state(self) -> None:
        self.assertEqual(remote_violations(self.remote), [])

    def test_the_only_secret_printed_is_admission_key(self) -> None:
        printed = [l for l in code_lines(self.remote) if re.search(CAT, l)]
        self.assertEqual(
            sorted(re.search(CAT, l).group(1) for l in printed),
            sorted(ALLOWED_CAT))
        for name in ("static.key", "auth_ed25519.seed", "auth_mldsa65.seed", "client.key"):
            for line in code_lines(self.remote):
                if line.startswith("echo ") and name in line:
                    self.fail(f"{name} named on an output line: {line}")

    # Anti-vacuity: each mutant must be flagged.
    def test_checkers_flag_broken_remote_scripts(self) -> None:
        stage_end = '  echo "staged.admission.fp $(fp "${LIVE[1]}.gk2-new")"\n'
        self.assertIn(stage_end, self.remote)
        add = lambda extra: self.remote.replace(stage_end, stage_end + extra)
        mutants = {
            "static.key printed": add('  echo "static.key $(cat "${TMP}/static.key")"\n'),
            "staged seed printed": add('  echo "seed $(cat "${LIVE[2]}.gk2-new")"\n'),
            "live key base64": add('  base64 -w0 < "${LIVE[0]}"\n'),
            "scp of a live key": add('  scp "${LIVE[0]}" operator:\n'),
            "ml seed via printf": add('  printf \'%s\' "$(cat "${TMP}/auth_mldsa65.seed")"\n'),
            "client.key printed": add('  echo "client.key $(cat "${TMP}/client.key")"\n'),
            "tr of a live key": add('  tr -d \'\\n\' < "${LIVE[0]}"\n'),
            "grep prints a key": add('  grep -E . "${LIVE[0]}"\n'),
            "xxd in a result line": add('  echo "live $(xxd -p "${LIVE[1]}")"\n'),
            "keygen stdout kept": self.remote.replace(
                '"${BIN}" -mode keygen -out "${TMP}" >/dev/null', '"${BIN}" -mode keygen -out "${TMP}"'),
            "stage trap removed": self.remote.replace(
                "  trap cleanup EXIT INT TERM\n\n  # keygen", "\n  # keygen"),
            "stage writes a live file": self.remote.replace(
                '"${TMP}/${GEN_NAMES[$i]}" "${LIVE[$i]}.gk2-new"\n',
                '"${TMP}/${GEN_NAMES[$i]}" "${LIVE[$i]}"\n'),
            "not tmpfs": self.remote.replace(
                "mktemp -d -p /run winn3-gk2gen", "mktemp -d -p /var/tmp winn3-gk2gen"),
            "restart in swap": self.remote.replace(
                '    mv -f "${LIVE[$i]}.gk2-new" "${LIVE[$i]}"\n',
                '    mv -f "${LIVE[$i]}.gk2-new" "${LIVE[$i]}"\n    systemctl restart "${UNIT}"\n'),
            "unit mapping check removed": self.remote.replace(
                'grep -q -x -F -e "LoadCredential=${IDS[$i]}:${LIVE[$i]}" <<<"${UNIT_TEXT}" \\',
                'true \\'),
            "admission printed from swap": self.remote.replace(
                '  echo "stamp ${STAMP}"\n  for i in 0 1 2 3; do\n    echo "backup',
                '  echo "stamp ${STAMP}"\n  echo "admission.key $(cat "${TMP}/admission.key")"\n'
                '  for i in 0 1 2 3; do\n    echo "backup'),
            "status deletes": self.remote.replace(
                '    for f in "${LIVE[$i]}".pre-gk2-*; do echo "backup ${f} $(sha "${f}")"; done\n',
                '    for f in "${LIVE[$i]}".pre-gk2-*; do rm -f "${f}"; done\n'),
            "swap ignores the recorded digests": self.remote.replace(
                '    [ "${NEW[$i]}" = "${EXPECT[$i]}" ] || fail "${LIVE[$i]}.gk2-new is not the file recorded in staging-record.txt"\n',
                ""),
            "rollback keeps nothing": self.remote.replace(
                '    cp -p "${LIVE[$i]}" "${LIVE[$i]}.gk2-rolledback-${STAMP}"\n', ""),
        }
        swap = branch(self.remote, "swap")
        backup_loop = ('  for i in 0 1 2 3; do\n    cp -p "${LIVE[$i]}" "${LIVE[$i]}.pre-gk2-${STAMP}"\n')
        promote_loop = ('  for i in 0 1 2 3; do\n    PROMOTED=$((PROMOTED + 1))\n'
                        '    mv -f "${LIVE[$i]}.gk2-new" "${LIVE[$i]}"\n  done\n')
        self.assertIn(backup_loop, swap)
        self.assertIn(promote_loop, swap)
        reordered = swap.replace(promote_loop, "").replace(backup_loop, promote_loop + backup_loop)
        mutants["swap renames before it backs up"] = self.remote.replace(swap, reordered)
        dry = re.search(r'  if \[ "\$\{DRY\}" = 1 \]; then\n.*?\n    exit 0\n  fi\n', swap, re.S)
        self.assertIsNotNone(dry)
        mutants["swap without dry-run guard"] = self.remote.replace(swap, swap.replace(dry.group(0), ""))
        for label, broken in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(broken, self.remote, "mutant did not apply")
                self.assertNotEqual(remote_violations(broken), [], label)


class SuccessorLocalStatic(unittest.TestCase):
    def setUp(self) -> None:
        self.text = TOOL.read_text()

    def test_operator_side_writes_only_public_files_admission_and_records(self) -> None:
        self.assertEqual(local_violations(self.text), [])

    def test_modes_are_wired_and_dry_run_is_refused_elsewhere(self) -> None:
        for line in (
            "--generate-successor) MODE=generate-successor ;;",
            "--swap-successor)     MODE=swap-successor ;;",
            "--rollback-successor) MODE=rollback-successor ;;",
            "--successor-status)   MODE=successor-status ;;",
            "generate-successor) do_generate_successor ;;",
            "swap-successor)     do_swap_successor ;;",
            "rollback-successor) do_rollback_successor ;;",
            "successor-status)   do_successor_status ;;",
            "generate-successor|swap-successor|rollback-successor) ;;",
        ):
            self.assertIn(line, self.text)

    def test_checkers_flag_broken_operator_sides(self) -> None:
        mutants = {
            "static.key in the public loop": self.text.replace(
                LOCAL_PUBLIC_LOOP, LOCAL_PUBLIC_LOOP.replace(
                    "static.pub:32:static_pub", "static.key:32:static_key static.pub:32:static_pub")),
            "admission.key in the record": self.text.replace(
                RECORD_FILTER, RECORD_FILTER.replace("|admission\\.fp|", "|admission\\.key|admission\\.fp|")),
            "extra private file": self.text.replace(
                '  chmod 600 "${OUT_DIR}/admission.key"\n',
                '  chmod 600 "${OUT_DIR}/admission.key"\n  printf x > "${OUT_DIR}/static.key"\n'),
            "swap sends no digests": self.text.replace(
                "'${AUTH_ML_DEST}' ${SWAP_EXPECT[*]+${SWAP_EXPECT[*]}}\")", "'${AUTH_ML_DEST}'\")"),
            "swap does not read the record": self.text.replace(SWAP_EXPECT_READ, 'sha="${SWAP_SHA:-}"'),
            "status writes": self.text.replace(
                "  run_successor status || die \"Could not read the successor state on ${NODE}.\"\n  gk2_block\n",
                "  run_successor status || die \"Could not read the successor state on ${NODE}.\"\n"
                "  gk2_block > \"${OUT_DIR}/status.txt\"\n"),
        }
        for label, broken in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(broken, self.text, "mutant did not apply")
                self.assertNotEqual(local_violations(broken), [], label)


if __name__ == "__main__":
    unittest.main()
