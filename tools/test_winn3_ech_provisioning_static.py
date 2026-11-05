#!/usr/bin/env python3
"""Static guards for per-node ECH provisioning (Round GK OI-GK-3 step 1).

tools/winn3_gateway_provision_keys.sh --generate-ech rotates a node's ECH key
file ON the node. Its one security property is that no private byte of any
ECH key crosses the network: what comes back is digests, the public config
list and winn-ech-keygen -describe output. tools/winn3_fleet_ech_check.sh must
stay read-only. Both properties live in shell text, so they are checked here
as text, and every checker is also run against a deliberately broken copy so
that a checker that stopped matching anything turns this suite red instead of
green.

Run:  python3 tools/test_winn3_ech_provisioning_static.py
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "winn3_gateway_provision_keys.sh"
FLEET = ROOT / "tools" / "winn3_fleet_ech_check.sh"

BEGIN = 'echo "---BEGIN winn3 ech provisioning result---"'
END = 'echo "---END winn3 ech provisioning result---"'

# Every line the result block may emit, by its leading key.
RESULT_KEYS = {
    "backup", "installed.sha256", "backup.sha256",
    "ech_config_list.sha256", "ech_config_list.b64",
}
DESCRIBE_LINE = '"${BIN}" -describe "${ECH_DEST}"'
EXFIL_TOOLS = re.compile(r"\b(scp|rsync|sftp|curl|wget|nc|ncat|socat|tee)\b")
PRIVATE_PATHS = ('"${ECH_DEST}"', '"${BACKUP}"', '"${TMP}/ech-server-keys.json"')


def generate_ech_function(text: str) -> str:
    match = re.search(r"^do_generate_ech\(\) \{\n(.*?)^\}\n", text, re.S | re.M)
    if not match:
        raise AssertionError("do_generate_ech() not found")
    return match.group(1)


def remote_script(function: str) -> str:
    match = re.search(r"<<'REMOTE'\n(.*?)^REMOTE\n", function, re.S | re.M)
    if not match:
        raise AssertionError("quoted REMOTE heredoc not found in do_generate_ech")
    return match.group(1)


def remote_violations(remote: str) -> list[str]:
    """What in the node-side script could carry private key bytes back."""
    problems = []
    lines = [line.strip() for line in remote.splitlines()]
    if 'TMP="$(mktemp -d -p /run winn3-echgen.XXXXXXXX)"' not in lines:
        problems.append("work directory is not a mktemp under /run (tmpfs)")
    if "trap cleanup EXIT INT TERM" not in lines:
        problems.append("tmpfs work directory has no EXIT trap")
    if '"${BIN}" -add-to "${ECH_DEST}" -out "${TMP}" >/dev/null' not in lines:
        problems.append("keygen does not run with -add-to into tmpfs and stdout discarded")
    if 'LIST="${TMP}/ech-config-list.bin"' not in lines:
        problems.append("the public list is not read from the tmpfs work directory")
    for line in lines:
        if line.startswith("#") or not line:
            continue
        if EXFIL_TOOLS.search(line):
            problems.append(f"transfer tool in remote script: {line}")
        if re.search(r"(^|[|;&(]\s*)cat\b", line):
            problems.append(f"cat in remote script: {line}")
        if "base64" in line and '< "${LIST}"' not in line:
            problems.append(f"base64 of something other than the public list: {line}")
        if "ech-server-keys.json" in line and not line.startswith("install -m 400 -o root -g root"):
            problems.append(f"tmpfs key file used outside the install step: {line}")
    try:
        block = remote[remote.index(BEGIN) + len(BEGIN):remote.index(END)]
    except ValueError:
        return problems + ["result block markers missing"]
    for line in (l.strip() for l in block.splitlines()):
        if not line:
            continue
        if line == DESCRIBE_LINE:
            continue
        key = re.match(r'echo "([a-z0-9_.]+) ', line)
        if not key or key.group(1) not in RESULT_KEYS:
            problems.append(f"result block line outside the allowlist: {line}")
            continue
        for path in PRIVATE_PATHS:
            if path in line and "sha256sum <" not in line and key.group(1) != "backup":
                problems.append(f"result line reads a private file: {line}")
    return problems


def local_violations(function: str) -> list[str]:
    """What the operator side of --generate-ech writes."""
    problems = []
    written = set(re.findall(r'>\s*"\$\{OUT_DIR\}/([^"]+)"', function))
    if written != {"ech-config-list.bin", "ech-public-digests.txt"}:
        problems.append(f"local side writes {sorted(written)}")
    if "grep -v '^ech_config_list.b64 '" not in function:
        problems.append("digests file is not filtered to exclude the b64 line")
    return problems


def fleet_remote(text: str) -> str:
    match = re.search(r"^REMOTE='(.*?)'\n", text, re.S | re.M)
    if not match:
        raise AssertionError("REMOTE='...' not found in fleet check")
    return match.group(1)


def fleet_violations(remote: str) -> list[str]:
    problems = []
    forbidden = re.compile(
        r"\b(install|mv|cp|rm|chmod|chown|systemctl|kill|pkill|tee|base64|cat|dd|truncate|sed\s+-i)\b")
    for line in remote.splitlines():
        if forbidden.search(line):
            problems.append(f"write or read-out verb in fleet remote: {line}")
        if re.search(r"(?<![<2])>(?!&)", line.replace("2>/dev/null", "")):
            problems.append(f"redirection that writes in fleet remote: {line}")
        for flag in re.findall(r'"\$bin" (-[a-z-]+)', line):
            if flag != "-describe":
                problems.append(f"keygen run with {flag} in fleet remote")
    if '"$bin" -describe "$f"' not in remote:
        problems.append("fleet remote does not use -describe")
    return problems


class GenerateEchStatic(unittest.TestCase):
    def setUp(self) -> None:
        self.text = TOOL.read_text()
        self.function = generate_ech_function(self.text)
        self.remote = remote_script(self.function)

    def test_node_side_never_emits_private_key_material(self) -> None:
        self.assertEqual(remote_violations(self.remote), [])

    def test_operator_side_writes_only_public_files(self) -> None:
        self.assertEqual(local_violations(self.function), [])

    def test_the_mode_is_wired_and_never_restarts_the_gateway(self) -> None:
        self.assertIn("--generate-ech) MODE=generate-ech ;;", self.text)
        self.assertIn("generate-ech) do_generate_ech ;;", self.text)
        self.assertNotRegex(self.remote, r"systemctl\s+(restart|start|reload|stop)")

    def test_no_transfer_tool_anywhere_in_the_provisioning_tool(self) -> None:
        code = [l for l in self.text.splitlines() if not l.lstrip().startswith("#")]
        hits = [l for l in code if re.search(r"\b(scp|rsync|sftp)\b", l)]
        self.assertEqual(hits, [])

    def test_the_existing_generate_block_still_withholds_static_key(self) -> None:
        # Mirror of the rule the --generate block states in its own comment.
        match = re.search(
            r'echo "---BEGIN winn3 provisioning result---"\n(.*?)echo "---END winn3 provisioning result---"',
            self.text, re.S)
        self.assertIsNotNone(match)
        block = match.group(1)
        self.assertNotIn('cat "${TMP}/static.key"', block)
        self.assertNotIn('cat "${STATIC_DEST}"', block)

    # Anti-vacuity: each checker must flag a broken copy.
    def test_checkers_flag_a_leaking_remote_script(self) -> None:
        leaks = [
            self.remote.replace(END, 'echo "leak $(cat "${ECH_DEST}")"\n' + END),
            self.remote.replace(END, 'echo "ech_config_list.b64 $(base64 -w0 < "${ECH_DEST}")"\n' + END),
            self.remote.replace(END, 'scp "${ECH_DEST}" operator:\n' + END),
            self.remote.replace(END, 'echo "backup.sha256 $(cat "${BACKUP}")"\n' + END),
            self.remote.replace('-out "${TMP}" >/dev/null', '-out "${TMP}"'),
            self.remote.replace("trap cleanup EXIT INT TERM", ""),
            self.remote.replace('LIST="${TMP}/ech-config-list.bin"', 'LIST="${ECH_DEST}"'),
        ]
        for leaked in leaks:
            self.assertNotEqual(remote_violations(leaked), [], leaked[-300:])

    def test_checker_flags_a_private_file_written_locally(self) -> None:
        broken = self.function.replace(
            'chmod 644 "${OUT_DIR}/ech-config-list.bin"',
            'chmod 644 "${OUT_DIR}/ech-config-list.bin"\n  printf x > "${OUT_DIR}/ech-server-keys.json"')
        self.assertNotEqual(broken, self.function)
        self.assertNotEqual(local_violations(broken), [])


class FleetCheckStatic(unittest.TestCase):
    def setUp(self) -> None:
        self.text = FLEET.read_text()
        self.remote = fleet_remote(self.text)

    def test_fleet_remote_is_read_only(self) -> None:
        self.assertEqual(fleet_violations(self.remote), [])

    def test_fleet_output_names_aliases_not_addresses(self) -> None:
        self.assertNotRegex(self.text, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertIn('"${node}"', self.text)

    def test_checker_flags_a_writing_fleet_remote(self) -> None:
        for broken in (
            self.remote + '\nrm -f "$f"',
            self.remote + '\necho x > "$f"',
            self.remote + '\ncat "$f"',
            self.remote.replace('"$bin" -describe "$f"', '"$bin" -add-to "$f" -out /run'),
        ):
            self.assertNotEqual(fleet_violations(broken), [], broken)


if __name__ == "__main__":
    unittest.main()
