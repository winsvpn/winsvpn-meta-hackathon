#!/usr/bin/env python3
"""Installer must persist hub v3 env vars into the unit's EnvironmentFile.

Gap: the hub PYEOF reads WINN3_DESCRIPTOR_PUBKEY_G1 and WINN3_INNER_POOL_CIDR
via os.getenv, but write_env used to omit both, so a fresh deploy could not
serve standalone v3 without a manual edit of the wrong file.

This suite checks the live installer, then mutates a private copy (never the
shared tree). Run:

  python3 server/test_winn3_hub_env_write.py
"""

from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import base64
import re
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
SCRATCH = (
    Path(__file__).resolve().parents[3]
    / ".spark_lanes"
    / "scratch"
    / "deploy_write_pubkey_env"
)
MUTANTS = SCRATCH / "mutants"
# The lane fleet may execute this suite concurrently. A fixed driver.sh lets
# one process truncate another process's executable between write and exec,
# producing a false syntax failure on otherwise identical product bytes.
RUNS = SCRATCH / "runs" / str(os.getpid())

WRITER_BEGIN = "# --- begin winn3 hub EnvironmentFile writers ---"
WRITER_END = "# --- end winn3 hub EnvironmentFile writers ---"
STANDALONE_BEGIN = "# --- begin install-time standalone carrier=winn3"
STANDALONE_END = "# --- end install-time standalone carrier=winn3 ---"
FIXTURE_PUBKEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
FAKE_PEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"
CANARY_ENV = {
    "WINN3_CANARY_NODE_SLUG": "lab-alpha",
    "WINN3_CANARY_STATIC_PUBLIC": FIXTURE_PUBKEY_B64,
    "WINN3_CANARY_INNER_V4": "10.10.0.254",
    "WINN3_CANARY_BIN": "/usr/local/bin/winn3-probe",
    "WINN3_CANARY_KEY_DIR": "/etc/winn/canary",
    "WINN3_CANARY_GATEWAY_ENDPOINT": "203.0.113.10:9111",
    "WINN3_CANARY_GATEWAY_ID": "winsgw-canary-01",
}


def function_definition(source: str, signature: str) -> str:
    start = source.index(signature)
    brace_idx = source.index("{", start)
    depth = 0
    for idx in range(brace_idx, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
    raise AssertionError(f"unbalanced braces while extracting {signature}")


def extract_heredoc_after(source: str, anchor: str, marker: str) -> str:
    """Return the body of the first heredoc for `marker` after `anchor`.

    Accepts <<'MARKER', <<"MARKER", and unquoted <<MARKER. The hub unit uses
    unquoted <<EOF so ${ENV_FILE} expands; PYEOF is quoted.
    """
    idx = source.find(anchor)
    if idx < 0:
        raise AssertionError(f"missing anchor {anchor!r}")
    token_at = -1
    for token in (f"<<'{marker}'", f'<<"{marker}"', f"<<{marker}"):
        at = source.find(token, idx)
        if at >= 0 and at - idx <= 200:
            token_at = at
            break
    if token_at < 0:
        raise AssertionError(f"missing heredoc {marker} after {anchor!r}")
    nl = source.find("\n", token_at)
    body_start = nl + 1
    end = source.find(f"\n{marker}\n", body_start)
    if end < 0:
        raise AssertionError(f"unclosed heredoc {marker}")
    return source[body_start:end]


def writer_block(source: str) -> str:
    begin = source.find(WRITER_BEGIN)
    end = source.find(WRITER_END)
    if begin < 0 or end < 0 or end <= begin:
        raise AssertionError("writer begin/end markers missing or inverted")
    return source[begin:end]


def standalone_block(source: str) -> str:
    """Optional. Flag/slug/validate now live inside the writer markers.

    Including this block is harmless (provision is never called). Missing
    markers must not fail the pubkey/pool tests.
    """
    begin = source.find(STANDALONE_BEGIN)
    end = source.find(STANDALONE_END)
    if begin < 0 or end < 0 or end <= begin:
        return ""
    return source[begin:end]


def bash_check(script: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-n", str(script)],
        cwd=str(SCRATCH),
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )


def run_writers(source: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    RUNS.mkdir(parents=True, exist_ok=True)
    block = writer_block(source)
    standalone = standalone_block(source)
    kv_fn = function_definition(source, "write_env_kv() {")
    driver = RUNS / "driver.sh"
    driver.write_text(
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        'ENV_FILE="${TEST_ENV_FILE:-/root/vpn_auth.env}"\n'
        'WINN3_INNER_POOL_CIDR_DEFAULT="${WINN3_INNER_POOL_CIDR_DEFAULT:-10.10.0.0/24}"\n'
        'WINN3_SET_CARRIER_STANDALONE_DEFAULT="${WINN3_SET_CARRIER_STANDALONE_DEFAULT:-0}"\n'
        'WINN3_STANDALONE_NODE_SLUG_DEFAULT="${WINN3_STANDALONE_NODE_SLUG_DEFAULT:-}"\n'
        'WINN3_STANDALONE_PATH_MTU_DEFAULT="${WINN3_STANDALONE_PATH_MTU_DEFAULT:-1450}"\n'
        'WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT="${WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT:-udp}"\n'
        'err() { printf \'[ERR] %s\\n\' "$*" >&2; }\n'
        'warn() { printf \'[WARN] %s\\n\' "$*" >&2; }\n'
        "env_kv_buffer=\"\"\n"
        f"{kv_fn}\n"
        f"{block}\n"
        f"{standalone}\n"
        "write_winn3_runtime_env\n"
        'printf \'%s\' "${env_kv_buffer}"\n',
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(SCRATCH),
        "TEST_ENV_FILE": str(RUNS / "vpn_auth.env"),
        "WINN3_INNER_POOL_CIDR_DEFAULT": "10.10.0.0/24",
        "WINN3_SET_CARRIER_STANDALONE_DEFAULT": "0",
        "WINN3_STANDALONE_PATH_MTU_DEFAULT": "1450",
        "WINN3_STANDALONE_CARRIER_CLASSES_DEFAULT": "udp",
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(driver)],
        cwd=str(SCRATCH),
        capture_output=True,
        text=True,
        env=env,
    )


def ring_pin(source: str, slot: str) -> str:
    """The reviewed ring key the installer pins for a slot."""
    match = re.search(r"^    " + slot + r"\) printf '%s' '([A-Za-z0-9+/=]+)' ;;$", source, re.M)
    assert match is not None, slot
    return match.group(1)


def kv_lines(buf: str, key: str) -> list[str]:
    prefix = f"{key}="
    return [ln for ln in buf.splitlines() if ln.startswith(prefix)]


class HubEnvWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SCRATCH.mkdir(parents=True, exist_ok=True)
        MUTANTS.mkdir(parents=True, exist_ok=True)
        RUNS.mkdir(parents=True, exist_ok=True)
        cls.source = INSTALLER.read_text(encoding="utf-8")
        cls.write_env = function_definition(cls.source, "write_env() {")
        cls.writers = writer_block(cls.source)
        cls.load_existing = function_definition(cls.source, "load_existing_envs() {")

    def test_unit_environmentfile_is_env_file_not_legacy_dot_env(self) -> None:
        self.assertIn('ENV_FILE="/root/vpn_auth.env"', self.source)
        self.assertIn('LEGACY_ENV_FILE="${APP_DIR}/.env"', self.source)
        self.assertIn('SERVICE_FILE="/etc/systemd/system/wins-hub.service"', self.source)
        unit = extract_heredoc_after(
            self.source, 'cat > "${SERVICE_FILE}" <<EOF', "EOF"
        )
        self.assertIn("Description=Wins VPN Enterprise Hub", unit)
        self.assertIn("EnvironmentFile=${ENV_FILE}", unit)
        self.assertNotIn("EnvironmentFile=${LEGACY_ENV_FILE}", unit)
        self.assertNotIn("EnvironmentFile=/root/vpn_auth/.env", unit)
        self.assertNotIn("EnvironmentFile=/etc/winn/server.env", unit)

    def test_winn_server_env_does_not_receive_hub_winn3_keys(self) -> None:
        winn_env = extract_heredoc_after(
            self.source, "cat > /etc/winn/server.env <<EOF", "EOF"
        )
        self.assertNotIn("WINN3_DESCRIPTOR_PUBKEY_G1", winn_env)
        self.assertNotIn("WINN3_INNER_POOL_CIDR", winn_env)

    def test_load_existing_envs_parses_legacy_sources_env_file_env_file_wins(self) -> None:
        # H0 (D7): the app-writable legacy copy is parsed as data, never
        # sourced; the root-owned ${ENV_FILE} is still sourced whole, after it.
        self.assertIn('load_env_file_as_data "${LEGACY_ENV_FILE}"', self.load_existing)
        self.assertNotIn('source "${LEGACY_ENV_FILE}"', self.load_existing)
        self.assertIn('source "${ENV_FILE}"', self.load_existing)
        self.assertLess(
            self.load_existing.find('load_env_file_as_data "${LEGACY_ENV_FILE}"'),
            self.load_existing.find('source "${ENV_FILE}"'),
        )
        # Backslash-repair is a known-field list. A base64 pubkey must not
        # be rewritten by it; sourcing the whole file is what preserves G1.
        self.assertNotIn("WINN3_DESCRIPTOR_PUBKEY_G1", self.load_existing)
        self.assertNotIn("WINN3_INNER_POOL_CIDR", self.load_existing)

    def test_write_env_rebuilds_env_file_and_calls_writer_once(self) -> None:
        self.assertEqual(self.write_env.count("write_winn3_runtime_env"), 1)
        self.assertIn("write_winn3_runtime_env || return 1", self.write_env)
        self.assertIn('atomic_replace_file "${ENV_FILE}"', self.write_env)
        self.assertNotIn('>> "${ENV_FILE}"', self.write_env)
        self.assertIn('atomic_replace_file "${LEGACY_ENV_FILE}"', self.write_env)
        winn3_at = self.write_env.find("write_winn3_runtime_env || return 1")
        env_at = self.write_env.find('atomic_replace_file "${ENV_FILE}"')
        legacy_at = self.write_env.find('atomic_replace_file "${LEGACY_ENV_FILE}"')
        self.assertLess(winn3_at, env_at)
        self.assertLess(env_at, legacy_at)

    def test_writers_never_generate_or_write_a_private_key(self) -> None:
        lowered = self.writers.lower()
        for needle in (
            "genpkey",
            "genrsa",
            "ecparam",
            "begin private",
            "openssl rand",
        ):
            self.assertNotIn(needle, lowered)
        self.assertIn("PUBLIC key only", self.writers)
        self.assertIn("never generates", self.writers.lower())

    def test_hub_pyeof_reads_the_same_names_the_writer_emits(self) -> None:
        hub = extract_heredoc_after(
            self.source, 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF"
        )
        self.assertIn(
            'os.getenv(f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}")', hub
        )
        self.assertIn(
            'WINN3_INNER_POOL_CIDR = (os.getenv("WINN3_INNER_POOL_CIDR")', hub
        )

    def test_bash_n_on_live_installer(self) -> None:
        proc = bash_check(INSTALLER)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_ast_parse_writer_python_and_hub_pyeof(self) -> None:
        for marker in (
            "WINN3_POOL_CIDR_PY",
            "WINN3_PUBKEY_B64_PY",
            "WINN3_PUBKEY_FILE_PY",
            "WINN3_CANARY_ENV_PY",
        ):
            body = extract_heredoc_after(self.source, f"<<'{marker}'", marker)
            ast.parse(body, filename=marker)
        hub = extract_heredoc_after(
            self.source, 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'', "PYEOF"
        )
        ast.parse(hub, filename="main.py")

    def test_fresh_deploy_writes_default_pool_and_empty_g1_once(self) -> None:
        proc = run_writers(self.source)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        pool = kv_lines(proc.stdout, "WINN3_INNER_POOL_CIDR")
        g1 = kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1")
        self.assertEqual(pool, ["WINN3_INNER_POOL_CIDR='10.10.0.0/24'"])
        self.assertEqual(g1, ["WINN3_DESCRIPTOR_PUBKEY_G1=''"])
        # Design 3.19 item 3: the active slot (g2 by default) and the g3
        # standby are in the verify ring from the reviewed pins.
        self.assertEqual(kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G2"),
                         [f"WINN3_DESCRIPTOR_PUBKEY_G2='{ring_pin(self.source, 'g2')}'"])
        self.assertEqual(kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G3"),
                         [f"WINN3_DESCRIPTOR_PUBKEY_G3='{ring_pin(self.source, 'g3')}'"])
        self.assertEqual(len(pool), 1)
        self.assertEqual(len(g1), 1)
        self.assertIn("WINN3_DESCRIPTOR_PUBKEY_G1 is empty", proc.stderr)

    def test_supplied_pubkey_is_written_and_rerun_does_not_duplicate(self) -> None:
        env = {"WINN3_DESCRIPTOR_PUBKEY_G1": FIXTURE_PUBKEY_B64}
        first = run_writers(self.source, env)
        second = run_writers(self.source, env)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(
            kv_lines(first.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"),
            [f"WINN3_DESCRIPTOR_PUBKEY_G1='{FIXTURE_PUBKEY_B64}'"],
        )
        self.assertEqual(
            len(kv_lines(first.stdout, "WINN3_INNER_POOL_CIDR")), 1
        )
        self.assertEqual(
            len(kv_lines(first.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1")), 1
        )

    def test_a_supplied_active_slot_key_other_than_its_pin_is_refused(self) -> None:
        proc = run_writers(
            self.source,
            {
                "WINN3_DESCRIPTOR_PUBKEY_G1": FIXTURE_PUBKEY_B64,
                "WINN3_DESCRIPTOR_PUBKEY_G2": FIXTURE_PUBKEY_B64,
            },
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("active signer slot g2", proc.stderr)

    def test_the_pinned_active_key_is_accepted_once(self) -> None:
        pin = ring_pin(self.source, "g2")
        proc = run_writers(self.source, {"WINN3_DESCRIPTOR_PUBKEY_G2": pin})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G2"),
                         [f"WINN3_DESCRIPTOR_PUBKEY_G2='{pin}'"])

    def test_with_g3_active_the_ring_carries_g3_and_the_g2_standby(self) -> None:
        proc = run_writers(self.source, {"WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT": "g3"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for slot in ("g2", "g3"):
            name = f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}"
            self.assertEqual(kv_lines(proc.stdout, name), [f"{name}='{ring_pin(self.source, slot)}'"])
        # A supplied standby value is kept (planned rotation, design 3.10).
        kept = run_writers(self.source, {"WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT": "g3",
                                         "WINN3_DESCRIPTOR_PUBKEY_G2": FIXTURE_PUBKEY_B64})
        self.assertEqual(kept.returncode, 0, kept.stderr)
        self.assertEqual(kv_lines(kept.stdout, "WINN3_DESCRIPTOR_PUBKEY_G2"),
                         [f"WINN3_DESCRIPTOR_PUBKEY_G2='{FIXTURE_PUBKEY_B64}'"])

    def test_host_bits_are_canonicalized_to_network_address(self) -> None:
        proc = run_writers(
            self.source, {"WINN3_INNER_POOL_CIDR": "10.10.0.7/24"}
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_INNER_POOL_CIDR"),
            ["WINN3_INNER_POOL_CIDR='10.10.0.0/24'"],
        )
        self.assertIn("host bits set", proc.stderr)

    def test_non_slash24_pool_is_refused(self) -> None:
        proc = run_writers(
            self.source, {"WINN3_INNER_POOL_CIDR": "10.10.0.0/16"}
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("not a usable hub inner pool", proc.stderr)

    def test_private_key_pem_file_is_refused(self) -> None:
        pem = RUNS / "looks_private.pem"
        pem.write_text(FAKE_PEM, encoding="utf-8")
        proc = run_writers(
            self.source,
            {"WINN3_DESCRIPTOR_PUBKEY_G1_FILE": str(pem)},
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("private key", proc.stderr.lower())
        self.assertEqual(kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"), [])

    def test_dart_define_value_is_refused(self) -> None:
        proc = run_writers(
            self.source,
            {
                "WINN3_DESCRIPTOR_PUBKEY_G1": (
                    f"--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1={FIXTURE_PUBKEY_B64}"
                )
            },
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("dart-define", proc.stderr)
        self.assertEqual(kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"), [])

    def test_canary_absent_writes_no_canary_fields(self) -> None:
        proc = run_writers(self.source)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in CANARY_ENV:
            self.assertEqual(kv_lines(proc.stdout, name), [])

    def test_complete_canary_tuple_round_trips_once_and_idempotently(self) -> None:
        first = run_writers(self.source, CANARY_ENV)
        second = run_writers(self.source, CANARY_ENV)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)
        for name, value in CANARY_ENV.items():
            self.assertEqual(kv_lines(first.stdout, name), [f"{name}='{value}'"])

    def test_every_partial_canary_tuple_is_rejected_atomically(self) -> None:
        for missing in CANARY_ENV:
            with self.subTest(missing=missing):
                env = dict(CANARY_ENV)
                del env[missing]
                proc = run_writers(self.source, env)
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(proc.stdout, "")
                self.assertIn("configuration is partial", proc.stderr)

    def test_malformed_canary_values_are_rejected_atomically(self) -> None:
        mutations = {
            "WINN3_CANARY_NODE_SLUG": "Uppercase",
            "WINN3_CANARY_STATIC_PUBLIC": FIXTURE_PUBKEY_B64[:-2] + "AA",
            "WINN3_CANARY_INNER_V4": "10.10.1.254",
            "WINN3_CANARY_BIN": "relative/winn3-probe",
            "WINN3_CANARY_KEY_DIR": "/etc/winn/../canary",
            "WINN3_CANARY_GATEWAY_ENDPOINT": "gateway.example:9111",
            "WINN3_CANARY_GATEWAY_ID": " gateway-id",
        }
        for name, value in mutations.items():
            with self.subTest(name=name, value=value):
                env = dict(CANARY_ENV)
                env[name] = value
                proc = run_writers(self.source, env)
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(proc.stdout, "")
                self.assertIn("invalid Winn3 external canary", proc.stderr)

    def test_dropping_any_canary_write_is_detected(self) -> None:
        for name in CANARY_ENV:
            with self.subTest(name=name):
                needle = f'write_env_kv "${{name}}" "${{!name}}"'
                self.assertEqual(self.source.count(needle), 1)
                mutated = self.source.replace(
                    needle, 'true  # mutated: dropped canary write', 1
                )
                proc = run_writers(mutated, CANARY_ENV)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(kv_lines(proc.stdout, name), [])

    def test_comment_only_copy_still_passes_functional_write(self) -> None:
        mutant = MUTANTS / "control_neutral.sh"
        mutated = self.source.replace(
            WRITER_BEGIN, WRITER_BEGIN + "\n# control-neutral comment\n", 1
        )
        self.assertNotEqual(mutated, self.source)
        mutant.write_text(mutated, encoding="utf-8")
        proc = run_writers(mutated)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_INNER_POOL_CIDR"),
            ["WINN3_INNER_POOL_CIDR='10.10.0.0/24'"],
        )
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"),
            ["WINN3_DESCRIPTOR_PUBKEY_G1=''"],
        )

    def test_dropping_g1_write_is_caught(self) -> None:
        needle = 'write_env_kv WINN3_DESCRIPTOR_PUBKEY_G1 "${pubkey}"'
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(needle, 'true  # mutated: dropped G1 write', 1)
        mutant = MUTANTS / "drop_g1.sh"
        mutant.write_text(mutated, encoding="utf-8")
        proc = run_writers(mutated)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"), [])
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_INNER_POOL_CIDR"),
            ["WINN3_INNER_POOL_CIDR='10.10.0.0/24'"],
        )

    def test_dropping_pool_write_is_caught(self) -> None:
        needle = 'write_env_kv WINN3_INNER_POOL_CIDR "${pool}"'
        self.assertEqual(self.source.count(needle), 1)
        mutated = self.source.replace(
            needle, 'true  # mutated: dropped pool write', 1
        )
        mutant = MUTANTS / "drop_pool.sh"
        mutant.write_text(mutated, encoding="utf-8")
        proc = run_writers(mutated)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(kv_lines(proc.stdout, "WINN3_INNER_POOL_CIDR"), [])
        self.assertEqual(
            kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"),
            ["WINN3_DESCRIPTOR_PUBKEY_G1=''"],
        )

    def test_dropping_write_env_call_is_caught(self) -> None:
        needle = "write_winn3_runtime_env || return 1"
        self.assertEqual(self.write_env.count(needle), 1)
        mutated = self.source.replace(needle, "true  # mutated: skipped writer", 1)
        write_env = function_definition(mutated, "write_env() {")
        self.assertNotIn("write_winn3_runtime_env || return 1", write_env)

    def test_wrong_environmentfile_is_caught(self) -> None:
        needle = "EnvironmentFile=${ENV_FILE}"
        unit = extract_heredoc_after(
            self.source, 'cat > "${SERVICE_FILE}" <<EOF', "EOF"
        )
        self.assertEqual(unit.count(needle), 1)
        mutated = self.source.replace(
            needle, "EnvironmentFile=${LEGACY_ENV_FILE}", 1
        )
        unit2 = extract_heredoc_after(
            mutated, 'cat > "${SERVICE_FILE}" <<EOF', "EOF"
        )
        self.assertNotIn("EnvironmentFile=${ENV_FILE}", unit2)
        self.assertIn("EnvironmentFile=${LEGACY_ENV_FILE}", unit2)


def _classify_drop_g1() -> str:
    """Score the G1-drop mutant inverted: FAIL (empty G1 lines) is the catch."""
    source = INSTALLER.read_text(encoding="utf-8")
    needle = 'write_env_kv WINN3_DESCRIPTOR_PUBKEY_G1 "${pubkey}"'
    mutated = source.replace(needle, 'true  # mutated: dropped G1 write', 1)
    proc = run_writers(mutated)
    if proc.returncode != 0:
        return "BUILD_FAIL"
    if kv_lines(proc.stdout, "WINN3_DESCRIPTOR_PUBKEY_G1"):
        return "SURVIVED"
    return "CAUGHT"


if __name__ == "__main__":
    os.chdir(str(ROOT))
    unittest.main(verbosity=2)
