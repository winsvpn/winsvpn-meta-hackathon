#!/usr/bin/env python3
"""Durable replay is a non-bypassable Winn v3 gateway installer invariant.

WINN3_GATEWAY_REPLAY_JOURNAL=0 used to emit a journal-off unit. A restarted
gateway then re-answered a captured initiation. This file pins the refusal.

Run: python3 server/test_winn3_gateway_replay_journal.py
"""

from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import os
import pwd
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from winn3_gateway_test_support import gateway_source


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = Path(
    os.environ.get(
        "WINN3_GATEWAY_INSTALLER",
        str(ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"),
    )
)
INSTALLER = gateway_source(INSTALLER, legacy=False)

REFUSE = (
    "WINN3_GATEWAY_REPLAY_JOURNAL=0 is refused: durable replay is a "
    "non-bypassable production invariant"
)
CANONICAL = "WINN3_REPLAY_JOURNAL=/var/lib/winn3-gateway/replay.journal"
# WINN3_GATEWAY_PATH_MTU has no default by design (the installer refuses to
# guess it), and emit_env_text validates it before the journal. Pin a valid
# value so these cases reach the journal invariant whatever the caller's
# environment holds; 1450 is what the other fixtures in this file use.
FIXTURE_PATH_MTU = "1450"
FIXTURE_MEMINFO = str(ROOT / "server/testdata/winn3_gateway_meminfo/large")


def _source(script: Path, body: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["WINN3_GATEWAY_MEMINFO"] = FIXTURE_MEMINFO
    env["WINN3_GATEWAY_PATH_MTU"] = FIXTURE_PATH_MTU
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [
            "bash",
            "-c",
            'set -euo pipefail; source "$1"; ' + body,
            "_",
            str(script),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


class GatewayReplayJournalInvariantTests(unittest.TestCase):
    def test_installer_names_the_disable_refusal(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(REFUSE, text)

    def test_explicit_disable_is_refused_by_emit_env_text(self) -> None:
        proc = _source(
            INSTALLER,
            "WINN3_GATEWAY_REPLAY_JOURNAL=0; emit_env_text",
            extra_env={"WINN3_GATEWAY_REPLAY_JOURNAL": "0"},
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(REFUSE, proc.stderr)
        self.assertNotIn(CANONICAL, proc.stdout)

    def test_explicit_disable_is_refused_by_emit_unit_text(self) -> None:
        proc = _source(
            INSTALLER,
            "WINN3_GATEWAY_REPLAY_JOURNAL=0; emit_unit_text",
            extra_env={"WINN3_GATEWAY_REPLAY_JOURNAL": "0"},
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(REFUSE, proc.stderr)
        self.assertNotIn("StateDirectory=winn3-gateway", proc.stdout)

    def test_explicit_disable_is_refused_by_resolve(self) -> None:
        proc = _source(
            INSTALLER,
            "WINN3_GATEWAY_REPLAY_JOURNAL=0; resolve_replay_journal_env",
            extra_env={"WINN3_GATEWAY_REPLAY_JOURNAL": "0"},
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(REFUSE, proc.stderr)

    def test_flag_on_emits_canonical_journal_and_state_directory(self) -> None:
        env_proc = _source(
            INSTALLER,
            "WINN3_GATEWAY_REPLAY_JOURNAL=1; emit_env_text",
            extra_env={"WINN3_GATEWAY_REPLAY_JOURNAL": "1"},
        )
        self.assertEqual(env_proc.returncode, 0, env_proc.stderr)
        self.assertIn(CANONICAL, env_proc.stdout)

        unit_proc = _source(
            INSTALLER,
            "WINN3_GATEWAY_REPLAY_JOURNAL=1; emit_unit_text",
            extra_env={"WINN3_GATEWAY_REPLAY_JOURNAL": "1"},
        )
        self.assertEqual(unit_proc.returncode, 0, unit_proc.stderr)
        self.assertIn("StateDirectory=winn3-gateway", unit_proc.stdout)
        self.assertIn("StateDirectoryMode=0700", unit_proc.stdout)

    def test_unset_flag_still_emits_the_journal(self) -> None:
        env = os.environ.copy()
        env["WINN3_GATEWAY_MEMINFO"] = FIXTURE_MEMINFO
        env.pop("WINN3_GATEWAY_REPLAY_JOURNAL", None)
        env["WINN3_GATEWAY_PATH_MTU"] = FIXTURE_PATH_MTU
        proc = subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"; '
                'WINN3_GATEWAY_REPLAY_JOURNAL=""; emit_env_text',
                "_",
                str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(CANONICAL, proc.stdout)

    def test_provision_refuses_explicit_disable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _source(
                INSTALLER,
                "WINN3_GATEWAY_REPLAY_JOURNAL=0; provision_replay_journal",
                extra_env={
                    "WINN3_GATEWAY_REPLAY_JOURNAL": "0",
                    "WINN3_GATEWAY_REPLAY_JOURNAL_DIR": tmp,
                    "WINN3_GATEWAY_REPLAY_JOURNAL_PATH": str(Path(tmp) / "replay.journal"),
                },
            )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(REFUSE, proc.stderr)

    def test_installer_names_service_user_ownership_preservation(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("replay_journal_dir_held_by_service_user() {", text)
        self.assertIn(
            'install -d -m 700 -o root -g root "${WINN3_GATEWAY_REPLAY_JOURNAL_DIR}"',
            text,
        )
        self.assertIn(
            "Reinstall preserves that service-user ownership",
            text,
        )

    def test_reinstall_preserves_service_user_verify_and_append(self) -> None:
        """Upgrade simulation: systemd already chowned StateDirectory to the
        service user. Re-running provision_replay_journal must keep that owner
        so the unprivileged process can still verify, append, and create WAL.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.write_bytes(b"LIVE")
            os.chmod(state, 0o700)
            os.chmod(journal, 0o640)

            svc_name, svc_uid, _svc_gid = _bind_service_user(state, journal)

            proc = _source(
                INSTALLER,
                """
                WINN3_GATEWAY_REPLAY_JOURNAL=1
                provision_replay_journal
                if replay_journal_dir_held_by_service_user "${WINN3_GATEWAY_REPLAY_JOURNAL_DIR}"; then
                  printf 'held=1\\n'
                else
                  printf 'held=0\\n'
                fi
                """,
                extra_env={
                    "WINN3_GATEWAY_REPLAY_JOURNAL": "1",
                    "WINN3_GATEWAY_REPLAY_JOURNAL_DIR": str(state),
                    "WINN3_GATEWAY_REPLAY_JOURNAL_PATH": str(journal),
                    "WINN3_GATEWAY_SERVICE_USER": svc_name,
                },
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("held=1", proc.stdout)

            st = state.stat()
            self.assertEqual(st.st_uid, svc_uid)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
            self.assertEqual(journal.read_bytes(), b"LIVE")

            wal = Path(str(journal) + ".wal")
            proof = _as_service_user(
                svc_name,
                str(journal),
                str(wal),
            )
            self.assertEqual(proof.returncode, 0, proof.stdout + proof.stderr)
            self.assertEqual(journal.read_bytes(), b"LIVEX")
            self.assertTrue(wal.is_dir())
            self.assertEqual((wal / "probe").read_bytes(), b"ok")


def _bind_service_user(state: Path, journal: Path) -> tuple[str, int, int]:
    """Hand the live StateDirectory to an unprivileged account.

    Running this test as root would hide the defect: install -d -o root
    would keep root ownership. When we are root, chown to nobody (or another
    non-root account) so preservation is actually tested.
    """
    me = pwd.getpwuid(os.getuid())
    if me.pw_uid != 0:
        return me.pw_name, me.pw_uid, me.pw_gid
    for name in ("nobody", "daemon", "www-data"):
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        if pw.pw_uid == 0:
            continue
        os.chown(state, pw.pw_uid, pw.pw_gid)
        os.chown(journal, pw.pw_uid, pw.pw_gid)
        os.chmod(state, 0o700)
        os.chmod(journal, 0o640)
        # The service user must be able to TRAVERSE the state directory's
        # parent. Production's parent is /var/lib (0755, world-traversable);
        # this test's parent is a 0700 mkdtemp owned by root, which nobody
        # cannot cross -- the WAL probe would fail for a reason that has
        # nothing to do with the installer (found running as root on the
        # 2026-08-28 GCP host). 0711 = traverse without listing: the temp
        # contents stay unenumerable to other local users.
        parent = state.parent
        if parent != state and parent.exists():
            os.chmod(parent, 0o711)
        return pw.pw_name, pw.pw_uid, pw.pw_gid
    raise RuntimeError("root host has no unprivileged account to simulate the service user")


def _as_service_user(
    name: str, journal: str, wal: str
) -> subprocess.CompletedProcess[str]:
    """Prove the service user can still traverse, append, and mkdir WAL."""
    script = (
        "set -euo pipefail\n"
        f"journal={shlex.quote(journal)}\n"
        f"wal={shlex.quote(wal)}\n"
        'test -x "$(dirname "$journal")"\n'
        'test -w "$(dirname "$journal")"\n'
        'test -w "$journal"\n'
        "printf 'X' >> \"$journal\"\n"
        'mkdir -m 700 "$wal"\n'
        'printf \'ok\' > "$wal/probe"\n'
    )
    pw = pwd.getpwnam(name)
    if pw.pw_uid == os.getuid():
        return subprocess.run(
            ["bash", "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )
    wrappers = []
    runuser = next(
        (p for p in ("/usr/sbin/runuser", "/usr/bin/runuser") if os.path.exists(p)),
        None,
    )
    if runuser is not None:
        wrappers.append([runuser, "-u", name, "--", "bash", "-c", script])
    wrappers.append(["su", "-s", "/bin/bash", name, "-c", script])
    last: subprocess.CompletedProcess[str] | None = None
    for cmd in wrappers:
        last = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if last.returncode == 0:
            return last
    assert last is not None
    return last


FIREWALL_HEREDOC_START = "cat <<'EOF' # the boot helper: /usr/local/sbin/winn3-gateway-firewall\n"
FIREWALL_HEREDOC_END = "\nEOF\n"
GATEWAY_ID_GRAMMAR_REFUSAL = (
    "WINN3_GATEWAY_ID must be 1..128 characters of [A-Za-z0-9._:-] only."
)


def _extract_generated_firewall_script() -> str:
    """The exact body of /usr/local/sbin/winn3-gateway-firewall as emitted.

    The heredoc is quoted (<<'EOF'), so the body is literal: what this
    returns is byte-for-byte what a fleet node executes as root.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    start = text.index(FIREWALL_HEREDOC_START) + len(FIREWALL_HEREDOC_START)
    end = text.index(FIREWALL_HEREDOC_END, start)
    return text[start:end]


class GatewayIdInjectionGuardTests(unittest.TestCase):
    """A-DEP-001: WINN3_GATEWAY_ID reaches a file a root service sources."""

    def test_validate_config_refuses_an_injectable_gateway_id(self) -> None:
        proc = _source(
            INSTALLER,
            "validate_config",
            extra_env={"WINN3_GATEWAY_ID": 'winsgw01$(touch /tmp/pwned)'},
        )
        self.assertIn(GATEWAY_ID_GRAMMAR_REFUSAL, proc.stderr,
                      proc.stdout + proc.stderr)

    def test_validate_config_accepts_the_deployed_id_grammar(self) -> None:
        """Colon/dot/hyphen ids (the GCP deployment-inputs shape) pass."""
        proc = _source(
            INSTALLER,
            "validate_config",
            extra_env={"WINN3_GATEWAY_ID": "winn3-proof-gateway.us-east1:01"},
        )
        self.assertNotIn(GATEWAY_ID_GRAMMAR_REFUSAL, proc.stderr,
                         proc.stdout + proc.stderr)

    def test_generated_firewall_refuses_to_source_injected_env_lines(self) -> None:
        """The read-side guard: a tampered env file must not execute as root.

        The env file below carries a command substitution in WINN3_GATEWAY_ID.
        Without the closed-grammar scan, `source` would execute it. The test
        fails if the marker file appears or if the script exits 0.
        """
        firewall = _extract_generated_firewall_script()
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pwned"
            env_file = Path(tmp) / "winn3-gateway.env"
            env_file.write_text(
                "WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n"
                f"WINN3_GATEWAY_ID=winsgw01$(touch {marker})\n"
                "WINN3_GATEWAY_PATH_MTU=1450\n",
                encoding="utf-8",
            )
            os.chmod(env_file, 0o600)
            proc = self._run_generated_firewall(firewall, tmp, env_file)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("closed value grammar", proc.stderr)
            self.assertFalse(marker.exists(),
                              "command substitution executed during source")

    def test_generated_firewall_refuses_injected_variable_names(self) -> None:
        """F-01: a value-grammar-clean but hostile NAME must be refused.

        The F-01 probe smuggled PATH=/attacker-bin into the env file via a
        newline in WINN3_GATEWAY_FORWARD_IF (validated only when forwarding is
        ON, emitted always). The injected line fits the closed VALUE grammar
        perfectly -- / is a legal value character -- so a value-only scan
        sources it and root runs the attacker's iptables stub. The name
        allowlist is what refuses it.
        """
        firewall = _extract_generated_firewall_script()
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "winn3-gateway.env"
            env_file.write_text(
                "WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n"
                "WINN3_GATEWAY_FORWARD_IF=winn3gw0\n"
                "PATH=/tmp/attacker-bin\n"
                "LD_PRELOAD=/tmp/evil.so\n",
                encoding="utf-8",
            )
            os.chmod(env_file, 0o600)
            proc = self._run_generated_firewall(firewall, tmp, env_file)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("not one of the gateway env keys", proc.stderr)
            self.assertIn("'PATH'", proc.stderr)
            iptables_log = Path(tmp) / "iptables.log"
            self.assertFalse(
                iptables_log.exists(),
                "the script reached iptables with a hijacked PATH")

    def test_generated_firewall_refuses_duplicate_assignments(self) -> None:
        """F-01: an injected WINN3_* line cannot shadow the real assignment."""
        firewall = _extract_generated_firewall_script()
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "winn3-gateway.env"
            env_file.write_text(
                "WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n"
                "WINN3_GATEWAY_ID=real-gateway-id\n"
                "WINN3_GATEWAY_ID=attacker-id\n",
                encoding="utf-8",
            )
            os.chmod(env_file, 0o600)
            proc = self._run_generated_firewall(firewall, tmp, env_file)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("duplicate assignment", proc.stderr)
            self.assertIn("WINN3_GATEWAY_ID", proc.stderr)

    def test_validate_config_refuses_a_newline_in_forward_if(self) -> None:
        """F-01 write side: emitted values are single-line even when unused.

        WINN3_GATEWAY_FORWARD_IF is semantically validated only when
        WINN3_GATEWAY_FORWARD=1, but it is emitted into the root-sourced env
        file unconditionally. With forwarding off, a newline used to pass
        validation and land as two lines. The unconditional transport-shape
        gate in validate_config must refuse it whatever the toggle says.
        """
        injected = "winn3gw0\nPATH=/tmp/attacker-bin"
        env = os.environ.copy()
        env.update({
            "WINN3_GATEWAY_ID": "gw01",
            "WINN3_GATEWAY_PATH_MTU": "1450",
            "WINN3_GATEWAY_INNER_V4": "10.10.0.1",
            "WINN3_GATEWAY_MAX_SESSIONS": "200",
            "WINN3_GATEWAY_FORWARD": "0",
            "WINN3_GATEWAY_FORWARD_IF": injected,
        })
        proc = subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"; '
                'if validate_config; then printf "ACCEPTED\\n"; else printf "REFUSED\\n"; fi',
                "_",
                str(INSTALLER),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertIn("REFUSED", proc.stdout, proc.stdout + proc.stderr)
        self.assertIn(
            "WINN3_GATEWAY_FORWARD_IF must be a single line", proc.stderr)

    def test_generated_firewall_refuses_hostile_dual_auth_values(self) -> None:
        """A-DEP-001 completeness (Daybreak Blue): every field the scanner
        admits, including the dual-auth key paths, is value-grammar-checked.

        The dual-auth paths are written into the same root-sourced env file,
        so a metacharacter in one is the same injection as a metacharacter in
        the gateway id -- the value grammar must refuse both identically.
        """
        firewall = _extract_generated_firewall_script()
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "winn3-gateway.env"
            env_file.write_text(
                "WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n"
                "WINN3_GATEWAY_DUAL_AUTH_ED_KEY=/etc/winn/ed25519.key; touch /tmp/pwned\n"
                "WINN3_GATEWAY_DUAL_AUTH_ML_SEED=$(rm -rf /)\n",
                encoding="utf-8",
            )
            os.chmod(env_file, 0o600)
            proc = self._run_generated_firewall(firewall, tmp, env_file)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("closed value grammar", proc.stderr)

    def test_generated_firewall_sources_a_clean_env_file(self) -> None:
        """Control: the scan passes exactly what emit_env_text writes.

        Proves the previous test refused the INJECTION, not sourcing itself:
        with a clean file the script gets past source and reaches iptables.
        """
        firewall = _extract_generated_firewall_script()
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "winn3-gateway.env"
            env_file.write_text(
                "# Winn Protocol v3 gateway -- written by installer\n"
                "WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n"
                "WINN3_GATEWAY_ID=winn3-proof-gateway.us-east1:01\n"
                "WINN3_GATEWAY_PATH_MTU=1450\n"
                "WINN3_GATEWAY_INNER_V4=10.10.0.1\n"
                "WINN3_GATEWAY_PLAN=udp,tls\n"
                "WINN3_GATEWAY_MAX_SESSIONS=200\n"
                "GOMEMLIMIT=1717986918\n"
                "WINN3_GATEWAY_FORWARD=0\n"
                "WINN3_GATEWAY_FORWARD_IF=winn3gw0\n"
                "WINN3_GATEWAY_FORWARD_CIDR=10.64.0.1/24\n"
                "WINN3_GATEWAY_RESOLVER=0\n"
                "WINN3_GATEWAY_RESOLVER_UPSTREAM=\n"
                "WINN3_GATEWAY_RESOLVER_TIMEOUT=5s\n"
                "WINN3_GATEWAY_DUAL_AUTH_ED_KEY=\n"
                "WINN3_GATEWAY_DUAL_AUTH_ML_SEED=\n"
                "WINN3_REPLAY_JOURNAL=/var/lib/winn3-gateway/replay.journal\n",
                encoding="utf-8",
            )
            os.chmod(env_file, 0o600)
            proc = self._run_generated_firewall(firewall, tmp, env_file)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            iptables_log = Path(tmp) / "iptables.log"
            self.assertIn("--dport 9111", iptables_log.read_text(encoding="utf-8"),
                          "the script never reached the iptables stage; "
                          "the scan refused a clean env file")

    @staticmethod
    def _run_generated_firewall(
        firewall: str, tmp: str, env_file: Path
    ) -> subprocess.CompletedProcess[str]:
        """Run the extracted firewall body with stubbed stat/iptables.

        The real script checks `stat -c '%u:%a' == 0:600`; the stub answers
        that check for a file we own, so the test exercises everything AFTER
        it -- the closed-grammar scan and the source -- on any host.
        """
        stub_bin = Path(tmp) / "bin"
        stub_bin.mkdir(exist_ok=True)
        (stub_bin / "stat").write_text(
            "#!/usr/bin/env bash\nprintf '0:600\\n'\n", encoding="utf-8")
        os.chmod(stub_bin / "stat", 0o755)
        (stub_bin / "iptables").write_text(
            '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> '
            f"{shlex.quote(str(Path(tmp) / 'iptables.log'))}\nexit 0\n",
            encoding="utf-8")
        os.chmod(stub_bin / "iptables", 0o755)
        # The script holds the shared firewall lock for its whole run (design
        # v17 2.2 item 1). macOS has no flock(1), so every host uses the
        # suites' fake, on a lock file inside tmp.
        fake_flock = Path(__file__).with_name("testdata") / "winn3_gateway_fake_flock.py"
        (stub_bin / "flock").write_bytes(fake_flock.read_bytes())
        os.chmod(stub_bin / "flock", 0o755)
        firewall_path = Path(tmp) / "winn3-gateway-firewall"
        firewall_path.write_text(firewall, encoding="utf-8")
        env = os.environ.copy()
        env["PATH"] = f"{stub_bin}{os.pathsep}{env['PATH']}"
        env["WINN3_GATEWAY_ENV_FILE"] = str(env_file)
        env["WINS_FIREWALL_LOCK"] = str(Path(tmp) / "wins-firewall.lock")
        return subprocess.run(
            ["bash", str(firewall_path)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )


class PreexistingJournalNormalizationTests(unittest.TestCase):
    """A-DEP-003: a wrong-mode pre-existing journal must not survive install."""

    def _provision(self, state: Path, journal: Path) -> subprocess.CompletedProcess[str]:
        return _source(
            INSTALLER,
            "WINN3_GATEWAY_REPLAY_JOURNAL=1; provision_replay_journal",
            extra_env={
                "WINN3_GATEWAY_REPLAY_JOURNAL": "1",
                "WINN3_GATEWAY_REPLAY_JOURNAL_DIR": str(state),
                "WINN3_GATEWAY_REPLAY_JOURNAL_PATH": str(journal),
                "WINN3_GATEWAY_SERVICE_USER": pwd.getpwuid(os.getuid()).pw_name,
            },
        )

    def test_a_0644_journal_is_normalized_and_records_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.write_bytes(b"LIVE")
            os.chmod(journal, 0o644)
            proc = self._provision(state, journal)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o640)
            self.assertEqual(journal.read_bytes(), b"LIVE")

    def test_a_fifo_journal_is_refused_without_waiting_for_a_writer(self) -> None:
        # Run the actual Python helper directly so timeout kills the reader,
        # without leaving a shell child blocked on an attacker-owned FIFO.
        text = INSTALLER.read_text(encoding="utf-8")
        function = text.split("normalize_replay_journal_node() {", 1)[1]
        helper = function.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            os.mkfifo(journal, 0o600)
            proc = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", helper, str(state),
                 "replay.journal", "replay.journal.wal",
                 pwd.getpwuid(os.getuid()).pw_name, "640"],
                capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("not a regular file", proc.stderr)
            self.assertTrue(stat.S_ISFIFO(journal.stat().st_mode))

    def test_a_symlink_journal_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            outside = Path(tmp) / "outside.journal"
            outside.write_bytes(b"EVIL")
            journal = state / "replay.journal"
            journal.symlink_to(outside)
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("symlink", proc.stderr)
            self.assertEqual(outside.read_bytes(), b"EVIL")

    def test_a_dangling_symlink_journal_is_refused(self) -> None:
        """The -e branch would miss it; the -L check fires first."""
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.symlink_to(Path(tmp) / "does-not-exist")
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("symlink", proc.stderr)
            self.assertFalse(journal.exists())

    def test_a_directory_at_the_journal_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.mkdir()
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("not a regular file", proc.stderr)

    def test_a_wrong_owner_journal_is_normalized_when_root(self) -> None:
        """F-04: a wrong-owned journal in a service-user-held StateDirectory.

        The Go runtime (replaystore checkJournalOwnerMode) refuses a journal
        not owned by the gateway's euid, and systemd does not repair a file
        inside an already-adopted StateDirectory -- so the installer must
        chown it itself or report success over a service that cannot boot.
        Only root can chown to another user, so the functional half runs as
        root and every other host gets the source-shape pin below.
        """
        if os.geteuid() != 0:
            text = INSTALLER.read_text(encoding="utf-8")
            self.assertIn("os.fchown(fd, owner.pw_uid, -1)", text,
                          "the F-04 ownership normalization is missing from "
                          "provision_replay_journal")
            return
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.write_bytes(b"LIVE")
            os.chmod(journal, 0o640)
            pw = pwd.getpwnam("nobody")
            os.chown(state, pw.pw_uid, pw.pw_gid)
            os.chown(journal, 0, 0)  # root-owned journal in nobody-owned dir
            proc = _source(
                INSTALLER,
                "WINN3_GATEWAY_REPLAY_JOURNAL=1; provision_replay_journal",
                extra_env={
                    "WINN3_GATEWAY_REPLAY_JOURNAL": "1",
                    "WINN3_GATEWAY_REPLAY_JOURNAL_DIR": str(state),
                    "WINN3_GATEWAY_REPLAY_JOURNAL_PATH": str(journal),
                    "WINN3_GATEWAY_SERVICE_USER": "nobody",
                },
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            st = journal.stat()
            self.assertEqual(st.st_uid, pw.pw_uid,
                             "journal left owned by root in a service-user "
                             "StateDirectory: the gateway would refuse it")
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o640)
            self.assertEqual(journal.read_bytes(), b"LIVE")

    def test_a_symlink_wal_dir_is_refused(self) -> None:
        """F-04: the WAL directory gets the same symlink refusal as the journal."""
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.write_bytes(b"LIVE")
            os.chmod(journal, 0o640)
            outside = Path(tmp) / "outside.wal"
            outside.mkdir()
            (state / "replay.journal.wal").symlink_to(outside)
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("symlink", proc.stderr)
            self.assertTrue(outside.is_dir())

    def test_a_wrong_owner_wal_dir_is_normalized_when_root(self) -> None:
        if os.geteuid() != 0:
            text = INSTALLER.read_text(encoding="utf-8")
            self.assertIn("os.fchown(wal_fd, owner.pw_uid, -1)", text,
                          "the F-04 WAL-directory ownership normalization is "
                          "missing")
            return
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.write_bytes(b"LIVE")
            os.chmod(journal, 0o640)
            wal = state / "replay.journal.wal"
            wal.mkdir(mode=0o755)
            (wal / "0000000000000001").write_bytes(b"REC")
            pw = pwd.getpwnam("nobody")
            os.chown(state, pw.pw_uid, pw.pw_gid)
            os.chown(journal, pw.pw_uid, pw.pw_gid)
            # WAL dir and its record stay root-owned: the restore artifact.
            proc = _source(
                INSTALLER,
                "WINN3_GATEWAY_REPLAY_JOURNAL=1; provision_replay_journal",
                extra_env={
                    "WINN3_GATEWAY_REPLAY_JOURNAL": "1",
                    "WINN3_GATEWAY_REPLAY_JOURNAL_DIR": str(state),
                    "WINN3_GATEWAY_REPLAY_JOURNAL_PATH": str(journal),
                    "WINN3_GATEWAY_SERVICE_USER": "nobody",
                },
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            wal_st = wal.stat()
            self.assertEqual(wal_st.st_uid, pw.pw_uid)
            self.assertEqual(stat.S_IMODE(wal_st.st_mode), 0o700)
            self.assertEqual((wal / "0000000000000001").read_bytes(), b"REC")

    def test_a_symlink_journal_never_touches_the_victim(self) -> None:
        """NEW-DEP-001: Daybreak's probe, refuted deterministically.

        The pre-fix code checked the path (symlink? regular?) and then
        chmod/chowned the PATH; a service user who owns the StateDirectory
        could swap the journal name for a symlink between the check and the
        chmod, and root chmodded the victim at the other end (the probe
        flipped an unrelated 0600 file to 0640). The dirfd/O_NOFOLLOW/fchmod
        helper must refuse the symlink AND leave the victim byte- and
        mode-identical.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            victim = Path(tmp) / "victim.conf"
            victim.write_bytes(b"DO-NOT-TOUCH")
            os.chmod(victim, 0o600)
            journal = state / "replay.journal"
            journal.symlink_to(victim)
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("is a symlink", proc.stderr)
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o600,
                             "the chmod raced through the symlink and "
                             "modified the victim's mode")
            self.assertEqual(victim.read_bytes(), b"DO-NOT-TOUCH")

    def test_a_symlink_wal_dir_never_touches_the_victim(self) -> None:
        """NEW-DEP-001: the same probe against the WAL normalization."""
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            journal = state / "replay.journal"
            journal.write_bytes(b"LIVE")
            os.chmod(journal, 0o640)
            victim_dir = Path(tmp) / "victim.d"
            victim_dir.mkdir(mode=0o700)
            (victim_dir / "keep").write_bytes(b"KEEP")
            (state / "replay.journal.wal").symlink_to(victim_dir)
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("is a symlink", proc.stderr)
            self.assertEqual(
                stat.S_IMODE(victim_dir.stat().st_mode), 0o700,
                "the WAL normalization raced through the symlink and "
                "modified the victim directory's mode")
            self.assertEqual((victim_dir / "keep").read_bytes(), b"KEEP")

    def test_creation_never_writes_through_a_swapped_symlink(self) -> None:
        """NEW-DEP-001 create branch: O_CREAT|O_EXCL|O_NOFOLLOW.

        The old `install` followed the destination path, so a symlink swapped
        in after the existence check was written THROUGH to the victim. The
        helper's create must refuse a name that exists in any form.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "winn3-gateway"
            state.mkdir(mode=0o700)
            victim = Path(tmp) / "victim.conf"
            victim.write_bytes(b"DO-NOT-TOUCH")
            os.chmod(victim, 0o600)
            journal = state / "replay.journal"
            journal.symlink_to(victim)
            # A dangling-looking swap: remove the real target's relevance by
            # pointing the link at an existing file -- O_EXCL on the name
            # itself is what must refuse.
            proc = self._provision(state, journal)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(victim.read_bytes(), b"DO-NOT-TOUCH",
                             "the create branch wrote through the symlink")
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o600)

    def test_normalization_uses_the_held_fd_not_the_path(self) -> None:
        """NEW-DEP-001 source pin: the race-free primitives are committed.

        The helper must operate through a directory fd with O_NOFOLLOW and
        fchmod/fchown on the open descriptor, and must re-verify the name
        still resolves to the inode it hardened.
        """
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("os.O_NOFOLLOW", text)
        self.assertIn("dir_fd=dir_fd", text)
        self.assertIn("os.fchmod(fd, mode)", text)
        self.assertIn("named.st_dev, named.st_ino", text,
                      "the (dev,ino) name re-verification is missing")


if __name__ == "__main__":
    unittest.main()
