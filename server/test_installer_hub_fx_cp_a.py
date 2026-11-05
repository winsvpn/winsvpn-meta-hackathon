#!/usr/bin/env python3
"""Hub installer fix wave FX-CP-A (installer audit 2026-09-29).

Covers findings IA-CP-01, 02, 03, 04 and 07 in
server/wins_control_plane_setup_ONETOUCH.sh, plus the undefined
LITESTREAM_SYNC_TIMEOUT_SECONDS_DEFAULT found while fixing IA-CP-04.

Every behavioural test runs the SHIPPED bash (functions and top-level blocks
extracted verbatim from the installer) under Bash 4+, with only host effects
stubbed: GNU stat/find are emulated for macOS, root ownership is asserted by
the stub (these tests are about precedence and ordering, not ownership), and
iptables/systemctl/litestream/cryptsetup are fakes that record their calls.
Nothing touches the host outside a private temporary directory.

    python3 server/test_installer_hub_fx_cp_a.py

WINS_FXCPA_INSTALLER=<path> points the suite at another copy (mutants.py uses
this to prove the tests bite).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
import sys


def _bash4() -> str:
    """Sol T4 N-1: the suite must run from a tree without server/_toolchain.py.
    Use the shared preflight when it is there, else resolve Bash 4+ locally
    with the same candidate order and the same one-line failure."""
    try:
        import _toolchain  # noqa: F401  (V-01 preflight)
    except ModuleNotFoundError:
        if sys.version_info < (3, 10):
            raise SystemExit("TOOLCHAIN PREREQUISITE NOT MET: Python 3.10+ is required.")
        for candidate in (
            os.environ.get("WINS_TEST_BASH", ""),
            "/opt/homebrew/bin/bash",
            "/usr/local/bin/bash",
            shutil.which("bash") or "",
            "/bin/bash",
        ):
            if not candidate or not os.path.exists(candidate):
                continue
            try:
                version = subprocess.run(
                    [candidate, "-c", "echo ${BASH_VERSINFO[0]}"],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                continue
            if version.isdigit() and int(version) >= 4:
                return candidate
        raise SystemExit(
            "TOOLCHAIN PREREQUISITE NOT MET: Bash 4+ is required; set WINS_TEST_BASH."
        )
    return _toolchain.bash4()

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = Path(
    os.environ.get(
        "WINS_FXCPA_INSTALLER",
        str(ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"),
    )
)
BASH = _bash4()
# Sol T4 N-2: harnesses run shipped installer code with host commands faked
# and persistence redirected. A mutant can still reach a hardcoded /etc path
# (configure_litestream_replication writes /etc/litestream.yml), and as root
# that write would land. Refuse to run as root so a test can never modify
# the host, whatever the code under test does.
if hasattr(os, "geteuid") and os.geteuid() == 0:
    raise SystemExit("refusing to run as root: this suite must never be able to modify the host")
FW_FUNCS = (
    "hub_fail2ban_ignoreips", "hub_filter_ruleset_dump", "hub_ruleset_validate",
    "hub_filter_chain_state", "hub_input_chain_state", "hub_f2b_exempt_ban_sources",
    "hub_f2b_exempt_ban_rules", "hub_f2b_purge_ignored_bans", "hub_f2b_traversal_check",
    "hub_f2b_require_jump", "hub_f2b_prove_restart", "hub_bounded", "hub_now",
    "hub_duration", "hub_f2b_left", "hub_f2b_budget", "hub_f2b_restart_observe", "hub_run",
    "hub_f2b_bans_before", "hub_wall_now", "hub_f2b_split_pending",
)
SOURCE = INSTALLER.read_text(encoding="utf-8")
LINES = SOURCE.splitlines()

HEX64_A = "a" * 64
HEX64_B = "b" * 64
HEX64_C = "c" * 64


def function_definition(name: str) -> str:
    """Return `name() { ... }` verbatim: up to the first column-0 `}` that is
    not inside a heredoc body (installer functions are column-0 delimited)."""
    signature = f"\n{name}() {{\n"
    start = SOURCE.find(signature)
    if start < 0:
        raise AssertionError(f"installer defines no function {name}")
    start += 1
    out = []
    terminator = None
    for line in SOURCE[start:].split("\n"):
        out.append(line)
        if terminator is not None:
            if line.strip("\t") == terminator:
                terminator = None
            continue
        if line == "}":
            return "\n".join(out)
        if "<<<" not in line and not line.lstrip().startswith("#"):
            match = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
            if match:
                terminator = match.group(1)
    raise AssertionError(f"unterminated function {name}")


def optional_functions(*names: str) -> str:
    """Definitions for the names this installer has; absent ones are skipped
    (so the snapshot runs and fails on behaviour, not on extraction)."""
    return "\n".join(function_definition(n) for n in names if f"\n{n}() {{\n" in SOURCE)


def between(begin: str, end: str) -> str:
    a = SOURCE.index(begin)
    b = SOURCE.index(end, a)
    return SOURCE[a : b + len(end)]


def top_level_defaults() -> str:
    """Every simple top-level NAME=... assignment before the first big block.

    These are the *_DEFAULT values write_env reads. They are evaluated AFTER the
    harness has loaded the defaults file, exactly as the installer does.
    """
    out = []
    for number, line in enumerate(LINES[:900], 1):
        if not re.match(r"^[A-Z][A-Z0-9_]*=", line):
            continue
        if line.startswith(("SCRIPT_DIR=", "WINS_OPERATOR_INTENT_KEYS=")):
            continue
        out.append(line)
    return "\n".join(out)


STUBS = r"""
log() { printf '[LOG] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR] %s\n' "$*" >&2; }
# GNU stat/find emulation for macOS. Ownership is reported as root (0): these
# tests exercise precedence and ordering, not the ownership gates.
stat() {
  local fmt="" path out mode
  if [[ "$1" == "-c" ]]; then fmt="$2"; shift 2; fi
  for path in "$@"; do
    if [[ -n "${FAKE_STAT_MODE_FOR:-}" && "${path}" == "${FAKE_STAT_MODE_FOR%%=*}" ]]; then
      mode="${FAKE_STAT_MODE_FOR#*=}"
    else
      [[ -e "${path}" || -L "${path}" ]] || return 1
      mode="$(python3 -c 'import os,stat,sys; print(format(stat.S_IMODE(os.lstat(sys.argv[1]).st_mode), "o"))' "${path}")"
    fi
    out="${fmt//%u/0}"
    out="${out//%a/${mode}}"
    printf '%s\n' "${out}"
  done
}
find() {
  # The `find PATH -prune -perm /MASK -print -quit` idiom is emulated (macOS
  # find has no /MASK); anything else is the real find. FAKE_FIND_RC makes
  # find fail with no output (only for FAKE_FIND_PATH, when that is set).
  local first="$1"
  [[ "${first}" == -[HLP] ]] && first="$2"
  if [[ -n "${FAKE_FIND_RC:-}" && ( -z "${FAKE_FIND_PATH:-}" || "${first}" == "${FAKE_FIND_PATH:-}" ) ]]; then
    echo "find: ${first}: Input/output error" >&2
    return "${FAKE_FIND_RC}"
  fi
  local path="$1" mask="" a
  for a in "$@"; do [[ "${a}" == -perm ]] && mask=x; done
  [[ -n "${mask}" ]] || { command find "$@"; return; }
  mask=""
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in -perm) mask="${2#/}"; shift 2 ;; *) shift ;; esac
  done
  python3 -c 'import os,stat,sys
m=stat.S_IMODE(os.lstat(sys.argv[1]).st_mode)
print(sys.argv[1] if m & int(sys.argv[2], 8) else "", end="")' "${path}" "${mask}"
}
"""


def run(script: str, env: dict | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C",
    }
    if env:
        base.update(env)
    return subprocess.run(
        [BASH, "-c", script],
        env=base,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=120,
    )


def write_fake(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/bash\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)
    return path


# --------------------------------------------------------------------------
# IA-CP-01: rerun env precedence
# --------------------------------------------------------------------------

RUN1_RUNTIME = {
    "ADMIN_TOKEN": "run1-admin-token",
    "ADMINTOKEN": "run1-admin-token",
    "SPA_KEY": "run1spakey" + "A" * 33 + "=",
    "SPA_HMAC": "run1spahmac" + "B" * 32 + "=",
    "XRAY_UUID": "11111111-1111-4111-8111-111111111111",
    "HOPPY_AGENT_HMAC": HEX64_A,
    "LEGAL_ACCEPTANCE_HMAC_KEY": HEX64_B,
    "RATE_LIMIT_SECRET": HEX64_C,
    "MANAGEMENT_NAME_HMAC_KEY": HEX64_A,
    "REDEMPTION_KEYS": "v1:" + HEX64_A,
    "REDEMPTION_KEY_ACTIVE_VERSION": "v1",
    "TUNNEL_SERVICE_TOKEN_ID": "run1.access",
    "TUNNEL_SERVICE_TOKEN_SECRET": "run1-tunnel-secret-" + "x" * 20,
    "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID": "22222222-2222-4222-8222-222222222222",
    "PAYPAL_WEBHOOK_ID": "WH-RUN1",
    "HIDE_CONTROL_ORIGIN": "1",
    "HUB_ADMIN_SSH_CIDRS": "203.0.113.4/32",
    "NODE_HEARTBEAT_STALE_SECONDS": "900",
    "REQUIRE_CLOUDFLARE_ACCESS": "1",
    "FREE_ACCESS_LABEL": "run1 label",
    "NODE_REGISTER_BLOCKED_HOSTS": "run1.example",
    "ACTIVE_GATEWAY_BASE": "https://old-gateway.example",
}

# The preseed prepends .env.example, so the real defaults file carries empty
# placeholders for every generated secret alongside the operator's values.
DEFAULTS_FILE = "\n".join(
    [
        "ADMIN_TOKEN=",
        "SPA_KEY=",
        "SPA_HMAC=",
        "TUNNEL_SERVICE_TOKEN_ID=",
        "TUNNEL_SERVICE_TOKEN_SECRET=",
        "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID=",
        "PAYPAL_WEBHOOK_ID=",
        "FREE_ACCESS_LABEL=",
        # Non-empty values for runtime-owned keys must still not win.
        "XRAY_UUID=33333333-3333-4333-8333-333333333333",
        "REDEMPTION_KEYS=v9:" + HEX64_C,
        "REDEMPTION_KEY_ACTIVE_VERSION=v9",
        # Operator changes since run 1.
        "HIDE_CONTROL_ORIGIN=0",
        "HUB_ADMIN_SSH_CIDRS='198.51.100.9/32'",
        "NODE_HEARTBEAT_STALE_SECONDS=300",
        "NODE_REGISTER_BLOCKED_HOSTS=defaults.example",
        "ACTIVE_GATEWAY_BASE=https://new-gateway.example",
        "",
    ]
)

SECRETS_FILE = "\n".join(
    [
        "NODE_REGISTER_BLOCKED_HOSTS='secrets.example'",
        "",
    ]
)

REPORT_KEYS = sorted(set(RUN1_RUNTIME) | {"XRAY_UUID", "REDEMPTION_KEYS", "LITESTREAM_SYNC_TIMEOUT_SECONDS"})


def write_env_harness(work: Path, defaults_text: str, runtime: dict | None, secrets_text: str | None) -> str:
    defaults = work / "winsvpn-defaults.env"
    defaults.write_text(defaults_text, encoding="utf-8")
    secrets = work / "winsvpn-secrets.env"
    if secrets_text is not None:
        secrets.write_text(secrets_text, encoding="utf-8")
        secrets.chmod(0o600)
    app = work / "vpn_auth"
    app.mkdir(exist_ok=True)
    env_file = work / "vpn_auth.env"
    if runtime is not None:
        env_file.write_text(
            "".join(f"{k}='{v}'\n" for k, v in runtime.items()), encoding="utf-8"
        )
    top_load = between('if [[ -f "${WINS_DEFAULTS_FILE}" ]]; then', "  set +a\nfi\n")
    try:
        capture = between(
            "# --- begin IA-CP-01 operator intent capture ---",
            "# --- end IA-CP-01 operator intent capture ---",
        )
    except ValueError:
        capture = "# (no intent capture in this installer)"
    env_region = between("load_existing_envs() {", "\natomic_replace_file() {")
    env_region = env_region[: -len("\natomic_replace_file() {")]
    winn3 = between(
        "# --- begin winn3 hub EnvironmentFile writers ---",
        "# --- end winn3 hub EnvironmentFile writers ---",
    )
    report = "\n".join(
        f"printf '%s=%s\\n' {k} \"${{{k}:-}}\"" for k in REPORT_KEYS
    )
    return f"""
set -Eeuo pipefail
{STUBS}
wins_require_trusted_env_file() {{ :; }}
snapshot_operator_intent() {{ :; }}
reapply_operator_intent() {{ :; }}
WINS_DEFAULTS_FILE={str(defaults)!r}
WINS_SECRETS_FILE={str(secrets)!r}
{top_load}
{capture}
{function_definition("overlay_wins_secrets_file")}
overlay_wins_secrets_file || exit 1
{top_level_defaults()}
APP_DIR={str(app)!r}
ENV_FILE={str(env_file)!r}
LEGACY_ENV_FILE={str(app / '.env')!r}
DB_PATH={str(app / 'vpn_users.db')!r}
{env_region}
{function_definition("atomic_replace_file")}
{winn3}
# H5: the hub AWG canary key needs wg and root ownership; its own tests are in
# test_hub_awg_carry_canary_h5.py. This harness checks env precedence only.
write_awg_canary_runtime_env() {{ :; }}
{function_definition("write_env")}
echo '--- preflight view ---'
{report}
write_env
source "${{ENV_FILE}}"
echo '--- deployed view ---'
{report}
"""


def parse_views(stdout: str) -> tuple[dict, dict]:
    pre, post, cur = {}, {}, None
    for line in stdout.splitlines():
        if line == "--- preflight view ---":
            cur = pre
            continue
        if line == "--- deployed view ---":
            cur = post
            continue
        if cur is not None and "=" in line:
            k, v = line.split("=", 1)
            cur[k] = v
    return pre, post


class RerunEnvPrecedence(unittest.TestCase):
    """IA-CP-01."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="fxcpa-env-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_rerun(self, defaults: str, env: dict | None = None, secrets: str | None = SECRETS_FILE):
        script = write_env_harness(self.tmp, defaults, RUN1_RUNTIME, secrets)
        full_env = {"LITESTREAM_SYNC_TIMEOUT_SECONDS": "30"}
        full_env.update(env or {})
        result = run(script, env=full_env)
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
        self.last_stderr = result.stderr
        return parse_views(result.stdout)

    def test_defaults_file_beats_previous_runtime_for_operator_keys(self) -> None:
        _, post = self.run_rerun(DEFAULTS_FILE)
        self.assertEqual(post["HUB_ADMIN_SSH_CIDRS"], "198.51.100.9/32")
        self.assertEqual(post["HIDE_CONTROL_ORIGIN"], "0")
        self.assertEqual(post["NODE_HEARTBEAT_STALE_SECONDS"], "300")

    def test_process_environment_is_operator_intent_too(self) -> None:
        _, post = self.run_rerun(DEFAULTS_FILE, env={"REQUIRE_CLOUDFLARE_ACCESS": "0"})
        self.assertEqual(post["REQUIRE_CLOUDFLARE_ACCESS"], "0")

    def test_preflight_and_deploy_agree_on_every_operator_key(self) -> None:
        pre, post = self.run_rerun(DEFAULTS_FILE, env={"REQUIRE_CLOUDFLARE_ACCESS": "0"})
        for key in (
            "HUB_ADMIN_SSH_CIDRS",
            "HIDE_CONTROL_ORIGIN",
            "NODE_HEARTBEAT_STALE_SECONDS",
            "REQUIRE_CLOUDFLARE_ACCESS",
            "NODE_REGISTER_BLOCKED_HOSTS",
            "ACTIVE_GATEWAY_BASE",
        ):
            self.assertEqual(pre[key], post[key], key)

    def test_generated_and_minted_secrets_survive_the_rerun(self) -> None:
        _, post = self.run_rerun(DEFAULTS_FILE)
        for key in (
            "ADMIN_TOKEN",
            "SPA_KEY",
            "SPA_HMAC",
            "XRAY_UUID",
            "HOPPY_AGENT_HMAC",
            "LEGAL_ACCEPTANCE_HMAC_KEY",
            "RATE_LIMIT_SECRET",
            "MANAGEMENT_NAME_HMAC_KEY",
            "REDEMPTION_KEYS",
            "REDEMPTION_KEY_ACTIVE_VERSION",
            "TUNNEL_SERVICE_TOKEN_ID",
            "TUNNEL_SERVICE_TOKEN_SECRET",
            "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID",
            "PAYPAL_WEBHOOK_ID",
        ):
            self.assertEqual(post[key], RUN1_RUNTIME[key], key)

    def test_empty_placeholder_never_clears_a_runtime_value(self) -> None:
        # .env.example ships HUB_ADMIN_SSH_CIDRS= empty; clearing the runtime
        # value would drop the admin SSH accept on the next firewall write.
        defaults = DEFAULTS_FILE.replace("HUB_ADMIN_SSH_CIDRS='198.51.100.9/32'", "HUB_ADMIN_SSH_CIDRS=")
        _, post = self.run_rerun(defaults)
        self.assertEqual(post["HUB_ADMIN_SSH_CIDRS"], "203.0.113.4/32")
        self.assertEqual(post["FREE_ACCESS_LABEL"], "run1 label")

    def test_ignored_runtime_owned_values_are_warned_by_name_only(self) -> None:
        self.run_rerun(DEFAULTS_FILE)
        err = self.last_stderr
        for key in ("XRAY_UUID", "REDEMPTION_KEYS", "REDEMPTION_KEY_ACTIVE_VERSION"):
            self.assertIn(f"[WARN] {key} is set in the defaults file or environment", err)
        # Empty placeholders are not intent and draw no warning.
        self.assertNotIn("[WARN] SPA_KEY is set", err)
        # Values never reach the log.
        self.assertNotIn("33333333-3333-4333-8333-333333333333", err)
        self.assertNotIn(HEX64_C, err)

    def test_owned_value_equal_to_runtime_draws_no_warning(self) -> None:
        defaults = DEFAULTS_FILE.replace("ADMIN_TOKEN=\n", f"ADMIN_TOKEN={RUN1_RUNTIME['ADMIN_TOKEN']}\n", 1)
        self.assertIn(f"ADMIN_TOKEN={RUN1_RUNTIME['ADMIN_TOKEN']}\n", defaults)
        self.run_rerun(defaults)
        self.assertNotIn("[WARN] ADMIN_TOKEN is set", self.last_stderr)
        # the differing ones still warn in the same run (non-vacuity)
        self.assertIn("[WARN] XRAY_UUID is set", self.last_stderr)

    def test_secrets_file_still_beats_defaults(self) -> None:
        _, post = self.run_rerun(DEFAULTS_FILE)
        self.assertEqual(post["NODE_REGISTER_BLOCKED_HOSTS"], "secrets.example")

    def test_routing_restores_unchanged(self) -> None:
        _, post = self.run_rerun(DEFAULTS_FILE)
        self.assertEqual(post["ACTIVE_GATEWAY_BASE"], "https://new-gateway.example")

    def test_fresh_deploy_without_sync_timeout_does_not_abort(self) -> None:
        """LITESTREAM_SYNC_TIMEOUT_SECONDS_DEFAULT was referenced, never defined."""
        script = write_env_harness(self.tmp, "", None, None)
        result = run(script)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        _, post = parse_views(result.stdout)
        self.assertEqual(post["LITESTREAM_SYNC_TIMEOUT_SECONDS"], "30")
        self.assertRegex(post["ADMIN_TOKEN"], r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------
# IA-CP-02: fail2ban jump order
# --------------------------------------------------------------------------


class Fail2banOrder(unittest.TestCase):
    """IA-CP-02."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="fxcpa-f2b-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.capture = self.tmp / "transaction.rules"
        # Sol N-1 (Turn 4): every lock-free live probe fails (xtables lock
        # held); only the definite iptables-save read may decide anything.
        write_fake(
            self.bin,
            "iptables",
            'echo "Another app is currently holding the xtables lock" >&2\nexit 4\n',
        )
        write_fake(
            self.bin,
            "fake-restore",
            f"""
            for a in "$@"; do [[ "$a" == --test ]] && {{ cat >/dev/null; exit 0; }}; done
            cat > {str(self.capture)!r}
            """,
        )
        self.write_save()
        write_fake(self.bin, "systemctl", "exit 1\n")
        # Sol T4 N-2: nothing write_iptables runs may reach the host. Every
        # command it can execute by name resolves to a recording fake, and the
        # persisted ruleset goes to a private directory.
        self.host_log = self.tmp / "host-effects.log"
        self.rules_dir = self.tmp / "etc-iptables"
        self.rules_dir.mkdir()
        for name in ("ip6tables", "ip6tables-save", "iptables-save", "netfilter-persistent", "suricata", "iptables-restore"):
            write_fake(self.bin, name, f'echo "{name} $*" >> {str(self.host_log)!r}\n' + ("exit 1\n" if name == "suricata" else "exit 0\n"))

    def write_save(
        self,
        state: Path | None = None,
        fail_first: int = 0,
        always_fail: bool = False,
        fail_after: int = 0,
        stderr_text: str = "",
        f2b_chain: bool = True,
    ) -> None:
        """iptables-save fake: a *filter section with f2b-sshd declared (unless
        f2b_chain=False), the ban lines from `state`, and after a commit the
        committed WINVPN-HUB-INPUT rules."""
        count = self.tmp / "save.count"
        decl = 'echo ":f2b-sshd - [0:0]"' if f2b_chain else ":"
        bans = f"grep '^-A ' {str(state)!r}" if state else ":"
        warn = f"echo {stderr_text!r} >&2" if stderr_text else ":"
        write_fake(
            self.bin,
            "fake-save",
            f"""
            n=$(( $(cat {str(count)!r} 2>/dev/null || echo 0) + 1 )); echo $n > {str(count)!r}
            {"echo 'Could not fetch rule set generation id: Permission denied (you must be root)' >&2; exit 4" if always_fail else ":"}
            [[ $n -le {fail_first} ]] && {{ echo "Another app is currently holding the xtables lock" >&2; exit 4; }}
            [[ {fail_after} -gt 0 && $n -gt {fail_after} ]] && {{ echo "save failed after deletion" >&2; exit 4; }}
            {warn}
            echo "# Generated by fake-save"
            echo "*filter"; echo ":INPUT DROP [0:0]"; {decl}; echo ":WINVPN-HUB-INPUT - [0:0]"
            {bans}
            [[ -f {str(self.capture)!r} ]] && grep -q -- '^-I INPUT 1 -j WINVPN-HUB-INPUT$' {str(self.capture)!r} && echo "-A INPUT -j WINVPN-HUB-INPUT"
            [[ -f {str(self.capture)!r} ]] && grep '^-A WINVPN-HUB-INPUT ' {str(self.capture)!r}
            echo COMMIT
            """,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    SANDBOXED = ("iptables", "ip6tables", "ip6tables-save", "iptables-save", "netfilter-persistent", "systemctl", "suricata", "iptables-restore")

    def emitted_input_rules(self, extra_env: dict | None = None, require_commit: bool = True) -> list[str]:
        guard = "\n".join(
            f'case "$(command -v {c})" in {self.bin}/*) ;; *) echo "SANDBOX BREACH: {c}" >&2; exit 99 ;; esac'
            for c in self.SANDBOXED
        )
        script = f"""
{guard}
{STUBS}
sleep() {{ echo "sleep $*" >> {str(self.tmp / 'sleeps.log')!r}; }}
HIDE_CONTROL_ORIGIN_DEFAULT=1
CONTROL_DIRECT_CLOUDFLARE_ONLY_DEFAULT=0
HUB_ADMIN_SSH_CIDRS_DEFAULT=""
HUB_SSH_PASSWORD_AUTH_DEFAULT=1
HUB_SSH_RECOVERY_CIDR_DEFAULT=""
SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT=0
CONTROL_LEGACY_SPA_UDP_DEFAULT=0
HUB_FAIL2BAN_IGNOREIPS_DEFAULT="127.0.0.1/8 ::1"
{optional_functions(*FW_FUNCS)}
{function_definition("write_iptables")}
write_iptables
"""
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "IPTABLES_RESTORE_BIN": str(self.bin / "fake-restore"),
            "IPTABLES_SAVE_BIN": str(self.bin / "fake-save"),
            "HUB_IPTABLES_RULES_DIR": str(self.rules_dir),
            "HUB_ADMIN_SSH_CIDRS": "203.0.113.4/32 203.0.113.5/32",
            "SSH_CONNECTION": "192.0.2.7 50000 192.0.2.1 22",
            "HUB_SSH_RECOVERY_CIDR": "100.64.0.0/10",
        }
        env.update(extra_env or {})
        self.last = run(script, env=env)
        self.assertNotEqual(self.last.returncode, 99, self.last.stderr)
        if not require_commit:
            return []
        self.assertTrue(self.capture.exists(), "write_iptables never committed a transaction")
        return [
            line
            for line in self.capture.read_text(encoding="utf-8").splitlines()
            if line.startswith("-A WINVPN-HUB-INPUT ")
        ]

    def test_jump_precedes_every_accept(self) -> None:
        rules = self.emitted_input_rules()
        jumps = [i for i, r in enumerate(rules) if r.endswith("-j f2b-sshd")]
        self.assertEqual(len(jumps), 1, rules)
        accepts = [i for i, r in enumerate(rules) if r.endswith("-j ACCEPT")]
        self.assertTrue(accepts, rules)
        self.assertLess(jumps[0], min(accepts), rules)
        # The recovery window (password auth) is behind the ban chain.
        recovery = [i for i, r in enumerate(rules) if "winsvpn-ssh-recovery" in r]
        self.assertEqual(len(recovery), 1, rules)
        self.assertLess(jumps[0], recovery[0])
        self.assertEqual(jumps[0], 0, rules)

    BANS = (
        "-A f2b-sshd -s 192.0.2.7/32 -j DROP\n"
        "-A f2b-sshd -s 198.51.100.77/32 -j DROP\n"
        "-A f2b-sshd -s 192.0.2.7/32 -j DROP\n"
        "-A f2b-sshd -s 100.64.1.1/32 -j DROP\n"
    )

    def stateful_f2b(
        self,
        save_fail_first: int = 0,
        save_always_fail: bool = False,
        save_fail_after: int = 0,
        delete_fails: bool = False,
        unban_fails: bool = False,
        bans: str | None = None,
    ) -> tuple[Path, Path]:
        """Fakes with one shared kernel state: iptables (-D edits it),
        iptables-save (prints it as a *filter section) and fail2ban-client."""
        state = self.tmp / "f2b.chain"
        events = self.tmp / "events.log"
        state.write_text(bans if bans is not None else self.BANS, encoding="utf-8")
        deleter = self.tmp / "delete.py"
        deleter.write_text(
            "import shlex, sys\n"
            "state, events, args = sys.argv[1], sys.argv[2], sys.argv[3:]\n"
            "lines = open(state).read().splitlines()\n"
            "for i, line in enumerate(lines):\n"
            "    # the kernel stores it's; iptables-save prints it as \\\\' inside double quotes\n"
            "    if shlex.split(line.replace(chr(92) + chr(39), chr(39)))[2:] == args:\n"
            "        del lines[i]\n"
            "        open(state, 'w').write(''.join(l + '\\n' for l in lines))\n"
            "        open(events, 'a').write('delete ' + ' '.join(args) + '\\n')\n"
            "        sys.exit(0)\n"
            "sys.exit(1)\n",
            encoding="utf-8",
        )
        write_fake(
            self.bin,
            "iptables",
            f"""
            [[ "$1" == -w ]] && shift 2
            if [[ "$1" == -D && "$2" == f2b-sshd ]]; then
              {"exit 4" if delete_fails else ":"}
              shift 2
              exec python3 {str(deleter)!r} {str(state)!r} {str(events)!r} "$@"
            fi
            echo "Another app is currently holding the xtables lock" >&2
            exit 4
            """,
        )
        self.write_save(
            state=state,
            fail_first=save_fail_first,
            always_fail=save_always_fail,
            fail_after=save_fail_after,
        )
        write_fake(
            self.bin,
            "fail2ban-client",
            f'echo "unban $*" >> {str(events)!r}\n' + ("exit 255\n" if unban_fails else "exit 0\n"),
        )
        write_fake(
            self.bin,
            "fake-restore",
            f"""
            for a in "$@"; do [[ "$a" == --test ]] && {{ cat >/dev/null; exit 0; }}; done
            echo commit >> {str(events)!r}
            cat > {str(self.capture)!r}
            """,
        )
        return state, events

    ADMIN = {"HUB_ADMIN_SSH_CIDRS": "203.0.113.4/32 198.51.100.0/24"}

    # ---- Turn 4: Seat C N-2 (rule shapes, messages), Sol N-1, OI-CPA-10A ----

    SHAPED_BANS = (
        '-A f2b-sshd -s 198.51.100.45/32 -m comment --comment "manual ban" -j DROP\n'
        "-A f2b-sshd -s 198.51.100.46/32 -p tcp -j REJECT --reject-with icmp-port-unreachable\n"
        "-A f2b-sshd -s 192.0.0.0/8 -j DROP\n"
        "-A f2b-sshd -p tcp -j REJECT\n"
        "-A f2b-sshd -s 198.51.100.47/32 -j RETURN\n"
        "-A f2b-sshd -s 100.64.1.1/32 -j DROP\n"
    )

    def test_every_rule_shape_that_blocks_an_exempt_source_is_removed(self) -> None:
        state, events = self.stateful_f2b(bans=self.SHAPED_BANS)
        self.emitted_input_rules(self.ADMIN)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-2000:])
        remaining = state.read_text()
        # extra matches (comment), REJECT, a wide CIDR covering the deploy
        # source, and a rule with no -s at all: all block an exempt source
        for gone in ("198.51.100.45/32", "198.51.100.46/32", "192.0.0.0/8", "-p tcp -j REJECT\n"):
            self.assertNotIn(gone, remaining, gone)
        # RETURN blocks nothing; the recovery source is not exempt
        self.assertIn("198.51.100.47/32 -j RETURN", remaining)
        self.assertIn("100.64.1.1/32 -j DROP", remaining)
        log = events.read_text()
        self.assertIn("delete -s 198.51.100.45/32 -m comment --comment manual ban -j DROP", log)
        # only single-host bans are handed to fail2ban
        self.assertIn("unban set sshd unbanip 198.51.100.45", log)
        self.assertNotIn("unbanip 192.0.0.0", log)

    def test_free_text_values_are_not_read_as_the_ban_source_or_target(self) -> None:
        """Sol N-10, the same parse for the purge: a comment "-s" made the
        source lookup crash (the commit was refused), and a comment "-j" made a
        RETURN rule look like a ban, so it was deleted."""
        bans = (
            "-A f2b-sshd -s 198.51.100.45/32 -m comment --comment -s -j DROP\n"
            "-A f2b-sshd -s 198.51.100.46/32 -m comment --comment -j -j RETURN\n"
        )
        state, events = self.stateful_f2b(bans=bans)
        self.emitted_input_rules(self.ADMIN)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-1500:])
        remaining = state.read_text()
        self.assertNotIn("198.51.100.45", remaining)
        self.assertIn("198.51.100.46/32 -m comment --comment -j -j RETURN", remaining)
        self.assertIn("delete -s 198.51.100.45/32 -m comment --comment -s -j DROP", events.read_text())

    def test_apostrophe_comments_are_deleted_and_printed_shell_safe(self) -> None:
        """Seat C T5 N-7: iptables prints it's as \"it\\'s\" inside double quotes."""
        bans = '-A f2b-sshd -s 198.51.100.45/32 -m comment --comment "it\\\'s" -j DROP\n'
        state, events = self.stateful_f2b(bans=bans)
        self.emitted_input_rules(self.ADMIN)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-1500:])
        self.assertNotIn("198.51.100.45", state.read_text())
        self.assertIn("delete -s 198.51.100.45/32 -m comment --comment it's -j DROP", events.read_text())

    def test_refusal_names_the_surviving_rules_and_the_recovery(self) -> None:
        state, events = self.stateful_f2b(delete_fails=True)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        err = self.last.stderr
        self.assertIn("[ERR]   -A f2b-sshd -s 192.0.2.7/32 -j DROP", err)
        self.assertIn("[ERR]   -A f2b-sshd -s 198.51.100.77/32 -j DROP", err)
        self.assertNotIn("[ERR]   -A f2b-sshd -s 100.64.1.1/32", err)
        self.assertIn("iptables-save -t filter | grep -- '-A f2b-sshd'", err)
        self.assertIn("rerun this installer", err)
        self.assertIn("may already have been removed", err)
        self.assertNotIn("cannot prove f2b-sshd holds no ban on an exempt source (admin CIDR or deploy source); active rules were not changed", err)

    def test_post_commit_check_requires_the_jump(self) -> None:
        """Sol N-1: a commit that leaves SSH outside f2b-sshd must not pass."""
        write_fake(
            self.bin,
            "fake-restore",
            f"""
            for a in "$@"; do [[ "$a" == --test ]] && {{ cat >/dev/null; exit 0; }}; done
            grep -v -- '-j f2b-sshd' > {str(self.capture)!r}
            """,
        )
        self.emitted_input_rules(self.ADMIN)
        self.assertNotEqual(self.last.returncode, 0)
        self.assertIn("SSH does not reliably traverse f2b-sshd after the hub firewall commit", self.last.stderr)

    def test_jump_decision_ignores_a_failing_live_probe(self) -> None:
        """Sol N-1: the lock-free `iptables -n -L f2b-sshd` always fails here."""
        rules = self.emitted_input_rules(self.ADMIN)
        self.assertEqual(sum(r.endswith("-j f2b-sshd") for r in rules), 1, rules)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-1500:])

    def require_jump(self, save_body: str) -> subprocess.CompletedProcess:
        write_fake(self.bin, "fake-save", save_body)
        script = f"""
set -Eeuo pipefail
{STUBS}
sleep() {{ :; }}
IPTABLES_SAVE_BIN={str(self.bin / 'fake-save')!r}
{optional_functions(*FW_FUNCS)}
hub_f2b_require_jump "after the fail2ban restart"
"""
        return run(script)

    @staticmethod
    def ruleset(*rules: str, f2b: bool = True) -> str:
        """An iptables-save body (as a fake script) with INPUT, the hub chain
        and optionally f2b-sshd declared, then the given rule lines."""
        lines = ["*filter", ":INPUT DROP [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [0:0]"]
        if f2b:
            lines.append(":f2b-sshd - [0:0]")
        lines.append(":WINVPN-HUB-INPUT - [0:0]")
        lines.extend(rules)
        lines.append("COMMIT")
        return "cat <<'SAVE'\n" + "\n".join(lines) + "\nSAVE\n"

    HUB_IN = "-A INPUT -j WINVPN-HUB-INPUT"
    F2B = "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -j f2b-sshd"

    def test_require_jump_passes_only_with_chain_and_tcp22_jump(self) -> None:
        ok = self.require_jump(self.ruleset(self.HUB_IN, self.F2B))
        self.assertEqual(ok.returncode, 0, ok.stderr)
        no_jump = self.require_jump(self.ruleset(self.HUB_IN))
        self.assertNotEqual(no_jump.returncode, 0)
        self.assertIn("no jump to f2b-sshd covering all tcp/22 traffic", no_jump.stderr)
        no_chain = self.require_jump(self.ruleset(self.HUB_IN, f2b=False))
        self.assertNotEqual(no_chain.returncode, 0)
        self.assertIn("f2b-sshd chain is missing", no_chain.stderr)
        unreadable = self.require_jump("exit 4\n")
        self.assertNotEqual(unreadable.returncode, 0)

    def test_traversal_rejects_what_does_not_route_tcp22_through_the_ban_chain(self) -> None:
        """Sol T4 N-1: protocol, earlier accepts, and conditions all matter."""
        bad = {
            "udp-only jump": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p udp -m multiport --dports 22 -j f2b-sshd"),
            "tcp/22 accept first": (self.HUB_IN, "-A WINVPN-HUB-INPUT -s 203.0.113.4/32 -p tcp -m tcp --dport 22 -j ACCEPT", self.F2B),
            "established accept first": (self.HUB_IN, "-A WINVPN-HUB-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", self.F2B),
            "jump limited to one source": (self.HUB_IN, "-A WINVPN-HUB-INPUT -s 192.0.2.7/32 -p tcp -m multiport --dports 22 -j f2b-sshd"),
            "jump negated": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p tcp -m multiport ! --dports 22 -j f2b-sshd"),
            "jump on another port": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 2222 -j f2b-sshd"),
            "INPUT accepts ssh first": ("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", self.HUB_IN, self.F2B),
            "INPUT never reaches the hub": (self.F2B,),
            "hub jump is conditional": ("-A INPUT -i eth0 -j WINVPN-HUB-INPUT", self.F2B),
        }
        for name, rules in bad.items():
            r = self.require_jump(self.ruleset(*rules))
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("SSH does not reliably traverse f2b-sshd", r.stderr, name)

    def test_covering_jump_has_exactly_tcp_and_one_port_set(self) -> None:
        """Both seats, Turn 5: extra matches on the jump can AND it to nothing
        (Seat C measured these as false passes on iptables 1.8.10 nft)."""
        bad = (
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -m socket -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m socket -m multiport --dports 22 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -m multiport --dports 80 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m tcp --dport 22 -m multiport --dports 80 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m tcp --dport 22 -m multiport --dports 22 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -m multiport --dports 22,80 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -m conntrack --ctstate NEW -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -m comment --comment x -j f2b-sshd",
        )
        for jump in bad:
            r = self.require_jump(self.ruleset(self.HUB_IN, jump, "-A WINVPN-HUB-INPUT -p tcp -m tcp --dport 22 -j ACCEPT"))
            self.assertNotEqual(r.returncode, 0, jump)
            self.assertIn("SSH does not reliably traverse f2b-sshd", r.stderr, jump)
        good = (
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 21:23 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 80,22,443 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m tcp --dport 22 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -m tcp -j f2b-sshd",
        )
        for jump in good:
            r = self.require_jump(self.ruleset(self.HUB_IN, jump))
            self.assertEqual(r.returncode, 0, f"{jump}: {r.stderr}")

    def test_free_text_values_are_never_read_as_options(self) -> None:
        """Sol N-10 (Turn 6): iptables 1.8.10 prints a plain comment unquoted,
        so "--comment -p -j ACCEPT" is an unconditional ACCEPT whose comment
        is -p. Reading the comment as -p made it look like a non-TCP rule and
        the traversal proof passed with an accept-all ahead of the ban chain."""
        sols = (
            "-A INPUT -m comment --comment -p -j ACCEPT", self.HUB_IN, self.F2B,
        )
        r = self.require_jump(self.ruleset(*sols))
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("INPUT can accept tcp/22 before WINVPN-HUB-INPUT: -A INPUT -m comment --comment -p -j ACCEPT", r.stderr)
        for accept in (
            "-A WINVPN-HUB-INPUT -m comment --comment -p -j ACCEPT",
            "-A WINVPN-HUB-INPUT -m comment --comment --dport -j ACCEPT",
            "-A WINVPN-HUB-INPUT -p tcp -m string --string -p --algo bm -j ACCEPT",
            "-A WINVPN-HUB-INPUT -m comment --comment ! -j ACCEPT",
        ):
            r = self.require_jump(self.ruleset(self.HUB_IN, accept, self.F2B))
            self.assertNotEqual(r.returncode, 0, accept)
            self.assertIn("WINVPN-HUB-INPUT can accept tcp/22 before f2b-sshd", r.stderr, accept)
        # The same parse in the other direction: the real option after a
        # free-text value is still read.
        for harmless in (
            "-A WINVPN-HUB-INPUT -m comment --comment -p -p udp -m udp --dport 22 -j ACCEPT",
            "-A WINVPN-HUB-INPUT -m comment --comment -j -j DROP",
        ):
            r = self.require_jump(self.ruleset(self.HUB_IN, harmless, self.F2B))
            self.assertEqual(r.returncode, 0, f"{harmless}: {r.stderr}")
        # And the restart proof, which runs the same traversal check.
        body = self.ruleset(*sols)
        r = self.prove_restart([body], self.status(), seconds=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("INPUT can accept tcp/22 before WINVPN-HUB-INPUT", r.stderr)

    def test_traversal_accepts_rules_that_cannot_bypass_the_ban_chain(self) -> None:
        good = {
            "udp/22 accept first": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p udp -m udp --dport 22 -j ACCEPT", self.F2B),
            "tcp/80 queue first": (self.HUB_IN, "-A WINVPN-HUB-INPUT -i lo -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0", self.F2B),
            "drop first": (self.HUB_IN, "-A WINVPN-HUB-INPUT -s 10.8.0.0/16 -j DROP", self.F2B),
            "port list": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 80,22 -j f2b-sshd"),
            "port range": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 20:30 -j f2b-sshd"),
            "single dport": (self.HUB_IN, "-A WINVPN-HUB-INPUT -p tcp -m tcp --dport 22 -j f2b-sshd"),
        }
        for name, rules in good.items():
            r = self.require_jump(self.ruleset(*rules))
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")

    # ---- Turns 5 and 6: prove the restart against the jail (OI-CPA-10A,
    # F2B-VERSION, Seat C N-4, Sol N-6 and N-7). A fake millisecond clock makes
    # the deadline testable: hub_now reads it; sleep and the slow fakes advance
    # it; the fake timeout(1) enforces its bound against that clock and exits
    # 124 exactly when a real one would have.

    CLOCK_ZERO = 1_000_000

    def prove_restart(self, save_bodies: list[str], status, before: str = "",
                      seconds: int = 4, env: dict | None = None, stamp: bool = True,
                      actions: str = "The jail sshd has the following actions:\nwins-iptables-hub",
                      save_cost: int = 0, status_cost: int | list[int] = 0, actions_cost: int = 0,
                      traversal: str | None = None, stamp_arg: str | None = None,
                      sleep_slack: int = 0, status_kill_at: int = 0,
                      wall_zero: int | None = None) -> subprocess.CompletedProcess:
        """status: a string, None (jail missing) or a list of strings (one per
        status call, the last one repeats). The *_cost values are the
        milliseconds each fake command takes on the fake clock; status_cost
        may be a list, one per status call (the last one repeats).
        sleep_slack: milliseconds every sleep overruns, as a real one may.
        status_kill_at: the status call (1-based) that is killed with SIGKILL
        after spending its cost, as an external kill or the OOM killer would.
        The fake clock at the end of every status call is logged (obs_ends).
        wall_zero: the wall-clock epoch second at which the proof begins; the
        wall clock (hub_wall_now) then follows the fake clock. None keeps the
        real wall clock."""
        count = self.tmp / "prove.count"
        count.unlink(missing_ok=True)
        (self.tmp / "obs_ends.log").unlink(missing_ok=True)
        clock = self.tmp / "clock"
        clock.write_text(f"{self.CLOCK_ZERO}\n", encoding="utf-8")
        self.clock_file = clock
        for i, body in enumerate(save_bodies, 1):
            write_fake(self.bin, f"save-body-{i}", body)
        last = len(save_bodies)
        write_fake(
            self.bin,
            "fake-save",
            f"""
            echo $(( $(cat {str(clock)!r}) + {save_cost} )) > {str(clock)!r}
            echo save >> {str(self.tmp / 'calls.log')!r}
            n=$(( $(cat {str(count)!r} 2>/dev/null || echo 0) + 1 )); echo $n > {str(count)!r}
            [[ $n -gt {last} ]] && n={last}
            exec {str(self.bin)!r}/save-body-$n
            """,
        )
        statuses = [status] if isinstance(status, str) or status is None else list(status)
        scount = self.tmp / "status.count"
        scount.unlink(missing_ok=True)
        for i, st in enumerate(statuses, 1):
            body = "echo 'Sorry but the jail sshd does not exist' >&2\nexit 255\n" if st is None else f"cat <<'STATUS'\n{st}\nSTATUS\n"
            write_fake(self.bin, f"status-body-{i}", body)
        write_fake(
            self.bin,
            "fail2ban-client",
            f"""
            echo "f2b $*" >> {str(self.tmp / 'calls.log')!r}
            if [[ "$1" == version ]]; then echo 1.0.2; exit 0; fi
            if [[ "$1 $2 $3" == "get sshd actions" ]]; then
              echo $(( $(cat {str(clock)!r}) + {actions_cost} )) > {str(clock)!r}
              cat <<'ACT'
{actions}
ACT
              exit 0
            fi
            n=$(( $(cat {str(scount)!r} 2>/dev/null || echo 0) + 1 )); echo $n > {str(scount)!r}
            costs=({" ".join(str(c) for c in (status_cost if isinstance(status_cost, list) else [status_cost]))})
            c=$(( n > ${{#costs[@]}} ? ${{#costs[@]}} : n ))
            echo $(( $(cat {str(clock)!r}) + ${{costs[c - 1]}} )) > {str(clock)!r}
            [[ $n == {status_kill_at} ]] && kill -KILL $$
            cat {str(clock)!r} >> {str(self.tmp / 'obs_ends.log')!r}
            [[ $n -gt {len(statuses)} ]] && n={len(statuses)}
            exec {str(self.bin)!r}/status-body-$n
            """,
        )
        write_fake(
            self.bin,
            "timeout",
            f"""
            echo "timeout $*" >> {str(self.tmp / 'calls.log')!r}
            while [[ "$1" == -k ]]; do shift 2; done
            limit=$(python3 -c 'import sys; print(round(float(sys.argv[1]) * 1000))' "$1")
            shift
            before=$(cat {str(clock)!r})
            "$@"
            rc=$?
            after=$(cat {str(clock)!r})
            if (( after - before > limit )); then
              echo $(( before + limit )) > {str(clock)!r}
              exit 124
            fi
            exit $rc
            """,
        )
        stamp_file = self.tmp / "sshd.actionstart"
        if stamp:
            stamp_file.write_text("", encoding="utf-8")
        else:
            stamp_file.unlink(missing_ok=True)
        script = f"""
set -Eeuo pipefail
{STUBS}
IPTABLES_SAVE_BIN={str(self.bin / 'fake-save')!r}
HUB_FAIL2BAN_IGNOREIPS_DEFAULT="127.0.0.1/8 ::1"
HUB_ADMIN_SSH_CIDRS_DEFAULT=""
HUB_F2B_PROOF_SECONDS={seconds}
{optional_functions(*FW_FUNCS)}
hub_now() {{ cat {str(clock)!r}; }}
{'' if wall_zero is None else f"hub_wall_now() {{ echo $(( {wall_zero} + ($(cat {str(clock)!r}) - {self.CLOCK_ZERO}) / 1000 )); }}"}
sleep() {{
  echo "sleep $*" >> {str(self.tmp / 'sleeps.log')!r}
  local ms
  if [[ "$1" == *.* ]]; then ms=$((10#${{1%%.*}} * 1000 + 10#${{1#*.}})); else ms=$(($1 * 1000)); fi
  echo $(( $(cat {str(clock)!r}) + ms + {sleep_slack} )) > {str(clock)!r}
}}
hub_f2b_prove_restart {before!r} {str(stamp_file) if stamp_arg is None else stamp_arg!r}{'' if traversal is None else ' ' + traversal}
"""
        full = {"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"}
        full.update(env or {})
        return run(script, env=full)

    @staticmethod
    def status(*ips: str) -> str:
        return (
            "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n"
            "`- Actions\n   |- Currently banned:\t" + str(len(ips)) + "\n"
            "   `- Banned IP list:\t" + " ".join(ips)
        )

    def sleeps(self) -> int:
        f = self.tmp / "sleeps.log"
        return f.read_text().count("sleep 1") if f.exists() else 0

    def sleep_args(self) -> list[str]:
        f = self.tmp / "sleeps.log"
        return [l.split(" ", 1)[1] for l in f.read_text().splitlines()] if f.exists() else []

    def obs_ends(self) -> list[int]:
        """Fake-clock time (ms since the proof began) at which each status
        call, the last external command of an observation, ended."""
        f = self.tmp / "obs_ends.log"
        return [int(x) - self.CLOCK_ZERO for x in f.read_text().split()] if f.exists() else []

    def elapsed(self) -> int:
        """Milliseconds on the fake clock since the proof began."""
        return int(self.clock_file.read_text()) - self.CLOCK_ZERO

    def calls(self) -> list[str]:
        f = self.tmp / "calls.log"
        return f.read_text().splitlines() if f.exists() else []

    def test_restart_proof_passes_when_the_chain_matches_the_jail(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 192.0.2.9/32 -j DROP")
        r = self.prove_restart([body], self.status("192.0.2.9"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("fail2ban restart proven", r.stderr)
        self.assertNotIn("BANS LOST", r.stderr)
        # Seat C N-8: the list is printed once
        self.assertEqual(r.stderr.count("192.0.2.9"), 1, r.stderr)
        self.assertEqual(self.sleeps(), 0)
        # Sol T5 N-7: every external call is bounded by the time left
        calls = self.calls()
        for needle in ("fail2ban-client version", "fail2ban-client get sshd actions", "fail2ban-client status sshd", "fake-save"):
            self.assertTrue(any(c.startswith("timeout -k 1 ") and needle in c for c in calls), (needle, calls))

    def test_restart_proof_requires_this_actionstart_to_have_succeeded(self) -> None:
        """Sol T5 OI-CPA-10A: restored empty chain plus existing jump, the
        flush failed (exit 4), so the action never wrote its stamp."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), seconds=3, stamp=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("actionstart has not completed successfully", r.stderr)
        self.assertIn("NOT proven within 3s", r.stderr)

    def test_restart_proof_requires_the_hub_action_in_the_jail(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B)
        for actions in ("The jail sshd has the following actions:\niptables-multiport",
                        "The jail sshd has the following actions:\nwins-iptables-hub-old"):
            r = self.prove_restart([body], self.status(), seconds=2, actions=actions)
            self.assertNotEqual(r.returncode, 0, actions)
            self.assertIn("does not run the wins-iptables-hub action", r.stderr)
        r = self.prove_restart([body], self.status(), seconds=2,
                               actions="The jail sshd has the following actions:\nsendmail, wins-iptables-hub")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_restart_proof_fails_on_a_stale_ban_the_flush_left(self) -> None:
        """Sol T4 OI-CPA-10A: restored chain and jump, flush failed (exit 4),
        the expired recovery-source DROP is still there."""
        body = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 100.64.1.1/32 -j DROP")
        r = self.prove_restart([body], self.status(), seconds=3)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("f2b-sshd holds a rule fail2ban does not account for: -A f2b-sshd -s 100.64.1.1/32 -j DROP", r.stderr)
        self.assertIn("NOT proven within 3s", r.stderr)
        self.assertLessEqual(self.elapsed(), 3000)

    def test_restart_proof_fails_when_a_jail_ban_has_no_kernel_rule(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status("192.0.2.9"), seconds=2)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fail2ban reports bans with no kernel rule: 192.0.2.9/32", r.stderr)

    def test_restart_proof_rejects_non_ban_rules_in_the_chain(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 192.0.2.0/24 -j REJECT")
        r = self.prove_restart([body], self.status(), seconds=1)
        self.assertNotEqual(r.returncode, 0)

    def test_restart_proof_accepts_cidr_bans_and_reports_ipv6(self) -> None:
        """Seat C N-6: a CIDR ban matches its rule; an IPv6 ban is reported."""
        body = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 192.0.2.0/24 -j DROP")
        r = self.prove_restart([body], self.status("192.0.2.0/24", "2001:db8::5"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("IPv6 bans (2001:db8::5)", r.stderr)

    def test_restart_proof_waits_for_the_actions_thread(self) -> None:
        """Seat C N-4: the chain appears on the third read."""
        late = self.ruleset(self.HUB_IN, f2b=False)
        ready = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([late, late, ready], self.status(), seconds=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.sleeps(), 2)

    def test_restart_proof_waits_for_queued_restoration(self) -> None:
        """Sol T5 N-6: a ban held before the restart is absent from both views
        until fail2ban's actions thread takes it; that is not a loss yet."""
        empty = self.ruleset(self.HUB_IN, self.F2B)
        restored = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 192.0.2.9/32 -j DROP")
        r = self.prove_restart([empty, empty, empty, restored],
                               [self.status(), self.status(), self.status(), self.status("192.0.2.9")],
                               before="192.0.2.9", seconds=15)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BANS LOST", r.stderr)
        self.assertEqual(self.sleeps(), 3)

    def test_restart_proof_reports_a_loss_only_after_the_full_window(self) -> None:
        """Sol T5 N-6 and both seats T6: wait the WHOLE window (Turn 6 gave
        up at 5000 ms of 6000 and claimed 6s), report the elapsed time that
        was measured, and fail. An ignored address is never reported."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before="192.0.2.9 198.51.100.77", seconds=6,
                               env={"HUB_ADMIN_SSH_CIDRS": "198.51.100.0/24"})
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr)
        self.assertIn("still not restored after 6.000s (the whole 6s window)", r.stderr)
        self.assertIn("[ERR] FAIL2BAN BANS LOST", r.stderr)
        self.assertIn("fail2ban-client get dbfile", r.stderr)
        self.assertNotIn("restart proven", r.stderr)
        self.assertNotIn("198.51.100.77", r.stderr)
        self.assertEqual(self.elapsed(), 6000)
        # The time reported is the time measured, not the window: sleeps that
        # overrun by 7 ms each end the wait at 6.007 s.
        (self.tmp / "sleeps.log").unlink()
        r = self.prove_restart([body], self.status(), before="192.0.2.9", seconds=6, sleep_slack=7)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("still not restored after 6.007s (the whole 6s window)", r.stderr)
        self.assertEqual(self.elapsed(), 6007)

    def test_the_last_poll_ends_at_the_deadline(self) -> None:
        """N-6, Turn 7, and N-14, Turn 8: with 300 ms observations in a 6 s
        window the remaining polls are spread evenly (0.81 s naps), so the
        sixth starts at 5.55 s and ends at 5.85 s, half a poll before the
        deadline. A ban restored only then is seen (Turn 6 stopped at 5.5 s
        and reported it lost; Turn 7 got there with 1 s naps by luck)."""
        empty = self.ruleset(self.HUB_IN, self.F2B)
        restored = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 192.0.2.9/32 -j DROP")
        r = self.prove_restart([empty] * 5 + [restored], [self.status()] * 5 + [self.status("192.0.2.9")],
                               before="192.0.2.9", seconds=6, status_cost=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BANS LOST", r.stderr)
        self.assertIn("restart proven after 5.850s", r.stderr)
        self.assertEqual(self.sleep_args(), ["0.810"] * 5)
        self.assertEqual(self.elapsed(), 5850)

    def test_a_pending_ban_waits_out_a_window_no_poll_fits(self) -> None:
        """N-6, Turn 7: 2.5 s observations in a 4 s window. After the first,
        1.5 s is left, too little for a second; the proof sleeps it out
        instead of reporting the ban lost at 2.5 s. A failing observation in
        the same position gives up at once (nothing more can be observed)."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before="192.0.2.9", seconds=4, status_cost=2500)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("still not restored after 4.000s", r.stderr)
        self.assertEqual(self.sleep_args(), ["1.500"])
        self.assertEqual(self.elapsed(), 4000)
        (self.tmp / "sleeps.log").unlink()
        r = self.prove_restart([body], self.status("192.0.2.9"), seconds=4, status_cost=2500)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("NOT proven within 4s (elapsed 2.500s): fail2ban reports bans with no kernel rule", r.stderr)
        self.assertEqual(self.sleep_args(), [])

    def test_a_command_killed_before_the_deadline_is_not_a_loss(self) -> None:
        """Sol N-6, Turn 7: one pending observation completes, then the next
        status call is SIGKILLed (exit 137) at 1.875 s of a 6 s window. Turn 7
        read that as a deadline cut and reported "BANS LOST ... after 1.875s
        (the whole 6s window)". Exit 137 before the deadline is a killed
        command: the proof fails with the true elapsed time and makes no loss
        claim."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before="192.0.2.9", seconds=6,
                               status_cost=600, status_kill_at=2)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BANS LOST", r.stderr)
        self.assertNotIn("(the whole", r.stderr)
        self.assertNotIn("restart proven", r.stderr)
        self.assertIn("NOT proven: the observations stopped after 1.875s with 4.125s of the 6s window left", r.stderr)
        self.assertIn("so a command was killed and was not cut off by the deadline", r.stderr)
        self.assertIn("The bans still pending (192.0.2.9) were not observed for the whole window and are not reported as lost", r.stderr)
        self.assertIn("journalctl -k", r.stderr)
        self.assertEqual(self.elapsed(), 1875)
        # The same kill in the first observation, nothing completed: still
        # fails closed, and names the kill, not the deadline.
        r = self.prove_restart([body], self.status("192.0.2.9"), seconds=6,
                               status_cost=600, status_kill_at=1)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("stopped after 0.600s with 5.400s of the 6s window left", r.stderr)
        self.assertIn("so a command was killed and was not cut off by the deadline", r.stderr)
        # A real deadline cut is still a cut (control): the loss is reported
        # only because the window did end.
        r = self.prove_restart([body], self.status(), before="192.0.2.9", seconds=4, status_cost=[500, 3000])
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr)
        self.assertNotIn("was killed", r.stderr)

    def test_a_ban_whose_bantime_ended_is_not_lost(self) -> None:
        """N-13, Turn 8: before the restart the jail held 192.0.2.9 (bantime
        ended a minute ago) and 192.0.2.10 (an hour left); fail2ban restores
        only the second. That is expiry, not loss: the proof passes and names
        the expired ban. The same address with time left is still lost."""
        now = int(time.time())
        restored = self.ruleset(self.HUB_IN, self.F2B, "-A f2b-sshd -s 192.0.2.10/32 -j DROP")
        before = f"192.0.2.9@{now - 60} 192.0.2.10@{now + 3600}"
        r = self.prove_restart([restored], self.status("192.0.2.10"), before=before, seconds=4)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BANS LOST", r.stderr)
        self.assertIn("bantime ended since the pre-restart snapshot, not expected back: 192.0.2.9.", r.stderr)
        self.assertEqual(self.sleeps(), 0)
        r = self.prove_restart([restored], self.status("192.0.2.10"), before=f"192.0.2.9@{now + 3600} 192.0.2.10@{now + 3600}", seconds=4)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr)
        self.assertIn("their bantime has not ended", r.stderr)
        self.assertNotIn("@", r.stderr.split("BANS LOST", 1)[1].split("\n", 1)[0])

    def test_a_ban_that_ends_during_the_window_is_expired_not_lost(self) -> None:
        """N-13, Sol T8: expiry was judged only inside an observation, and the
        final verdict reused that observation's pending list. 192.0.2.9 ends
        at 1800000003; the proof starts at wall time 1800000000 with a 4 s
        window and the first observation costs 2.5 s, so the ban is pending
        at 1800000002 and the proof then sleeps to 1800000004, where its own
        now >= end + 1 rule holds. Turn 8 reported BANS LOST there. The rule
        is applied again at the verdict: expired, the proof passes. A ban
        still running at the verdict (end 1800000004, or an hour later) is
        still lost, and so is an address one of whose entries still runs."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before="192.0.2.9@1800000003", seconds=4,
                               status_cost=2500, wall_zero=1_800_000_000)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BANS LOST", r.stderr)
        self.assertIn("fail2ban restart proven after 4.000s", r.stderr)
        self.assertIn("bantime ended since the pre-restart snapshot, not expected back: 192.0.2.9.", r.stderr)
        self.assertEqual(self.obs_ends(), [2500])
        self.assertEqual(self.elapsed(), 4000)
        # Already expired at the first observation: no wait at all, which
        # needs the observation to read the same wall clock (hub_wall_now).
        (self.tmp / "sleeps.log").unlink(missing_ok=True)
        r = self.prove_restart([body], self.status(), before="192.0.2.9@1799999990", seconds=4,
                               status_cost=500, wall_zero=1_800_000_000)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not expected back: 192.0.2.9.", r.stderr)
        self.assertEqual((self.sleep_args(), self.obs_ends()), ([], [500]))
        for before in ("192.0.2.9@1800000004", "192.0.2.9@1800003600",
                       "192.0.2.9@1800000003 192.0.2.9@1800003600", "192.0.2.9@1800003600 192.0.2.9@1800000003",
                       "192.0.2.9"):
            r = self.prove_restart([body], self.status(), before=before, seconds=4,
                                   status_cost=2500, wall_zero=1_800_000_000)
            self.assertNotEqual(r.returncode, 0, before)
            self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr, before)
            self.assertIn("their bantime has not ended", r.stderr, before)
            self.assertEqual(self.elapsed(), 4000, before)
        # Mixed: one ban ends in the window, the other is lost; only the
        # second is reported, and the first is not called lost.
        r = self.prove_restart([body], self.status(), before="192.0.2.9@1800000003 192.0.2.10@1800003600",
                               seconds=4, status_cost=2500, wall_zero=1_800_000_000)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.10.", r.stderr)

    def test_the_last_poll_ends_half_a_poll_before_the_deadline(self) -> None:
        """N-14, Seat C T7: Turn 7 capped each nap at 1 s and let the last
        poll land wherever that left it (900 ms polls in 6 s: sleeps 1.000,
        1.000, 1.300 and the last observation ended at 4.70 s). Now, whenever
        a further poll fits, the remaining polls are spread so the last one
        ends at most half a poll before the deadline, every nap stays within
        1 s while polls cost under 1 s, and the window is still waited out.
        When a poll costs more than 1 s (2.5 s polls in 8 s) the nap grows
        rather than going negative."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        for cost, seconds in ((300, 6), (700, 6), (900, 6), (300, 15), (700, 15), (900, 15), (1500, 6), (2500, 8), (450, 4)):
            (self.tmp / "sleeps.log").unlink(missing_ok=True)
            r = self.prove_restart([body], self.status(), before="192.0.2.9", seconds=seconds, status_cost=cost)
            label = f"{cost} ms polls, {seconds} s"
            self.assertIn("FAIL2BAN BANS LOST", r.stderr, label)
            ends = self.obs_ends()
            self.assertGreaterEqual(len(ends), 2, label)
            self.assertLessEqual(seconds * 1000 - ends[-1], cost // 2, (label, ends))
            self.assertEqual(self.elapsed(), seconds * 1000, label)
            naps = [float(a) for a in self.sleep_args()[:-1]]
            if cost < 1000:
                self.assertTrue(all(n <= 1.0 for n in naps), (label, naps))
            self.assertTrue(all(n >= 0.001 for n in naps), (label, naps))

    def test_the_clock_is_monotonic(self) -> None:
        """N-6, Turn 7: the deadline and the elapsed time come from a
        monotonic clock, never wall-clock time (EPOCHREALTIME or date), which
        NTP can step. A fake date on PATH and an unset EPOCHREALTIME change
        nothing; the value follows python's time.monotonic()."""
        write_fake(self.bin, "date", "echo 99\n")
        script = f"""
set -Eeuo pipefail
{optional_functions("hub_now")}
hub_now
unset EPOCHREALTIME
hub_now
"""
        before = time.monotonic() * 1000
        r = run(script, env={"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"})
        after = time.monotonic() * 1000
        self.assertEqual(r.returncode, 0, r.stderr)
        for value in (int(x) for x in r.stdout.split()):
            self.assertTrue(before - 50 <= value <= after + 50, (before, value, after))
        self.assertNotIn("EPOCHREALTIME", function_definition("hub_now"))
        self.assertNotIn("date", function_definition("hub_now"))

    def test_restart_proof_gives_up_after_the_deadline(self) -> None:
        late = self.ruleset(self.HUB_IN, f2b=False)
        r = self.prove_restart([late], self.status(), seconds=5)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.sleeps(), 5)
        self.assertIn("(elapsed 5.000s)", r.stderr)
        self.assertIn("NOT proven within 5s", r.stderr)
        self.assertIn("journalctl -u fail2ban", r.stderr)

    def test_restart_proof_deadline_is_total_wall_clock(self) -> None:
        """Sol T5 N-7: a slow, failing table read cannot stretch the deadline:
        one attempt per observation, every call bounded by the time left."""
        r = self.prove_restart(["exit 4\n"], self.status(), seconds=5, save_cost=2000)
        self.assertNotEqual(r.returncode, 0)
        self.assertLessEqual(self.elapsed(), 5000, self.calls())
        calls = self.calls()
        saves = calls.count("save")
        bounded = [c for c in calls if c.startswith("timeout -k 1 ") and "fake-save" in c]
        self.assertEqual(len(bounded), saves, calls)
        for c in bounded:
            self.assertLessEqual(float(c.split()[3]), 5.0, c)
        self.assertLessEqual(saves, 3, calls)
        self.assertNotIn("sleep 2", (self.tmp / "sleeps.log").read_text() if (self.tmp / "sleeps.log").exists() else "")

    def test_sols_one_second_budget_with_slow_failing_reads(self) -> None:
        """Sol T5 N-7, his own measurement: HUB_F2B_PROOF_SECONDS=1 with three
        table reads of 0.4 s took 1.327 s and still said 'after 1s'. Now the
        first failing read leaves 0.6 s, too little for a second observation."""
        r = self.prove_restart(["exit 4\n"], self.status(), seconds=1, save_cost=400)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.calls().count("save"), 1, self.calls())
        self.assertLessEqual(self.elapsed(), 1000)
        self.assertIn("NOT proven within 1s", r.stderr)

    def test_restart_proof_default_deadline_is_15s(self) -> None:
        late = self.ruleset(self.HUB_IN, f2b=False)
        r = self.prove_restart([late], self.status(), seconds=0, env={})
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.elapsed(), 15000)
        self.assertIn("NOT proven within 15s", r.stderr)

    def test_deadline_cut_keeps_the_last_completed_observation(self) -> None:
        """Sol T5 N-6 with N-7: pending bans are polled to the deadline, and
        the observation the deadline cuts short must not replace a completed
        OK one. Status takes 0.5 s, then 3 s in a 4 s window: the first
        observation completes, the second is cut at the deadline, and the
        result is the first one's pending ban (Turn 7: a loss is a failure)."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before="192.0.2.9", seconds=4, status_cost=[500, 3000])
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr)
        self.assertNotIn("NOT proven within", r.stderr)
        self.assertNotIn("cut off by the deadline", r.stderr)
        self.assertEqual(self.elapsed(), 4000)

    def test_deadline_cut_with_nothing_completed_fails_inside_the_budget(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B)
        for knob, text in (
            ("status_cost", "fail2ban-client status sshd was cut off by the deadline"),
            ("actions_cost", "fail2ban-client get sshd actions was cut off by the deadline"),
            ("save_cost", "the filter table read was cut off by the deadline"),
        ):
            r = self.prove_restart([body], self.status(), seconds=3, **{knob: 5000})
            self.assertNotEqual(r.returncode, 0, knob)
            self.assertIn(text, r.stderr, knob)
            self.assertIn("NOT proven within 3s", r.stderr, knob)
            self.assertNotIn("BANS LOST", r.stderr, knob)
            self.assertLessEqual(self.elapsed(), 3000, knob)

    def test_a_failing_observation_after_an_ok_one_still_fails(self) -> None:
        """The pending-restoration wait is not a pass: when a later completed
        observation shows the jail listing a ban the kernel does not hold, the
        proof fails (it never reports success from the earlier observation)."""
        empty = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([empty], [self.status(), self.status("192.0.2.9")],
                               before="192.0.2.9", seconds=3)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fail2ban reports bans with no kernel rule: 192.0.2.9/32", r.stderr)
        self.assertIn("NOT proven within 3s", r.stderr)
        self.assertNotIn("restart proven", r.stderr)

    def test_restart_proof_never_sleeps_past_the_deadline(self) -> None:
        """A 3 s budget with 0.7 s reads (N-14, Turn 8: the polls are spread):
        naps of 0.275 s put the third observation at 1.95 to 2.65 s; then
        0.35 s is left, a fourth read would run to 3.35 s, and no sleep is
        started."""
        late = self.ruleset(self.HUB_IN, f2b=False)
        r = self.prove_restart([late], self.status(), seconds=3, save_cost=700)
        self.assertNotEqual(r.returncode, 0)
        self.assertLessEqual(self.elapsed(), 3000)
        self.assertEqual(self.sleep_args(), ["0.275", "0.275"])
        self.assertEqual(self.elapsed(), 2650)

    def test_version_lookup_is_inside_the_budget(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B)
        for seconds, bound in ((2, "2.000"), (15, "5.000")):
            (self.tmp / "calls.log").unlink(missing_ok=True)
            r = self.prove_restart([body], self.status(), seconds=seconds)
            self.assertEqual(r.returncode, 0, r.stderr)
            first = self.calls()[0]
            self.assertTrue(first.startswith(f"timeout -k 1 {bound} fail2ban-client version"), (seconds, self.calls()))

    def slow_command(self, name: str, marker: str, ms: int) -> None:
        """A `name` on PATH that spends `ms` on the fake clock when one of its
        arguments contains `marker` (empty: always), then runs the real one."""
        real = sys.executable if name == "python3" else shutil.which(name)
        clock = str(self.tmp / "clock")
        write_fake(
            self.bin,
            name,
            f"""
            hit={'0' if marker else '1'}
            for a in "$@"; do
              case "$a" in *{marker!r}*) hit=1; break ;; esac
            done
            [[ $hit == 0 ]] || echo $(( $(cat {clock!r}) + {ms} )) > {clock!r}
            exec {real!r} "$@"
            """,
        )

    def test_every_subprocess_of_the_proof_is_bounded(self) -> None:
        """Sol N-7, Turn 6: delaying only the unbounded validator by 2 s made a
        1 s proof take 3.3 s. Each helper the proof runs (the temporary file,
        the validator, the traversal check, the status parser and the
        comparison) now ends at the deadline and the proof stops there."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        for name, marker, text in (
            ("python3", "def valid_body", "the filter table read was cut off by the deadline"),
            ("python3", "def covers_all_tcp22", "the traversal check was cut off by the deadline"),
            ("python3", "splitlines() if", "reading the jail's banned list was cut off by the deadline"),
            ("python3", "does not account for", "comparing the kernel with the jail was cut off by the deadline"),
            ("mktemp", "", "the filter table read was cut off by the deadline"),
        ):
            self.slow_command(name, marker, 5000)
            r = self.prove_restart([body], self.status(), seconds=2)
            (self.bin / name).unlink()
            self.assertNotEqual(r.returncode, 0, marker)
            self.assertIn(text, r.stderr, marker)
            self.assertIn("NOT proven within 2s (elapsed 2.000s)", r.stderr, marker)
            self.assertEqual(self.elapsed(), 2000, marker)

    def test_a_hung_validator_cannot_outlive_the_real_deadline(self) -> None:
        """Sol N-7 with the real clock and a killing timeout(1) stand-in: the
        python validator hangs for 30 s."""
        write_fake(self.bin, "timeout", self.REAL_TIMEOUT)
        write_fake(
            self.bin,
            "fail2ban-client",
            'case "$1" in version) echo 1.0.2 ;; get) printf "x:\\nwins-iptables-hub\\n" ;; '
            '*) printf "Status\\n   - Banned IP list:\\t\\n" ;; esac\n',
        )
        write_fake(self.bin, "fake-save", self.ruleset(self.HUB_IN, self.F2B))
        write_fake(
            self.bin,
            "python3",
            # Only the validator itself ($1 is -c); the timeout stand-in runs
            # python3 too, with the validator among its arguments.
            f'[[ "$1" == -c && "$2" == *"def valid_body"* ]] && sleep 30\nexec {sys.executable!r} "$@"\n',
        )
        stamp = self.tmp / "sshd.actionstart"
        stamp.write_text("", encoding="utf-8")
        script = f"""
set -Eeuo pipefail
{STUBS}
IPTABLES_SAVE_BIN={str(self.bin / 'fake-save')!r}
HUB_FAIL2BAN_IGNOREIPS_DEFAULT="127.0.0.1/8 ::1"
HUB_ADMIN_SSH_CIDRS_DEFAULT=""
HUB_F2B_PROOF_SECONDS=2
{optional_functions(*FW_FUNCS)}
hub_f2b_prove_restart "" {str(stamp)!r}
"""
        began = time.monotonic()
        r = run(script, env={"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"})
        took = time.monotonic() - began
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("NOT proven within 2s", r.stderr)
        self.assertIn("cut off by the deadline", r.stderr)
        self.assertLess(took, 12.0, r.stderr)  # the hung validator sleeps 30 s

    def test_the_deadline_is_local_to_the_proof(self) -> None:
        """hub_run bounds commands only inside the proof: after it returns, a
        later table read (write_iptables) is not cut by a stale deadline."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        self.prove_restart([body], self.status(), seconds=1)
        self.assertIn("local _HUB_F2B_DEADLINE", function_definition("hub_f2b_prove_restart"))
        script = f"""
set -Eeuo pipefail
{STUBS}
{optional_functions(*FW_FUNCS)}
hub_now() {{ echo 5000000; }}
f() {{ local _HUB_F2B_DEADLINE=4000000; hub_run true || echo "inside rc=$?"; }}
f
hub_run true && echo "outside ok"
"""
        r = run(script)
        self.assertEqual(r.stdout.split("\n")[:2], ["inside rc=124", "outside ok"], r.stderr)

    def test_early_restart_proof_skips_traversal_but_not_the_rest(self) -> None:
        """On a hub whose f2b-sshd chain survived from rules.v4, the old jump
        can still sit below the accepts until the firewall write that follows
        the early restart moves it. That order is proved after the commit; the
        early restart must still prove the stamp and the kernel/jail match."""
        old_order = self.ruleset(
            self.HUB_IN, "-A WINVPN-HUB-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", self.F2B)
        r = self.prove_restart([old_order], self.status(), seconds=2)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("can accept tcp/22 before f2b-sshd", r.stderr)
        r = self.prove_restart([old_order], self.status(), seconds=2, traversal="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.prove_restart([old_order], self.status(), seconds=2, traversal="0", stamp=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("actionstart has not completed successfully", r.stderr)
        stale = self.ruleset(
            self.HUB_IN, "-A WINVPN-HUB-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", self.F2B,
            "-A f2b-sshd -s 100.64.1.1/32 -j DROP")
        r = self.prove_restart([stale], self.status(), seconds=2, traversal="0")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not account for", r.stderr)

    def test_the_stamp_is_mandatory(self) -> None:
        """An empty stamp argument names no file, so it can never pass."""
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), seconds=2, stamp_arg="")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("actionstart has not completed successfully", r.stderr)

    def test_only_the_pre_firewall_restart_is_early(self) -> None:
        main_body = function_definition("main")
        self.assertEqual(main_body.count("write_hub_fail2ban_config"), 1)
        self.assertIn("write_hub_fail2ban_config early", main_body)
        self.assertNotIn("early", function_definition("install_control_ids_ips"))
        helper = function_definition("write_hub_fail2ban_config")
        self.assertIn('hub_f2b_prove_restart "${bans_before}" "${actionstart_stamp}" "${traversal}"', helper)
        self.assertIn('[[ "${1:-}" != "early" ]] || traversal=0', helper)

    def test_clock_and_duration_helpers(self) -> None:
        script = f"""
set -Eeuo pipefail
{optional_functions("hub_now", "hub_duration")}
a=$(hub_now); sleep 0.3; b=$(hub_now)
echo "$a $b"
for ms in -5 0 1 999 1000 1500 5000 30000; do hub_duration "$ms"; done
"""
        began = time.monotonic() * 1000
        r = run(script)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.split("\n")
        a, b = (int(x) for x in lines[0].split())
        self.assertLess(abs(a - began), 5000)
        self.assertTrue(250 <= b - a <= 3000, (a, b))
        self.assertEqual(lines[1:9], ["0.001", "0.001", "0.001", "0.999", "1.000", "1.500", "5.000", "30.000"])

    # The same bounds with the real millisecond clock and a real (killing)
    # timeout(1) stand-in: macOS has no coreutils timeout.
    REAL_TIMEOUT = r"""
    while [[ "$1" == -k ]]; do shift 2; done
    exec python3 - "$@" <<'PY'
    import os, signal, subprocess, sys
    p = subprocess.Popen(sys.argv[2:], start_new_session=True)
    try:
        sys.exit(p.wait(timeout=float(sys.argv[1])))
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        sys.exit(124)
    PY
    """

    def test_a_hung_command_cannot_outlive_the_real_deadline(self) -> None:
        write_fake(self.bin, "timeout", self.REAL_TIMEOUT)
        write_fake(self.bin, "fail2ban-client", 'if [[ "$1" == version ]]; then echo 1.0.2; exit 0; fi\nsleep 30\n')
        stamp = self.tmp / "sshd.actionstart"
        stamp.write_text("", encoding="utf-8")
        script = f"""
set -Eeuo pipefail
{STUBS}
HUB_FAIL2BAN_IGNOREIPS_DEFAULT="127.0.0.1/8 ::1"
HUB_ADMIN_SSH_CIDRS_DEFAULT=""
HUB_F2B_PROOF_SECONDS=2
{optional_functions(*FW_FUNCS)}
hub_f2b_prove_restart "" {str(stamp)!r}
"""
        began = time.monotonic()
        r = run(script, env={"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"})
        took = time.monotonic() - began
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("NOT proven within 2s", r.stderr)
        self.assertIn("cut off by the deadline", r.stderr)
        self.assertLess(took, 12.0, r.stderr)  # the hung command sleeps 30 s

    def test_a_hung_table_read_is_cut_and_reported_as_a_timeout(self) -> None:
        write_fake(self.bin, "timeout", self.REAL_TIMEOUT)
        write_fake(self.bin, "slow-save", "sleep 30\n")
        script = f"""
set -Eeuo pipefail
{STUBS}
IPTABLES_SAVE_BIN={str(self.bin / 'slow-save')!r}
{optional_functions(*FW_FUNCS)}
rc=0
hub_filter_ruleset_dump 1 1 || rc=$?
echo "dump_rc=$rc"
"""
        began = time.monotonic()
        r = run(script, env={"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"})
        took = time.monotonic() - began
        self.assertIn("dump_rc=124", r.stdout, r.stderr)
        self.assertIn("timed out after 1s", r.stderr)
        self.assertLess(took, 15.0, r.stderr)  # the hung table read sleeps 30 s

    def bans_before(self, with_time: str | None, status: str | None, env: dict | None = None,
                    zone: str | None = None) -> subprocess.CompletedProcess:
        """Run hub_f2b_bans_before against a fake fail2ban-client. None makes
        that command fail as a missing jail does. zone: the time zone the
        helper parses in (its argument); None parses in the system zone, as
        the installer does."""
        (self.bin / "wt.out").write_text(with_time or "", encoding="utf-8")
        (self.bin / "st.out").write_text(status or "", encoding="utf-8")
        write_fake(
            self.bin,
            "fail2ban-client",
            f"""
            if [[ "$*" == "get sshd banip --with-time" ]]; then
              {"cat " + repr(str(self.bin / "wt.out")) + "; exit 0" if with_time is not None else "echo 'Sorry but the jail sshd does not exist' >&2; exit 255"}
            fi
            if [[ "$*" == "status sshd" ]]; then
              {"cat " + repr(str(self.bin / "st.out")) + "; exit 0" if status is not None else "echo 'Sorry but the jail sshd does not exist' >&2; exit 255"}
            fi
            exit 1
            """,
        )
        # N-15, Seat C T8: the installer's own log, warn and err (they print to
        # stdout), not the suite's STUBS (stderr), so a message the helper
        # prints inside bans_before="$(...)" shows up where it really goes.
        # The first definition of each (later ones live in embedded scripts).
        own = "\n".join(next(l for l in LINES if re.match(name + r"\(\)\s+\{.*\}$", l)) for name in ("log", "warn", "err"))
        script = f"""
set -Eeuo pipefail
{own}
{optional_functions(*FW_FUNCS)}
hub_f2b_bans_before{"" if zone is None else " " + zone}
"""
        full = {"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"}
        full.update(env or {})
        return run(script, env=full)

    @staticmethod
    def local_stamp(epoch: int) -> str:
        """What fail2ban's MyTime.time2str prints: local time, no TZ set."""
        return subprocess.run(
            [sys.executable, "-c", "import sys, time; print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(sys.argv[1]))))", str(epoch)],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, capture_output=True, text=True, check=True,
        ).stdout.strip()

    def test_bans_before_carry_the_end_of_their_bantime(self) -> None:
        """N-13, Turn 8: fail2ban 1.0.2 'get sshd banip --with-time' prints
        '<ip> \\t<start> + <bantime> = <end>' per ban, newline separated, in
        the daemon's local time (banmanager.getBanList, beautifier,
        MyTime.time2str at tag 1.0.2). The helper turns that into ip@end. A TZ
        in the installer's environment must not shift it: the daemon reads
        /etc/localtime."""
        e1, e2 = 1790000000, 1790003600
        lines = (
            f"192.0.2.9 \t{self.local_stamp(e1 - 3600)} + 3600 = {self.local_stamp(e1)}\n"
            f"198.51.100.0/24 \t{self.local_stamp(e2 - 3600)} + 3600 = {self.local_stamp(e2)}"
        )
        for env in (None, {"TZ": "UTC+11"}):
            r = self.bans_before(lines, self.status("192.0.2.9", "198.51.100.0/24"), env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), f"192.0.2.9@{e1} 198.51.100.0/24@{e2}", env)
            self.assertNotIn("[WARN]", r.stderr)
        # A permanent ban (bantime -1) has no end.
        r = self.bans_before(f"192.0.2.9 \t{self.local_stamp(e1)} + -1 = {self.local_stamp(e1)}", self.status("192.0.2.9"))
        self.assertEqual(r.stdout.strip(), "192.0.2.9")
        # An empty jail.
        r = self.bans_before("", self.status())
        self.assertEqual((r.returncode, r.stdout.strip()), (0, ""))

    def test_bans_before_fall_back_to_the_status_list_and_say_so(self) -> None:
        """Unreadable end times keep every ban (the Turn 7 behaviour, fail
        closed) with a warning; no jail at all means no bans, silently.
        N-15, Seat C T8: the warning goes to stderr. The caller captures the
        helper's stdout (bans_before="$(...)") and the installer's warn
        prints to stdout, so in Turn 8 the warning became the first words of
        the snapshot and the operator never saw it. stdout holds addresses
        only."""
        e1 = 1790000000
        for with_time in (None, "192.0.2.9 garbage", f"192.0.2.9 {self.local_stamp(e1)} + 3600 = {self.local_stamp(e1)}"):
            r = self.bans_before(with_time, self.status("192.0.2.9", "192.0.2.10"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, "192.0.2.9 192.0.2.10\n", with_time)
            self.assertIn("Could not read the sshd jail's bans with their end times", r.stderr)
        r = self.bans_before(None, None)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, ""))
        self.assertNotIn("[WARN]", r.stderr)

    def test_an_end_in_the_repeated_dst_hour_is_never_read_early(self) -> None:
        """N-16, Sol T8: fail2ban prints local time with no offset. In
        America/New_York 2026-11-01 01:30:00 happens twice (EDT 1793511000,
        EST 1793514600). A one-hour ban from 01:30 EDT prints start and end
        both as 01:30:00 and really ends at 1793514600; Turn 8 parsed
        1793511000 and, at 1793512800, called the missing ban expired. An
        ambiguous end is now read as the LATER instant: a ban never looks
        expired before it ends (an end in the first fold reads an hour late,
        which can only report a loss). A stamp no instant prints (the
        skipped spring hour) does not parse, so every ban is counted. The
        zone is a process-local fixture, the helper's argument."""
        zone = "America/New_York"
        stamp = "2026-11-01 01:30:00"
        cases = (
            (f"192.0.2.9 \t{stamp} + 3600 = {stamp}", "192.0.2.9@1793514600"),
            (f"192.0.2.9 \t2026-11-01 00:30:00 + 3600 = {stamp}", "192.0.2.9@1793514600"),
            # Unambiguous controls, either side of the change and in summer.
            ("192.0.2.9 \t2026-11-01 02:00:00 + 3600 = 2026-11-01 03:00:00", "192.0.2.9@1793520000"),
            ("192.0.2.9 \t2026-07-01 11:00:00 + 3600 = 2026-07-01 12:00:00", "192.0.2.9@1782921600"),
            ("192.0.2.9 \t2026-01-15 11:00:00 + 3600 = 2026-01-15 12:00:00", "192.0.2.9@1768496400"),
        )
        for line, want in cases:
            r = self.bans_before(line, self.status("192.0.2.9"), zone=zone)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, want), (line, r.stderr))
            self.assertNotIn("Could not read", r.stdout + r.stderr, line)
        # The same stamps in a zone without DST read as that zone's one instant.
        r = self.bans_before(f"192.0.2.9 \t{stamp} + 3600 = {stamp}", self.status("192.0.2.9"), zone="UTC")
        self.assertEqual(r.stdout.strip(), "192.0.2.9@1793496600", r.stderr)
        r = self.bans_before(f"192.0.2.9 \t{stamp} + 3600 = {stamp}", self.status("192.0.2.9"), zone="Asia/Yangon")
        self.assertEqual(r.stdout.strip(), "192.0.2.9@1793473200", r.stderr)
        # 02:30 on 2026-03-08 never happens in New York.
        r = self.bans_before("192.0.2.9 \t2026-03-08 01:30:00 + 3600 = 2026-03-08 02:30:00", self.status("192.0.2.9"), zone=zone)
        self.assertEqual(r.stdout, "192.0.2.9\n", r.stderr)
        self.assertIn("Could not read the sshd jail's bans with their end times", r.stderr)
        # End to end, Sol's case: at 1793512800 the ban has 1800 s left; it
        # is missing from the jail and the kernel, so it is lost.
        r = self.bans_before(f"192.0.2.9 \t{stamp} + 3600 = {stamp}", self.status("192.0.2.9"), zone=zone)
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before=r.stdout.strip(), seconds=6, wall_zero=1_793_512_800)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr)
        self.assertNotIn("not expected back", r.stderr)

    def test_an_end_in_a_repeated_standard_time_hour_is_never_read_early(self) -> None:
        """N-17, Seat C T9: a zone that moves its standard offset back repeats
        an hour with the same DST flag on both sides (Europe/Volgograd,
        2020-12-27 02:00 +04 became 01:00 +03; Europe/Moscow 2014-10-26), so
        mktime's two DST flags do not name both instants and libc picks one,
        depending on the lines it converted before. 01:30:00 in Volgograd is
        1609018200 (+04) and 1609021800 (+03); a one-hour ban from 01:30 +04
        really ends at the later one. Read alone or after another line, it
        must be the later instant. The same holds for New York's DST hour,
        Dublin's (whose tzdata flags winter as the DST side) and Lord Howe's
        30-minute fold. Expected values: every instant that zoneinfo prints
        as the stamp, the latest taken. End to end, at wall 1609020000 the
        missing Volgograd ban has 1800 s left and is lost."""
        a = "192.0.2.9 \t2020-12-27 01:30:00 + 3600 = 2020-12-27 01:30:00"
        b = "192.0.2.9 \t2014-10-26 01:30:00 + 3600 = 2014-10-26 01:30:00"
        cases = (
            ("Europe/Volgograd", a, "192.0.2.9@1609021800"),
            ("Europe/Volgograd", "192.0.2.7 \t2020-12-26 23:45:00 + 3600 = 2020-12-27 00:45:00\n" + a,
             "192.0.2.7@1609015500 192.0.2.9@1609021800"),
            ("Europe/Moscow", b, "192.0.2.9@1414276200"),
            ("Europe/Moscow", "192.0.2.7 \t2014-10-25 23:50:00 + 3600 = 2014-10-26 00:50:00\n" + b,
             "192.0.2.7@1414270200 192.0.2.9@1414276200"),
            ("Europe/Moscow", "192.0.2.7 \t2014-10-26 00:20:00 + 3600 = 2014-10-26 01:20:00\n" + b,
             "192.0.2.7@1414275600 192.0.2.9@1414276200"),
            ("America/New_York", "192.0.2.7 \t2026-11-01 00:20:00 + 3600 = 2026-11-01 01:20:00\n"
             "192.0.2.9 \t2026-11-01 01:30:00 + 3600 = 2026-11-01 01:30:00",
             "192.0.2.7@1793514000 192.0.2.9@1793514600"),
            ("Europe/Dublin", "192.0.2.9 \t2026-10-25 01:30:00 + 3600 = 2026-10-25 01:30:00", "192.0.2.9@1792891800"),
            ("Europe/Dublin", "192.0.2.9 \t2026-01-15 11:00:00 + 3600 = 2026-01-15 12:00:00\n"
             "192.0.2.7 \t2026-07-01 11:00:00 + 3600 = 2026-07-01 12:00:00",
             "192.0.2.9@1768478400 192.0.2.7@1782903600"),
            ("Australia/Lord_Howe", "192.0.2.7 \t2026-04-05 00:10:00 + 3600 = 2026-04-05 01:10:00\n"
             "192.0.2.9 \t2026-04-05 01:45:00 + 3600 = 2026-04-05 01:45:00",
             "192.0.2.7@1775311800 192.0.2.9@1775315700"),
        )
        for zone, lines, want in cases:
            r = self.bans_before(lines, self.status("192.0.2.9"), zone=zone)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, want), (zone, lines, r.stderr))
            self.assertNotIn("Could not read", r.stderr, (zone, lines))
        # Dublin's skipped spring hour does not parse: every ban is counted.
        r = self.bans_before("192.0.2.9 \t2026-03-29 00:30:00 + 3600 = 2026-03-29 01:30:00", self.status("192.0.2.9"), zone="Europe/Dublin")
        self.assertEqual(r.stdout, "192.0.2.9\n", r.stderr)
        self.assertIn("Could not read the sshd jail's bans with their end times", r.stderr)
        r = self.bans_before("192.0.2.7 \t2020-12-26 23:45:00 + 3600 = 2020-12-27 00:45:00\n" + a,
                             self.status("192.0.2.7", "192.0.2.9"), zone="Europe/Volgograd")
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], self.status(), before=r.stdout.strip(), seconds=6, wall_zero=1_609_020_000)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("FAIL2BAN BANS LOST ACROSS THE RESTART: 192.0.2.9.", r.stderr)

    def test_an_inherited_deadline_never_reaches_the_firewall_reads(self) -> None:
        """Seat C T7 note: hub_run treats any non-empty _HUB_F2B_DEADLINE as a
        live deadline, so one inherited from the environment made every table
        read outside the proof return 124 and main() refuse. The installer
        unsets it before anything else runs."""
        prologue = SOURCE[: SOURCE.index("\n# M-6:")]
        self.assertLess(SOURCE.find("\nunset _HUB_F2B_DEADLINE\n"), SOURCE.index("() {"))
        write_fake(self.bin, "fake-save", self.ruleset(self.HUB_IN, self.F2B))
        script = f"""
{prologue}
{STUBS}
IPTABLES_SAVE_BIN={str(self.bin / 'fake-save')!r}
{optional_functions(*FW_FUNCS)}
hub_run true && echo "hub_run ok"
hub_filter_chain_state WINVPN-HUB-INPUT
"""
        r = run(script, env={"PATH": f"{self.bin}:{os.environ.get('PATH', '')}", "_HUB_F2B_DEADLINE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["hub_run", "ok", "present"])

    def test_restart_proof_fails_when_the_jail_status_is_unreadable(self) -> None:
        body = self.ruleset(self.HUB_IN, self.F2B)
        r = self.prove_restart([body], None, seconds=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fail2ban-client status sshd failed", r.stderr)
        r = self.prove_restart([body], "Status for the jail: sshd", seconds=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no single 'Banned IP list:' line", r.stderr)

    def test_fail2ban_restart_is_followed_by_the_jump_proof(self) -> None:
        helper = function_definition("write_hub_fail2ban_config")
        body = [l.strip() for l in helper.splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(body[-2], 'hub_f2b_prove_restart "${bans_before}" "${actionstart_stamp}" "${traversal}"')
        restart_at = helper.index("systemctl restart fail2ban")
        # N-13, Turn 8: the snapshot carries end times (hub_f2b_bans_before).
        self.assertLess(helper.index('bans_before="$(hub_f2b_bans_before)"'), restart_at)
        self.assertNotIn("f2b_status_before", helper)
        self.assertLess(helper.index('rm -f -- "${actionstart_stamp}"'), restart_at)
        self.assertLess(helper.index("wait_for_fail2ban"), helper.index('hub_f2b_prove_restart "${bans_before}"'))

    def test_actionstart_writes_its_stamp_last_and_actionstop_removes_it(self) -> None:
        action = between("cat > /etc/fail2ban/action.d/wins-iptables-hub.conf <<'EOF'", "\nEOF\n")
        start = action[action.index("actionstart = "):action.index("actionstop = ")]
        self.assertIn("&& mkdir -p /run/winsvpn-fail2ban && : > /run/winsvpn-fail2ban/<name>.actionstart", start)
        self.assertTrue(start.rstrip().endswith(": > /run/winsvpn-fail2ban/<name>.actionstart"), start)
        stop = action[action.index("actionstop = "):action.index("actioncheck = ")]
        self.assertIn("rm -f /run/winsvpn-fail2ban/<name>.actionstart", stop)
        self.assertEqual(
            function_definition("write_hub_fail2ban_config").count("actionstart_stamp=/run/winsvpn-fail2ban/sshd.actionstart"), 1
        )

    def test_write_iptables_touches_only_the_sandbox(self) -> None:
        """Sol T4 N-2: persistence and IPv6 go to fakes and a private dir."""
        self.emitted_input_rules(self.ADMIN)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-1500:])
        self.assertTrue((self.rules_dir / "rules.v4").exists())
        log = self.host_log.read_text()
        self.assertIn("netfilter-persistent save", log)
        self.assertIn("ip6tables -P INPUT DROP", log)
        body = function_definition("write_iptables")
        code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
        self.assertEqual(code.count("/etc/iptables"), 1, "only the rules_dir default may name /etc/iptables")

    def test_suite_runs_without_the_shared_toolchain_module(self) -> None:
        """Sol T4 N-1: a tree without server/_toolchain.py can run the suite."""
        work = self.tmp / "isolated"
        work.mkdir()
        shutil.copy(Path(__file__), work / "t.py")
        r = subprocess.run(
            [sys.executable, str(work / "t.py"), "PkgCamouflage"],
            cwd=str(work),
            env={"PATH": os.environ.get("PATH", ""), "WINS_FXCPA_INSTALLER": str(INSTALLER)},
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(r.returncode, 0, r.stderr[-1500:])
        self.assertIn("OK", r.stderr)


    def run_actionstart(self, flush_fails: bool) -> tuple[subprocess.CompletedProcess, Path]:
        """Run the shipped actionstart through /bin/sh (fail2ban uses
        shell=True) against a fake kernel holding a stale DROP restored from
        rules.v4 on the recovery source."""
        action = between("cat > /etc/fail2ban/action.d/wins-iptables-hub.conf <<'EOF'", "\nEOF\n")
        lines, grab = [], False
        for line in action.splitlines():
            if line.startswith("actionstart = "):
                grab = True
                lines.append(line[len("actionstart = "):])
                continue
            if grab and line.startswith((" ", "\t")):
                lines.append(line.strip())
                continue
            grab = False
        cmd = "\n".join(lines).replace("<name>", "sshd").replace("<protocol>", "tcp").replace("<port>", "ssh")
        # Sandbox: the stamp directory goes to the private temp dir.
        self.stamp_dir = self.tmp / "run-winsvpn-fail2ban"
        assert cmd.count("/run/winsvpn-fail2ban") >= 1, cmd
        cmd = cmd.replace("/run/winsvpn-fail2ban", str(self.stamp_dir))
        kstate = self.tmp / "kernel.txt"
        kstate.write_text("chain f2b-sshd\n-A f2b-sshd -s 100.64.1.1/32 -j DROP\n", encoding="utf-8")
        write_fake(
            self.bin,
            "iptables",
            f"""
            k={str(kstate)!r}
            [[ "$1" == -w ]] && shift 2
            case "$1" in
              -N) grep -qx "chain $2" "$k" && exit 1; echo "chain $2" >> "$k"; exit 0 ;;
              -F) {"exit 4" if flush_fails else ""}
                  grep -v -- "^-A $2 " "$k" > "$k.t"; mv "$k.t" "$k"; exit 0 ;;
              -C) grep -qx -- "jump $2 $*" "$k" ;;
              -I) echo "jump $2 -C $2 ${{*:4}}" >> "$k"; echo "inserted at $3" >> "$k"; exit 0 ;;
              *) exit 1 ;;
            esac
            """,
        )
        r = subprocess.run(
            ["/bin/sh", "-c", cmd],
            env={"PATH": f"{self.bin}:/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=60,
        )
        return r, kstate

    def test_actionstart_flushes_a_restored_stale_ban_then_links(self) -> None:
        """OI-CPA-10A: a DROP restored from rules.v4 must not survive start."""
        r, kstate = self.run_actionstart(flush_fails=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        state = kstate.read_text()
        self.assertNotIn("100.64.1.1/32", state)
        self.assertIn("inserted at 1", state)

    def test_actionstart_fails_when_the_flush_fails(self) -> None:
        r, kstate = self.run_actionstart(flush_fails=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("inserted at", kstate.read_text())

    def test_existing_bans_on_exempt_sources_are_purged_before_commit(self) -> None:
        """SC-1: a ban fail2ban already holds on the deploy source or an admin
        CIDR address must not go live when the jump moves to the top."""
        state, events = self.stateful_f2b()
        self.emitted_input_rules(self.ADMIN)
        log = events.read_text().splitlines() if events.exists() else []
        remaining = state.read_text()
        self.assertNotIn("192.0.2.7/32", remaining, log)
        self.assertNotIn("198.51.100.77/32", remaining, log)
        self.assertIn("100.64.1.1/32", remaining)  # recovery CIDR is not exempt
        self.assertIn("commit", log)
        commit_at = log.index("commit")
        for src in ("192.0.2.7/32", "198.51.100.77/32"):
            self.assertIn(f"delete -s {src} -j DROP", log)
            self.assertLess(log.index(f"delete -s {src} -j DROP"), commit_at)
        self.assertIn("unban set sshd unbanip 192.0.2.7", log)
        self.assertIn("unban set sshd unbanip 198.51.100.77", log)
        self.assertEqual(sum(l.startswith("unban") for l in log), 2, log)
        self.assertNotIn("delete -s 100.64.1.1/32 -j DROP", log)

    def test_unreadable_ban_table_refuses_the_commit(self) -> None:
        """OI-CPA-2 T3: a failed read is UNKNOWN, never 'no bans'."""
        state, events = self.stateful_f2b(save_always_fail=True)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists(), "committed a firewall with the ban table unread")
        self.assertNotEqual(self.last.returncode, 0)
        self.assertIn("Refusing to apply the hub firewall", self.last.stderr)
        self.assertIn("192.0.2.7/32", state.read_text())

    def test_transient_read_failure_is_retried_to_a_definite_answer(self) -> None:
        """Sol's counterexample: lock contention on the first reads, then clear."""
        state, events = self.stateful_f2b(save_fail_first=2)
        self.emitted_input_rules(self.ADMIN)
        self.assertNotIn("192.0.2.7/32", state.read_text())
        self.assertIn("commit", events.read_text())
        self.assertEqual((self.tmp / "sleeps.log").read_text().count("sleep 2"), 2)

    def test_failed_reread_after_deletion_refuses_the_commit(self) -> None:
        # read 1: f2b-sshd existence, read 2: purge, read 3+: re-read (fails)
        state, events = self.stateful_f2b(save_fail_after=2)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertIn("delete -s 192.0.2.7/32 -j DROP", events.read_text())  # first read worked
        self.assertFalse(self.capture.exists(), "committed without re-verifying the ban table")
        self.assertNotEqual(self.last.returncode, 0)

    def test_unreadable_table_at_purge_time_refuses_the_commit(self) -> None:
        """The chain-state read works, the purge's own first read fails."""
        state, events = self.stateful_f2b(save_fail_after=1)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists(), "committed with the ban table unread at purge time")
        self.assertNotEqual(self.last.returncode, 0)
        self.assertIn("192.0.2.7/32", state.read_text())

    def test_unknown_f2b_chain_state_refuses_the_transaction(self) -> None:
        """Sol N-1: every chain-state attempt fails, later reads would work."""
        state, events = self.stateful_f2b(save_fail_first=3)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists(), "committed without knowing whether f2b-sshd exists")
        self.assertNotEqual(self.last.returncode, 0)
        self.assertIn("cannot tell whether the f2b-sshd chain exists", self.last.stderr)

    def test_surviving_exempt_ban_refuses_the_commit(self) -> None:
        state, events = self.stateful_f2b(delete_fails=True)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists(), "committed with an exempt DROP still present")
        self.assertNotEqual(self.last.returncode, 0)
        self.assertIn("survived deletion", self.last.stderr)

    def test_malformed_ruleset_is_unknown_not_empty(self) -> None:
        state, events = self.stateful_f2b()
        write_fake(self.bin, "fake-save", 'echo "# Generated by nothing useful"\n')
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists())
        self.assertNotEqual(self.last.returncode, 0)

    def assert_unknown_output_refuses(self, body: str) -> None:
        state, events = self.stateful_f2b()
        write_fake(self.bin, "fake-save", body)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists(), body)
        self.assertNotEqual(self.last.returncode, 0, body)
        self.assertIn("192.0.2.7/32", state.read_text(), body)

    def test_commit_without_table_header_is_unknown(self) -> None:
        """Sol T3: 'garbage COMMIT' was read as a definite absence."""
        self.assert_unknown_output_refuses('echo "garbage COMMIT"\n')
        self.assert_unknown_output_refuses('echo garbage; echo COMMIT\n')
        # garbage outside any table, next to an otherwise valid table
        self.assert_unknown_output_refuses(
            'echo "garbage COMMIT"; echo "*filter"; echo ":INPUT DROP [0:0]"; echo COMMIT\n'
        )

    def test_filter_section_with_non_rule_lines_is_unknown(self) -> None:
        """Sol T3: '*filter / this is not a ruleset / COMMIT' was accepted."""
        self.assert_unknown_output_refuses('echo "*filter"; echo "this is not a ruleset"; echo COMMIT\n')
        self.assert_unknown_output_refuses('echo "*filter"; echo "-A undeclared -j DROP"; echo COMMIT\n')
        self.assert_unknown_output_refuses('echo "*filter"; echo ":INPUT ACCEPT [0:0]"\n')

    def test_legacy_tables_warning_on_stderr_is_unknown(self) -> None:
        """Seat C N-1: nft save prints nothing, exits 0, and warns on stderr."""
        state, events = self.stateful_f2b()
        write_fake(
            self.bin,
            "fake-save",
            'echo "# Warning: iptables-legacy tables present, use iptables-legacy-save to see them" >&2\nexit 0\n',
        )
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertFalse(self.capture.exists())
        self.assertNotEqual(self.last.returncode, 0)
        self.assertIn("iptables-legacy tables present", self.last.stderr)
        self.assertIn("Recovery:", self.last.stderr)

    def chain_state(self, save_body: str) -> subprocess.CompletedProcess:
        write_fake(self.bin, "fake-save", save_body)
        script = f"""
set -Eeuo pipefail
{STUBS}
sleep() {{ :; }}
IPTABLES_SAVE_BIN={str(self.bin / 'fake-save')!r}
{optional_functions(*FW_FUNCS)}
hub_filter_chain_state WINVPN-HUB-INPUT
"""
        return run(script)

    def assert_unknown(self, save_body: str) -> None:
        r = self.chain_state(save_body)
        self.assertNotEqual(r.returncode, 0, f"{save_body!r} -> {r.stdout!r}")
        self.assertNotIn("absent", r.stdout, save_body)
        self.assertNotIn("present", r.stdout, save_body)

    def test_malformed_rule_bodies_are_unknown(self) -> None:
        """Sol T4 OI-CPA-2: '-A INPUT garbage' inside a declared table."""
        for rule in (
            "-A INPUT garbage",
            "-A INPUT -s notanip -j DROP",
            "-A INPUT -s 2001:db8::1/128 -j DROP",
            "-A INPUT -j DROP -j ACCEPT",
            "-A INPUT -p tcp !",
            "-A INPUT ! garbage",
            "-A INPUT -j",
            "-A INPUT -m",
            '-A INPUT -m comment --comment "unbalanced -j DROP',
            "-A INPUT -p tcp --dport 22 extra -x -j DROP",
            "-A INPUT",
        ):
            self.assert_unknown(self.ruleset(self.HUB_IN, rule))

    def test_option_arguments_are_checked(self) -> None:
        """Sol T5 OI-CPA-2: the validator must know each option's arity."""
        for rule in (
            "-A INPUT -p tcp -m tcp --dport -j DROP",
            "-A INPUT -p tcp -m tcp --dport 22 garbage -j DROP",
            "-A INPUT -p tcp -m tcp --made-up-option 1 -j DROP",
            "-A INPUT -p 999 -j DROP",
            "-A INPUT -p tcp -m tcp --dport 70000 -j DROP",
            "-A INPUT -p tcp -m tcp --tcp-flags SYN -j DROP",
            "-A INPUT -m conntrack --ctstate -j ACCEPT",
            "-A INPUT -j LOG --log-prefix",
            "-A INPUT -p tcp -j TPROXY --on-port",
            "-A INPUT -m connbytes --connbytes -j DROP",
            "-A INPUT -m cpu --cpu -j DROP",
            "-A INPUT -j SET --add-set blocklist",
            "-A INPUT -m ah --ahspi -j DROP",
            "-A INPUT -p tcp -m tcp --dport 22:99999 -j DROP",
            "-A INPUT -p tcp -m multiport --dports 22,,80 -j DROP",
            "-A INPUT -p tcp -m tcp --sport 1:2:3 -j DROP",
            # a missing argument must not swallow the next option, even one that takes none
            "-A INPUT -m recent --name --set -j DROP",
        ):
            self.assert_unknown(self.ruleset(self.HUB_IN, rule))

    def test_values_outside_the_iptables_grammar_are_unknown(self) -> None:
        """Sol N-11 (Turn 6): invalid TCP flags, invalid connection states and
        a comma list on a single-port option were accepted, and a filter table
        holding the first one answered "absent". The extensions refuse to load
        such rules (iptables 1.8.10), so a save holding one is not a real
        save: UNKNOWN."""
        for rule in (
            "-A INPUT -p tcp -m tcp --tcp-flags NOT_A_FLAG ALSO_INVALID -j DROP",
            "-A INPUT -p tcp -m tcp --tcp-flags SYN,ACK BOGUS -j DROP",
            "-A INPUT -p tcp -m tcp --tcp-flags SYN,,ACK SYN -j DROP",
            "-A INPUT -p tcp -m tcp --dport 80,22 -j DROP",
            "-A INPUT -p tcp -m tcp --sport 1,2 -j DROP",
            "-A INPUT -p udp -m udp --destination-port 53,54 -j DROP",
            "-A INPUT -p tcp -m tcp --source-port 1:2,3 -j DROP",
            "-A INPUT -m conntrack --ctstate NOT_A_STATE -j DROP",
            "-A INPUT -m conntrack --ctstate NEW,BOGUS -j ACCEPT",
            "-A INPUT -m state --state SNAT -j ACCEPT",
            "-A INPUT -m state --state NEW, -j ACCEPT",
        ):
            self.assert_unknown(self.ruleset(self.HUB_IN, rule))
        # Sol's exact case: no hub chain declared, so the old answer was "absent".
        self.assert_unknown(
            "cat <<'SAVE'\n*filter\n:INPUT DROP [0:0]\n"
            "-A INPUT -p tcp -m tcp --tcp-flags NOT_A_FLAG ALSO_INVALID -j DROP\nCOMMIT\nSAVE\n"
        )

    def test_values_inside_the_iptables_grammar_are_definite(self) -> None:
        for rule in (
            "-A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j DROP",
            "-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP",
            "-A INPUT -m conntrack --ctstate INVALID,NEW,RELATED,ESTABLISHED,UNTRACKED,SNAT,DNAT -j ACCEPT",
            "-A INPUT -m conntrack ! --ctstate NEW -j ACCEPT",
            "-A INPUT -m state --state INVALID,NEW,RELATED,ESTABLISHED,UNTRACKED -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 22:80 -j ACCEPT",
            "-A INPUT -p tcp -m multiport --dports 80,22 -j ACCEPT",
            "-A INPUT -p tcp -m multiport --sports 1:2,3 -j ACCEPT",
        ):
            r = self.chain_state(self.ruleset(self.HUB_IN, rule))
            self.assertEqual(r.returncode, 0, f"{rule}: {r.stderr}")
            self.assertEqual(r.stdout.strip(), "present", rule)

    # N-12 (Seat C T6 and T7): every save line below was printed by the real
    # iptables-save and iptables-legacy-save 1.8.10 on colima-l80 (Turn 8,
    # private netns), the two backends giving the same lines.
    TARGET_SAVE_LINES = """
mangle -A POSTROUTING -o virbr0 -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill
mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-remove
mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-cwr 0
mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-ece 0
mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-cwr 1
mangle -A PREROUTING -j ECN --ecn-ip-ect 2
mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-ece 0 --ecn-tcp-cwr 0 --ecn-ip-ect 1
mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-ece 1 --ecn-tcp-cwr 1 --ecn-ip-ect 3
mangle -A PREROUTING -j HMARK --hmark-src-prefix 32 --hmark-dst-prefix 32 --hmark-rnd 0x00000001 --hmark-mod 4
mangle -A PREROUTING -j HMARK --hmark-src-prefix 32 --hmark-dst-prefix 32 --hmark-sport-mask 0xffff --hmark-dport-mask 0xffff --hmark-proto-mask 0xffff --hmark-rnd 0x00000007 --hmark-mod 8 --hmark-offset 100
mangle -A PREROUTING -j HMARK --hmark-src-prefix 32 --hmark-dst-prefix 32 --hmark-spi-mask 0xffffffff --hmark-rnd 0x00000007 --hmark-mod 8
mangle -A PREROUTING -j HMARK --hmark-rnd 0x00000005 --hmark-mod 2 --hmark-tuple ct
mangle -A PREROUTING -j HMARK --hmark-sport-mask 0xffff --hmark-dport-mask 0x00ff --hmark-proto-mask 0xff --hmark-rnd 0x00000001 --hmark-mod 3
mangle -A PREROUTING -j HMARK --hmark-spi-mask 0xffffffff --hmark-rnd 0x00000001 --hmark-mod 3
mangle -A PREROUTING -j HMARK --hmark-sport 0x0001 --hmark-dport 0x0002 --hmark-rnd 0x00000001 --hmark-mod 5
mangle -A PREROUTING -j HMARK --hmark-spi 0x00000003 --hmark-rnd 0x00000001 --hmark-mod 5
filter -A INPUT -j AUDIT --type accept
filter -A INPUT -j AUDIT --type drop
filter -A INPUT -j AUDIT --type reject
"""

    def target_save(self, entries: list[str]) -> str:
        builtin = {"mangle": ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"),
                   "filter": ("INPUT", "FORWARD", "OUTPUT")}
        by_table: dict[str, list[str]] = {}
        for entry in entries:
            table, line = entry.split(" ", 1)
            by_table.setdefault(table, []).append(line)
        lines: list[str] = []
        for table, rules in by_table.items():
            lines += [f"*{table}"] + [f":{c} ACCEPT [0:0]" for c in builtin[table]] + rules + ["COMMIT"]
        return "cat <<'SAVE'\n" + "\n".join(lines) + "\nSAVE\n"

    def test_checksum_ecn_audit_hmark_save_forms_validate(self) -> None:
        """N-12: these targets were missing from the option table, so a host
        carrying one (libvirt installs the CHECKSUM line) could not deploy.
        The ECN target saves --ecn-tcp-cwr and --ecn-tcp-ece WITH a value,
        while the ecn match takes them as flags; both forms must stay
        definite."""
        entries = self.TARGET_SAVE_LINES.strip().splitlines()
        self.assertEqual(len(entries), 19)
        for entry in entries:
            r = self.chain_state(self.target_save([entry]))
            self.assertEqual(r.returncode, 0, f"{entry}: {r.stderr}")
        r = self.chain_state(self.target_save(entries + ["filter -A INPUT -p tcp -m ecn --ecn-tcp-cwr -j DROP"]))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_checksum_ecn_audit_hmark_outside_their_grammar_are_unknown(self) -> None:
        """N-12, fail closed outside the grammar: an AUDIT type iptables never
        saves, an HMARK tuple word it does not know, a missing value, a
        surplus token, a value on a flag, and the ECN target's value form on
        the ecn match."""
        for entry in (
            "filter -A INPUT -j AUDIT --type ACCEPT",
            "filter -A INPUT -j AUDIT --type bogus",
            "filter -A INPUT -j AUDIT --type",
            "mangle -A PREROUTING -j HMARK --hmark-tuple src,bogus --hmark-rnd 0x00000001 --hmark-mod 2",
            "mangle -A PREROUTING -j HMARK --hmark-rnd 0x00000001 --hmark-mod",
            "mangle -A POSTROUTING -o virbr0 -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill 1",
            "mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-remove 1",
            "mangle -A PREROUTING -p tcp -j ECN --ecn-tcp-cwr",
            "filter -A INPUT -p tcp -m ecn --ecn-tcp-cwr 1 -j DROP",
        ):
            self.assert_unknown(self.target_save([entry]))

    def test_extension_options_seen_on_real_hosts_are_accepted(self) -> None:
        """Turn 6: an exact arity table must not refuse a normal host. These
        are IPv4 iptables 1.8.10 extension options, a hand-picked set on top of
        the captured real saves in test_every_real_iptables_1_8_10_save_line_validates."""
        for rule in (
            "-A INPUT -p tcp -j TPROXY --on-port 3128 --on-ip 10.0.0.1 --tproxy-mark 0x1/0x1",
            "-A INPUT -m connbytes --connbytes 1:2 --connbytes-dir both --connbytes-mode bytes -j DROP",
            "-A INPUT -m ipvs --ipvs -j ACCEPT",
            "-A INPUT -j SET --add-set blocklist src --exist",
            "-A INPUT -m rpfilter --loose --validmark --invert -j DROP",
            "-A INPUT -p tcp -m socket --transparent --nowildcard --restore-skmark -j ACCEPT",
            "-A INPUT -p ah -m ah --ahspi 100:200 -j DROP",
            "-A INPUT -m cpu --cpu 1 -j ACCEPT",
            "-A INPUT -p tcp -m osf --genre Linux --ttl 2 --log 1 -j ACCEPT",
            "-A INPUT -j NFQUEUE --queue-balance 0:3 --queue-bypass --queue-cpu-fanout",
            "-A INPUT -p tcp -m tcp --dport 22 -m recent --set --name SSH --rsource -j ACCEPT",
            "-A INPUT -m set --match-set allow src -j ACCEPT",
            "-A INPUT -m set ! --match-set deny src -j ACCEPT",
            "-A INPUT -p tcp -m multiport --dports 22,80:90 -m comment --comment \"ssh and web\" -j ACCEPT",
        ):
            r = self.chain_state(self.ruleset(self.HUB_IN, rule))
            self.assertEqual(r.returncode, 0, f"{rule}: {r.stderr}")

    # Real iptables 1.8.10 output. probe_t5_live.sh section H added each rule
    # to a private netns on colima-l80 (Ubuntu 24.04, kernel 6.8) and kept the
    # line iptables-save printed for it: TABLE, then the -A line as saved. The
    # nf_tables and the legacy printer gave the same 86 lines.
    REAL_SAVE_LINES = r'''
filter -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
filter -A INPUT -p tcp -m multiport --dports 22,80:90 -j ACCEPT
filter -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP
filter -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
filter -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
filter -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED --ctdir ORIGINAL -j ACCEPT
filter -A INPUT -m state --state NEW -j ACCEPT
filter -A INPUT -m limit --limit 5/min --limit-burst 10 -j ACCEPT
filter -A INPUT -m hashlimit --hashlimit-upto 5/sec --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name hl1 -j ACCEPT
filter -A INPUT -m recent --set --name SSH --mask 255.255.255.255 --rsource
filter -A INPUT -m recent --update --seconds 60 --hitcount 4 --name SSH --mask 255.255.255.255 --rsource -j DROP
filter -A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 24 --connlimit-saddr -j REJECT --reject-with tcp-reset
filter -A INPUT -m comment --comment "x y" -j ACCEPT
filter -A INPUT -m comment --comment -x -j ACCEPT
filter -A INPUT -m comment --comment "it\'s \"odd\" back\\slash" -j ACCEPT
filter -A INPUT -m mark --mark 0x1/0xff -j ACCEPT
filter -A INPUT -m connmark ! --mark 0x1 -j ACCEPT
filter -A OUTPUT -m owner --uid-owner 0 -j ACCEPT
filter -A INPUT -m addrtype --src-type LOCAL --limit-iface-in -j ACCEPT
filter -A INPUT -m iprange --src-range 10.0.0.1-10.0.0.9 -j ACCEPT
filter -A INPUT -m length --length 100:200 -j DROP
filter -A INPUT -m ttl --ttl-eq 64 -j DROP
filter -A INPUT -m tos --tos 0x10/0x3f -j DROP
filter -A INPUT -m dscp --dscp 0x2e -j DROP
filter -A INPUT -m pkttype --pkt-type broadcast -j DROP
filter -A INPUT -m statistic --mode random --probability 0.50000000000 -j DROP
filter -A INPUT -m statistic --mode nth --every 3 --packet 0 -j DROP
filter -A INPUT -m time --timestart 08:00:00 --timestop 17:00:00 --weekdays Mon,Tue --datestop 2038-01-19T03:14:07 --kerneltz -j ACCEPT
filter -A INPUT -p tcp -m string --string "abc" --algo bm -j DROP
filter -A INPUT -m u32 --u32 "0x0>>0x16&0x3c@0xc>>0x1a=0x1" -j DROP
filter -A INPUT -m cpu --cpu 1 -j ACCEPT
filter -A INPUT -m connbytes --connbytes 1:2 --connbytes-mode bytes --connbytes-dir both -j DROP
filter -A INPUT -m helper --helper ftp -j ACCEPT
filter -A INPUT -p tcp -m socket --transparent -j ACCEPT
filter -A INPUT -m policy --dir in --pol ipsec --strict --reqid 1 --proto esp -j ACCEPT
filter -A INPUT -p ah -m ah --ahspi 100:200 -j DROP
filter -A INPUT -p esp -m esp --espspi 100 -j DROP
filter -A INPUT -p gre -j ACCEPT
filter -A INPUT ! -i lo -j DROP
filter -A INPUT -i wg+ -j ACCEPT
filter -A INPUT ! -s 10.0.0.0/8 -j DROP
filter -A INPUT -f -j DROP
filter -A INPUT -j LOG --log-prefix "it\'s \"odd\" " --log-tcp-sequence --log-ip-options
filter -A INPUT -j NFLOG --nflog-prefix x --nflog-group 5 --nflog-threshold 10
filter -A INPUT -p tcp -j NFQUEUE --queue-balance 0:3 --queue-bypass
filter -A INPUT -p tcp -j NFQUEUE --queue-balance 0:3 --queue-cpu-fanout
filter -A INPUT -j REJECT --reject-with icmp-port-unreachable
filter -A INPUT -p udp -m udp --sport 53 -j ACCEPT
filter -A INPUT -p sctp -m sctp --dport 5000 --chunk-types any DATA:Be -j ACCEPT
filter -A INPUT -p dccp -m dccp --dport 5000 --dccp-types REQUEST -j ACCEPT
filter -A INPUT -m ecn --ecn-ip-ect 1 -j DROP
filter -A INPUT -m devgroup --src-group 0x1 -j ACCEPT
filter -A INPUT -m realm --realm 0x1 -j ACCEPT
filter -A INPUT -m quota --quota 1000 -j ACCEPT
filter -A INPUT -m bpf --bytecode "1,6 0 0 1" -j ACCEPT
filter -A FORWARD -m physdev --physdev-in eth0 -j ACCEPT
mangle -A PREROUTING -j MARK --set-xmark 0x1/0xffffffff
mangle -A PREROUTING -j CONNMARK --save-mark --nfmask 0xff --ctmask 0xff
mangle -A PREROUTING -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
mangle -A PREROUTING -j TOS --set-tos 0x10/0x3f
mangle -A PREROUTING -j DSCP --set-dscp 0x2e
mangle -A PREROUTING -j TTL --ttl-set 64
mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
mangle -A PREROUTING -p tcp -j TPROXY --on-port 3128 --on-ip 10.0.0.1 --tproxy-mark 0x1/0x1
mangle -A POSTROUTING -j CLASSIFY --set-class 0001:0010
raw -A PREROUTING -j CT --notrack
raw -A PREROUTING -p tcp -m tcp --dport 21 -j CT --helper ftp
raw -A PREROUTING -j CT --zone 5
nat -A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80
nat -A POSTROUTING -j SNAT --to-source 10.0.0.1 --random-fully
nat -A POSTROUTING -p tcp -j MASQUERADE --to-ports 1024-2048 --random
nat -A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128
nat -A POSTROUTING -j SNAT --to-source 10.0.0.1-10.0.0.9 --persistent
filter -A INPUT -m connlabel --label "1" -j ACCEPT
filter -A INPUT -m ipvs --vproto 6 --vaddr 10.0.0.1 --vport 80 -j ACCEPT
filter -A INPUT -m cluster --cluster-local-nodemask 0x00000001 --cluster-total-nodes 2 --cluster-hash-seed 0x00000001 -j ACCEPT
filter -A INPUT -p tcp -m tcpmss --mss 1:1400 -j DROP
filter -A INPUT -p tcp -m osf --genre Linux --ttl 2 --log 1 -j ACCEPT
filter -A INPUT -p tcp -m connlimit --connlimit-upto 5 --connlimit-mask 32 --connlimit-daddr -j ACCEPT
filter -A INPUT -p tcp -m ecn --ecn-tcp-ece --ecn-tcp-cwr -j DROP
filter -A INPUT -p ipcomp -m ipcomp --ipcompspi 100 -j DROP
mangle -A FORWARD -j DSCP --set-dscp 0x2e
mangle -A PREROUTING -j CONNSECMARK --save
mangle -A PREROUTING -j TEE --gateway 10.0.0.2
nat -A POSTROUTING -d 10.2.0.0/16 -j NETMAP --to 10.1.0.0/16
'''

    def test_every_real_iptables_1_8_10_save_line_validates(self) -> None:
        """Turn 6: the option table is checked against what the real printer
        writes, not only against hand-made rules."""
        builtin = {
            "raw": ("PREROUTING", "OUTPUT"),
            "mangle": ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"),
            "filter": ("INPUT", "FORWARD", "OUTPUT"),
            "nat": ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"),
        }
        by_table: dict[str, list[str]] = {}
        for entry in self.REAL_SAVE_LINES.strip().splitlines():
            table, line = entry.split(" ", 1)
            by_table.setdefault(table, []).append(line)
        self.assertEqual(sorted(by_table), ["filter", "mangle", "nat", "raw"])
        self.assertEqual(sum(len(v) for v in by_table.values()), 86)
        lines: list[str] = []
        for table, rules in by_table.items():
            chains = sorted({r.split()[1] for r in rules} | set(builtin[table]))
            lines += [f"*{table}"] + [f":{c} ACCEPT [0:0]" for c in chains] + rules + ["COMMIT"]
        r = self.chain_state("cat <<'SAVE'\n" + "\n".join(lines) + "\nSAVE\n")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_free_text_arguments_may_look_like_options(self) -> None:
        """Seat C T5 N-9: iptables prints a plain comment unquoted, so
        '--comment -x' and '--comment --allow-ssh' are legal saves."""
        for rule in (
            "-A INPUT -m comment --comment -x -j RETURN",
            "-A INPUT -m comment --comment --allow-ssh -j RETURN",
            "-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
            "-A INPUT -p 47 -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport ssh -j ACCEPT",
        ):
            r = self.chain_state(self.ruleset(self.HUB_IN, rule))
            self.assertEqual(r.returncode, 0, f"{rule}: {r.stderr}")

    def test_refusal_names_the_rejected_line(self) -> None:
        """Seat C T5 N-9: an operator must be able to find the cause."""
        r = self.chain_state(self.ruleset(self.HUB_IN, "-A INPUT -s 10.0.0.0/255.0.255.0 -j RETURN"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("first rejected line: -A INPUT -s 10.0.0.0/255.0.255.0 -j RETURN", r.stderr)

    def test_bad_chain_declarations_are_unknown(self) -> None:
        for decls in (
            ["*filter", ":INPUT BOGUS [0:0]", "COMMIT"],
            ["*filter", ":f2b-sshd ACCEPT [0:0]", "COMMIT"],
            ["*filter", ":INPUT - [0:0]", "COMMIT"],
            ["*filter", ":INPUT DROP [0:0]", ":INPUT DROP [0:0]", "COMMIT"],
            ["*filter", ":INPUT DROP [0:0]", "-A INPUT -j DROP", ":LATE - [0:0]", "COMMIT"],
            ["*filter", ":INPUT DROP [x:0]", "COMMIT"],
            ["*bogus", ":INPUT DROP [0:0]", "COMMIT"],
            ["*filter", ":INPUT DROP [0:0]", "", "COMMIT"],
        ):
            self.assert_unknown("cat <<'SAVE'\n" + "\n".join(decls) + "\nSAVE\n")

    def test_whitespace_is_not_emptiness(self) -> None:
        """Sol T4: whitespace-only stdout and stderr were accepted."""
        self.assert_unknown("printf '  \\n'\n")
        self.assert_unknown("printf '\\n'\n")
        self.assert_unknown("printf ' ' >&2\n")
        good = self.ruleset(self.HUB_IN).replace("cat <<'SAVE'", "printf ' \\n' >&2; cat <<'SAVE'", 1)
        self.assert_unknown(good)

    def test_only_generated_and_completed_comments_are_accepted(self) -> None:
        """Seat C N-5: the 'incompatible table' comment is not a definite answer."""
        nat = ["*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]", "COMMIT"]
        for extra in (
            ["# Table `filter' is incompatible, use 'nft' tool."],
            ["# hello"],
        ):
            self.assert_unknown("cat <<'SAVE'\n" + "\n".join(extra + nat) + "\nSAVE\n")
        inside = ["*filter", ":INPUT DROP [0:0]", "# Generated by inside", "COMMIT"]
        self.assert_unknown("cat <<'SAVE'\n" + "\n".join(inside) + "\nSAVE\n")

    def test_a_rich_real_world_ruleset_is_definite(self) -> None:
        """The strict grammar must not refuse a normal hub (Seat C T4 fixtures)."""
        lines = [
            "# Generated by iptables-nft-save v1.8.10 (nf_tables) on Wed Sep 30 10:00:00 2026",
            "*raw", ":PREROUTING ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", "COMMIT",
            "# Completed on Wed Sep 30 10:00:00 2026",
            "# Generated by iptables-nft-save v1.8.10 (nf_tables) on Wed Sep 30 10:00:00 2026",
            "*mangle", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
            ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]",
            "-A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j TCPMSS --clamp-mss-to-pmtu",
            "COMMIT",
            "*filter", ":INPUT DROP [1211:88120]", ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [5:300]",
            ":DOCKER-USER - [0:0]", ":WINVPN-HUB-INPUT - [0:0]", ":f2b-sshd - [0:0]", ":ufw-user-input - [0:0]",
            "-A INPUT -j WINVPN-HUB-INPUT",
            "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 22 -j f2b-sshd",
            "-A WINVPN-HUB-INPUT -i lo -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0 --queue-bypass",
            "-A WINVPN-HUB-INPUT -i lo -j ACCEPT",
            "-A WINVPN-HUB-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            '-A WINVPN-HUB-INPUT -s 203.0.113.4/32 -p tcp -m tcp --dport 22 -m comment --comment "admin \\"x\\" it\'s" -j ACCEPT',
            "-A WINVPN-HUB-INPUT ! -s 10.0.0.0/8 -m set --match-set blocklist src -j DROP",
            '-A WINVPN-HUB-INPUT -p tcp -m string --string "GET /admin" --algo bm -j LOG --log-prefix "[WINS-DROP] "',
            "-A WINVPN-HUB-INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT",
            "-A WINVPN-HUB-INPUT -j DROP",
            "-A f2b-sshd -s 192.0.2.9/32 -j REJECT --reject-with icmp-port-unreachable",
            "-A f2b-sshd -j RETURN",
            "-A DOCKER-USER -i eth+ -o docker0 -j RETURN",
            "COMMIT",
            "*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]",
            "-A PREROUTING -d 198.51.100.1/32 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.8.0.2:443",
            "-A POSTROUTING -s 10.8.0.0/16 -o eth0 -j MASQUERADE",
            "COMMIT",
            "# Completed on Wed Sep 30 10:00:00 2026",
        ]
        r = self.chain_state("cat <<'SAVE'\n" + "\n".join(lines) + "\nSAVE\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "present")

    def test_well_formed_ruleset_without_filter_table_is_absent(self) -> None:
        """Seat C N-3: a nat-only ruleset definitely holds no hub chains."""
        write_fake(
            self.bin,
            "fake-save",
            'echo "# Generated by fake"; echo "*nat"; echo ":PREROUTING ACCEPT [0:0]"; '
            'echo "-A PREROUTING -j RETURN"; echo COMMIT\n',
        )
        rules = self.emitted_input_rules(self.ADMIN)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-1500:])
        self.assertFalse(any(r.endswith("-j f2b-sshd") for r in rules), rules)

    def test_save_error_text_reaches_the_operator(self) -> None:
        state, events = self.stateful_f2b(save_always_fail=True)
        self.emitted_input_rules(self.ADMIN, require_commit=False)
        self.assertIn("Permission denied (you must be root)", self.last.stderr)


    def test_pristine_host_with_no_tables_still_deploys(self) -> None:
        # Empty iptables-save output (no tables loaded) is a definite "absent".
        self.emitted_input_rules(self.ADMIN)
        self.assertEqual(self.last.returncode, 0, self.last.stderr[-1500:])

    def test_unban_failure_is_a_warning_once_the_kernel_rule_is_gone(self) -> None:
        state, events = self.stateful_f2b(unban_fails=True)
        self.emitted_input_rules(self.ADMIN)
        self.assertNotIn("192.0.2.7/32", state.read_text())
        self.assertIn("commit", events.read_text())
        self.assertIn("could not unban", self.last.stderr)

    def main_step_log(self, chain_exists: bool | None, save_body: str | None = None, expect_rc0: bool = True) -> list[str]:
        """Run the real main() --deploy with every step stubbed to log its name."""
        body = function_definition("main")
        builtins = {
            "local", "case", "esac", "if", "then", "fi", "else", "elif", "for", "do",
            "done", "echo", "return", "exit", "source", "log", "warn", "err", "while",
        }
        steps = sorted(
            {m for m in re.findall(r"^\s+([a-z_][a-z0-9_]*)\b", body, re.M)} - builtins
        )
        steps_log = self.tmp / "steps.log"
        self.args_log = self.tmp / "steps.args"
        stubs = "\n".join(
            f'{name}() {{ echo {name} >> {str(steps_log)!r}; echo "{name} $*" >> {str(self.args_log)!r}; }}'
            for name in steps
        )
        env_file = self.tmp / "vpn_auth.env"
        env_file.write_text("", encoding="utf-8")
        write_fake(self.bin, "fail2ban-client", "exit 0\n")
        # A lock-free `iptables -L` probe must not be what decides: it always
        # fails here (xtables lock held), whatever the table holds.
        write_fake(self.bin, "iptables", 'echo "Another app is currently holding the xtables lock" >&2\nexit 4\n')
        if save_body is None:
            save_body = (
                'echo "*filter"; echo ":WINVPN-HUB-INPUT - [0:0]"; echo COMMIT\n'
                if chain_exists
                else "exit 0\n"
            )
        write_fake(self.bin, "fake-save", save_body)
        script = f"""
set -Eeuo pipefail
{STUBS}
{stubs}
sleep() {{ :; }}
IPTABLES_SAVE_BIN={str(self.bin / 'fake-save')!r}
{optional_functions(*FW_FUNCS)}
ENV_FILE={str(env_file)!r}
HIDE_CONTROL_ORIGIN_DEFAULT=1
CONTROL_DISK_ENCRYPTION_EFFECTIVE=substitute
{body}
main --deploy >/dev/null
"""
        r = run(script, env={"PATH": f"{self.bin}:{os.environ.get('PATH', '')}"})
        self.last_main = r
        if expect_rc0:
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return steps_log.read_text().split() if steps_log.exists() else []

    def test_unknown_hub_state_refuses_before_any_firewall_write(self) -> None:
        """OI-CPA-2 T3: an unreadable table is never read as 'fresh host'."""
        for body in ("exit 4\n", 'echo "garbage without a table"\n'):
            steps = self.main_step_log(None, save_body=body, expect_rc0=False)
            self.assertNotEqual(self.last_main.returncode, 0, body)
            self.assertIn("Refusing to change the firewall", self.last_main.stderr)
            self.assertIn("write_env", steps)
            self.assertNotIn("write_iptables", steps)
            self.assertNotIn("write_hub_fail2ban_config", steps)

    def test_rerun_restarts_fail2ban_with_new_ignoreip_before_first_firewall_write(self) -> None:
        steps = self.main_step_log(chain_exists=True)
        self.assertIn("write_hub_fail2ban_config", steps)
        self.assertLess(steps.index("write_hub_fail2ban_config"), steps.index("write_iptables"))
        self.assertLess(steps.index("write_env"), steps.index("write_hub_fail2ban_config"))
        # The firewall order it precedes is not final yet, so its proof must
        # not demand the tcp/22 traversal (hub_f2b_restart_observe).
        self.assertIn("write_hub_fail2ban_config early", self.args_log.read_text().splitlines())

    def test_fresh_host_skips_the_early_restart(self) -> None:
        steps = self.main_step_log(chain_exists=False)
        self.assertNotIn("write_hub_fail2ban_config", steps[: steps.index("write_iptables")])

    def test_ids_install_still_writes_and_restarts_fail2ban(self) -> None:
        body = function_definition("install_control_ids_ips")
        self.assertIn("write_hub_fail2ban_config", body)
        helper = function_definition("write_hub_fail2ban_config")
        at = helper.index('ignore_ips="$(hub_fail2ban_ignoreips)"')
        self.assertLess(at, helper.index("systemctl restart fail2ban"))
        self.assertIn("wait_for_fail2ban", helper)

    def test_action_reinserts_at_position_one(self) -> None:
        action = between("cat > /etc/fail2ban/action.d/wins-iptables-hub.conf <<'EOF'", "\nEOF\n")
        self.assertIn("-I WINVPN-HUB-INPUT 1 -p <protocol>", action)
        self.assertNotRegex(action, r"-I WINVPN-HUB-INPUT [02-9]")

    def ignoreips(self, env: dict) -> list[str]:
        script = f"""
set -Eeuo pipefail
HUB_FAIL2BAN_IGNOREIPS_DEFAULT="127.0.0.1/8 ::1"
HUB_ADMIN_SSH_CIDRS_DEFAULT=""
{function_definition("hub_fail2ban_ignoreips")}
hub_fail2ban_ignoreips
"""
        result = run(script, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.split()

    def test_admin_and_deploy_sources_can_never_ban_themselves(self) -> None:
        got = self.ignoreips(
            {
                "HUB_ADMIN_SSH_CIDRS": "203.0.113.4/32 198.51.100.0/24",
                "SSH_CONNECTION": "192.0.2.7 50000 192.0.2.1 22",
                "HUB_SSH_RECOVERY_CIDR": "100.64.0.0/10",
            }
        )
        for entry in ("127.0.0.1/8", "::1", "203.0.113.4/32", "198.51.100.0/24", "192.0.2.7/32"):
            self.assertIn(entry, got)
        self.assertNotIn("100.64.0.0/10", got)
        self.assertEqual(len(got), len(set(got)))

    def test_ignoreips_without_admin_or_ipv4_deploy_source(self) -> None:
        got = self.ignoreips({"SSH_CONNECTION": "2001:db8::1 50000 2001:db8::2 22"})
        self.assertEqual(got, ["127.0.0.1/8", "::1"])

    def test_jail_uses_the_ignoreip_helper(self) -> None:
        body = function_definition("write_hub_fail2ban_config")
        self.assertIn('ignore_ips="$(hub_fail2ban_ignoreips)"', body)
        self.assertIn("ignoreip = ${ignore_ips}", body)


# --------------------------------------------------------------------------
# IA-CP-03: /pkg/ camouflage
# --------------------------------------------------------------------------


def nginx_locations_snippet() -> str:
    return between("cat > /etc/nginx/snippets/wins-hub-locations.conf <<'EOF'", "\nEOF\n")


def add_headers(block: str) -> dict:
    out = {}
    for line in block.splitlines():
        m = re.match(r"\s*add_header\s+(\S+)\s+(.*?);\s*$", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


class PkgCamouflage(unittest.TestCase):
    """IA-CP-03 (static: no nginx on this host; see packet for live status)."""

    @classmethod
    def setUpClass(cls) -> None:
        snippet = nginx_locations_snippet()
        cls.server_level = add_headers(snippet[: snippet.index("\nlocation ")])
        start = snippet.index("location /pkg/ {")
        cls.pkg = snippet[start : snippet.index("\n}", start) + 2]

    def test_no_second_content_type(self) -> None:
        self.assertNotIn("Content-Type", add_headers(self.pkg))

    def test_type_is_replaced_not_appended(self) -> None:
        self.assertRegex(self.pkg, r"\n\s*types\s*\{\s*\}")
        self.assertRegex(self.pkg, r"\n\s*default_type\s+application/octet-stream;")

    def test_server_level_security_headers_are_repeated(self) -> None:
        self.assertTrue(self.server_level)
        pkg = add_headers(self.pkg)
        for name, values in self.server_level.items():
            self.assertEqual(pkg.get(name), values, name)

    def test_still_an_attachment(self) -> None:
        self.assertIn("Content-Disposition", add_headers(self.pkg))


# --------------------------------------------------------------------------
# IA-CP-04: the Litestream replica target (sftp:// since LSR 2026-10-02) and the postflight barrier
# --------------------------------------------------------------------------


class LitestreamDurability(unittest.TestCase):
    """IA-CP-04."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="fxcpa-ls-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.calls = self.tmp / "calls.log"
        write_fake(
            self.bin,
            "systemctl",
            f"""
            echo "systemctl $*" >> {str(self.calls)!r}
            case "$1" in
              is-enabled) [[ "${{FAKE_LS_ENABLED:-1}}" == 1 ]] ;;
              is-active) [[ "${{FAKE_LS_ACTIVE:-1}}" == 1 ]] ;;
              *) exit 0 ;;
            esac
            """,
        )
        write_fake(
            self.bin,
            "timeout",
            'echo "timeout $*" >> ' + repr(str(self.tmp / "calls.log")) + '\n'
            'while [[ "$1" == -* ]]; do shift 2; done\nshift\nexec "$@"\n',
        )
        self.db = self.tmp / "vpn_users.db"
        self.db.write_text("", encoding="utf-8")
        # LSR (2026-10-02): the gs:// cases became SFTP cases. The client key
        # floor is the one the gs:// credentials file had; the receiver host
        # key is a real ed25519 key; the hub's own host keys live in a private
        # directory so the "not this host" check never reads /etc/ssh.
        self.key = self.tmp / "wins_litestream_ed25519"
        self.local_keys = self.tmp / "etc-ssh"
        self.local_keys.mkdir()
        self.host_key = self.keygen(self.tmp / "receiver_host")

    def keygen(self, path: Path) -> str:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fxcpa", "-f", str(path)],
            check=True, capture_output=True,
        )
        fields = Path(str(path) + ".pub").read_text().split()
        return f"{fields[0]} {fields[1]}"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **extra: str) -> dict:
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "LITESTREAM_SFTP_KEY_PATH": str(self.key),
            "LITESTREAM_LOCAL_SSH_HOST_KEY_DIR": str(self.local_keys),
        }
        env.update(extra)
        return env

    def helpers(self) -> str:
        return optional_functions(
            "litestream_sftp_key_path", "litestream_sftp_key_ok", "litestream_sftp_url_ok",
            "litestream_sftp_url_host_port", "litestream_ssh_public_key_ok",
            "litestream_sftp_host_key_not_local", "control_path_absent", "litestream_replica_target_ok",
            "ensure_litestream_sftp_key", "ensure_litestream_sftp_tunnel_account",
            "litestream_tunnel_dirs_safe", "litestream_tunnel_account_is_managed",
            "end_litestream_sftp_tunnel_sessions", "disable_litestream_sftp_tunnel_account",
        )

    SFTP_URL = "sftp://wins-replica@127.0.0.1:2232/srv/wins-replica/data/hub/vpn_users"

    # --- preflight -----------------------------------------------------------

    def contract(self, **extra: str) -> subprocess.CompletedProcess:
        script = f"""
set -Eeuo pipefail
{STUBS}
DURABILITY_BARRIER_REQUIRED_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT=''
LITESTREAM_SFTP_KEY_PATH_DEFAULT=/root/.ssh/wins_litestream_ed25519
LITESTREAM_SFTP_HOST_KEY_DEFAULT=''
LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY_DEFAULT=''
LITESTREAM_SFTP_TUNNEL_USER_DEFAULT=wins-replica-tunnel
{self.helpers()}
{function_definition("validate_durability_replication_contract")}
validate_durability_replication_contract
"""
        return run(script, env=self.env(**extra))

    def sftp(self, **extra: str) -> subprocess.CompletedProcess:
        values = {"LITESTREAM_REPLICA_URL": self.SFTP_URL, "LITESTREAM_SFTP_HOST_KEY": self.host_key}
        values.update(extra)
        return self.contract(**values)

    def good_key(self, mode: int = 0o600) -> None:
        self.keygen(self.key)
        self.key.chmod(mode)

    def test_preflight_refuses_sftp_without_host_key(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY="")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_preflight_refuses_group_readable_sftp_key(self) -> None:
        self.good_key(0o640)
        r = self.sftp()
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_preflight_refuses_symlinked_sftp_key(self) -> None:
        self.good_key()
        link = self.tmp / "link_key"
        link.symlink_to(self.key)
        r = self.sftp(LITESTREAM_SFTP_KEY_PATH=str(link))
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_preflight_refuses_password_in_sftp_url(self) -> None:
        r = self.sftp(LITESTREAM_REPLICA_URL="sftp://wins-replica:pw@127.0.0.1:2232/srv/wins-replica/data/hub")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_preflight_accepts_good_sftp_replica(self) -> None:
        self.good_key()
        r = self.sftp()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_preflight_refuses_retired_gs_replica(self) -> None:
        r = self.contract(LITESTREAM_REPLICA_URL="gs://bucket/db")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_preflight_only_warns_when_barrier_not_required(self) -> None:
        r = self.sftp(LITESTREAM_SFTP_HOST_KEY="", DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)

    def test_preflight_local_replica_refused_when_required(self) -> None:
        # Reversed (LSR 2026-10-02): this was test_preflight_local_replica_unaffected.
        # A replica on the hub's own disk never met "replicated off this host".
        r = self.contract(LITESTREAM_REPLICA_URL="/var/backups/litestream/vpn_users")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        r = self.contract(LITESTREAM_REPLICA_URL="/var/backups/litestream/vpn_users", DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)

    # --- deploy --------------------------------------------------------------

    def configure(self, **extra: str) -> subprocess.CompletedProcess:
        script = f"""
set -Eeuo pipefail
{STUBS}
DURABILITY_BARRIER_REQUIRED_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT=''
LITESTREAM_SFTP_KEY_PATH_DEFAULT=/root/.ssh/wins_litestream_ed25519
LITESTREAM_SFTP_HOST_KEY_DEFAULT=''
LITESTREAM_SFTP_TUNNEL_PUBLIC_KEY_DEFAULT=''
LITESTREAM_SFTP_TUNNEL_USER_DEFAULT=wins-replica-tunnel
bin=/usr/local/bin/litestream
{self.helpers()}
{function_definition("configure_litestream_replication")}
configure_litestream_replication
"""
        return run(script, env=self.env(**extra))

    def test_deploy_fails_hard_on_unpinned_sftp(self) -> None:
        r = self.configure(LITESTREAM_REPLICA_URL=self.SFTP_URL)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.calls.exists() and "enable" in self.calls.read_text())

    def test_deploy_warns_only_when_barrier_not_required(self) -> None:
        r = self.configure(LITESTREAM_REPLICA_URL=self.SFTP_URL, DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.calls.exists() and "enable" in self.calls.read_text())

    def test_rerun_with_binary_present_still_configures(self) -> None:
        fake_ls = write_fake(self.bin, "litestream", 'echo "v0.5.15"\n')
        record = self.tmp / "configured"
        script = f"""
set -Eeuo pipefail
{STUBS}
LITESTREAM_VERSION_DEFAULT=0.5.15
LITESTREAM_BIN_DEFAULT={str(fake_ls)!r}
LITESTREAM_SHA256_AMD64_DEFAULT={HEX64_A}
LITESTREAM_SHA256_ARM64_DEFAULT={HEX64_A}
{function_definition("litestream_version_supports_barrier")}
{function_definition("install_litestream")}
configure_litestream_replication() {{ echo configure >> {str(record)!r}; }}
litestream_replication_preflight() {{ echo preflight >> {str(record)!r}; }}
install_litestream
"""
        r = run(script, env=self.env())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(record.exists(), "already-installed path skipped configuration")
        self.assertEqual(record.read_text().split(), ["configure", "preflight"])

    # --- postflight ----------------------------------------------------------

    def postflight(
        self, payload: str, rc: int = 0, succeed_on_call: int = 0, **extra: str
    ) -> subprocess.CompletedProcess:
        counter = self.tmp / "ls.count"
        fake_ls = write_fake(
            self.bin,
            "litestream",
            f"""
            echo "litestream $*" >> {str(self.calls)!r}
            n=$(( $(cat {str(counter)!r} 2>/dev/null || echo 0) + 1 )); echo $n > {str(counter)!r}
            cat <<'JSON'
{payload}
JSON
            if [[ {succeed_on_call} -gt 0 ]]; then [[ $n -ge {succeed_on_call} ]] && exit 0 || exit 1; fi
            exit {rc}
            """,
        )
        script = f"""
set -Eeuo pipefail
{STUBS}
DURABILITY_BARRIER_REQUIRED_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT=sftp://wins-replica@127.0.0.1:2232/srv/wins-replica/data/hub/vpn_users
LITESTREAM_BIN_DEFAULT={str(fake_ls)!r}
LITESTREAM_SYNC_TIMEOUT_SECONDS_DEFAULT=30
DB_PATH={str(self.db)!r}
sleep() {{ echo "sleep $*" >> {str(self.calls)!r}; }}
{optional_functions("litestream_barrier_round_trip_ok")}
{function_definition("verify_litestream_replication_live")}
verify_litestream_replication_live
"""
        return run(script, env=self.env(**extra))

    def good(self, **fields) -> str:
        import json

        payload = {"db_path": str(self.db), "txid": 7, "replica_txid": 7}
        payload.update(fields)
        return json.dumps(payload)

    def test_postflight_accepts_confirmed_replication(self) -> None:
        r = self.postflight(self.good())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"sync -socket /run/litestream/litestream.sock -wait -timeout 30 -json {self.db}", self.calls.read_text())

    def test_postflight_fails_when_service_not_active(self) -> None:
        r = self.postflight(self.good(), FAKE_LS_ACTIVE="0")
        self.assertNotEqual(r.returncode, 0)

    def test_postflight_fails_when_service_not_enabled(self) -> None:
        r = self.postflight(self.good(), FAKE_LS_ENABLED="0")
        self.assertNotEqual(r.returncode, 0)

    def test_postflight_fails_when_replica_behind(self) -> None:
        r = self.postflight(self.good(replica_txid=6))
        self.assertNotEqual(r.returncode, 0)

    def test_postflight_fails_on_bool_or_zero_txid(self) -> None:
        self.assertNotEqual(self.postflight(self.good(txid=True, replica_txid=True)).returncode, 0)
        self.assertNotEqual(self.postflight(self.good(txid=0, replica_txid=0)).returncode, 0)

    def test_postflight_fails_on_wrong_db(self) -> None:
        r = self.postflight(self.good(db_path="/elsewhere.db"))
        self.assertNotEqual(r.returncode, 0)

    def test_postflight_fails_on_nonzero_exit(self) -> None:
        r = self.postflight(self.good(), rc=1)
        self.assertNotEqual(r.returncode, 0)

    def test_postflight_fails_on_ipc_field_name(self) -> None:
        import json

        payload = json.dumps({"db_path": str(self.db), "txid": 7, "replicated_txid": 7})
        self.assertNotEqual(self.postflight(payload).returncode, 0)

    def test_postflight_only_warns_when_barrier_not_required(self) -> None:
        r = self.postflight(self.good(replica_txid=6), DURABILITY_BARRIER_REQUIRED="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WARN]", r.stderr)

    def sync_calls(self) -> list[str]:
        return [l for l in self.calls.read_text().splitlines() if l.startswith("litestream sync")]

    def test_postflight_retries_a_slow_first_replication(self) -> None:
        r = self.postflight(self.good(), succeed_on_call=3)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.sync_calls()), 3)

    def test_postflight_retry_is_bounded(self) -> None:
        r = self.postflight(self.good(), rc=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(self.sync_calls()), 3)
        self.assertEqual(self.calls.read_text().count("sleep "), 2)

    def test_postflight_timeout_clamped_like_main_py(self) -> None:
        self.postflight(self.good(), LITESTREAM_SYNC_TIMEOUT_SECONDS="3600")
        self.assertIn("sync -socket /run/litestream/litestream.sock -wait -timeout 120 -json", self.calls.read_text())
        self.assertIn("timeout -k 5 125 ", self.calls.read_text())
        self.calls.unlink()
        self.postflight(self.good(), LITESTREAM_SYNC_TIMEOUT_SECONDS="0")
        self.assertIn("sync -socket /run/litestream/litestream.sock -wait -timeout 1 -json", self.calls.read_text())
        self.calls.unlink()
        r = self.postflight(self.good(), LITESTREAM_SYNC_TIMEOUT_SECONDS="abc")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sync -socket /run/litestream/litestream.sock -wait -timeout 30 -json", self.calls.read_text())

    def test_config_hash_survives_missing_files_under_pipefail(self) -> None:
        body = function_definition("configure_litestream_replication")
        lines = [l.strip() for l in body.splitlines() if l.strip().startswith(("config_before=", "config_after="))]
        self.assertEqual(len(lines), 2, lines)
        for line in lines:
            name, expr = line.split("=", 1)
            script = f"""
set -Eeuo pipefail
cat() {{ command cat "$@"; }}
sha256sum() {{ command shasum -a 256; }}
{line.replace("/etc/litestream.yml", "/nonexistent/litestream.yml").replace("/etc/systemd/system/litestream.service", "/nonexistent/litestream.service")}
echo "ok ${{{name}}}"
"""
            r = run(script)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("ok ", r.stdout)

    def test_postflight_control_runs_the_check(self) -> None:
        body = function_definition("postflight_control")
        at = body.index("verify_litestream_replication_live || return 1")
        self.assertLess(at, body.index('log "Control-plane post-deployment validation passed"'))


# --------------------------------------------------------------------------
# IA-CP-07: partial vault must not chmod the image's shared parent
# --------------------------------------------------------------------------


class PartialVaultModes(unittest.TestCase):
    """IA-CP-07."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="fxcpa-vault-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "modes.log"
        for name in ("fallocate", "cryptsetup", "blkid", "mkfs.ext4", "mount"):
            write_fake(self.bin, name, "exit 0\n")
        write_fake(self.bin, "mountpoint", "exit 0\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def vault(self, image: str, mount_dir: str, fake_mode: str = "") -> list[str]:
        script = f"""
set -Eeuo pipefail
{STUBS}
chmod() {{ echo "chmod $*" >> {str(self.log)!r}; }}
install() {{ echo "install $*" >> {str(self.log)!r}; }}
mkdir() {{ echo "mkdir $*" >> {str(self.log)!r}; }}
read_partial_vault_passphrase() {{ printf 'lab-passphrase'; }}
vault_link_dir() {{ :; }}
vault_link_file() {{ :; }}
write_partial_vault_unlock_tool() {{ :; }}
APP_DIR=/nonexistent/vpn_auth
ENV_FILE=/nonexistent/vpn_auth.env
WINS_PARTIAL_VAULT_ENABLED_DEFAULT=0
WINS_PARTIAL_VAULT_IMAGE_DEFAULT=/var/lib/winsvpn-vault.luks
WINS_PARTIAL_VAULT_MOUNT_DEFAULT=/srv/winsvpn-vault
WINS_PARTIAL_VAULT_NAME_DEFAULT=winsvpn-vault
WINS_PARTIAL_VAULT_SIZE_DEFAULT=16G
{function_definition("configure_partial_vault")}
configure_partial_vault
"""
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "WINS_PARTIAL_VAULT_ENABLED": "1",
            "WINS_PARTIAL_VAULT_IMAGE": image,
            "WINS_PARTIAL_VAULT_MOUNT": mount_dir,
            "FAKE_STAT_MODE_FOR": fake_mode,
        }
        r = run(script, env=env)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_existing_shared_parent_is_never_tightened(self) -> None:
        shared = self.tmp / "var" / "lib"
        shared.mkdir(parents=True)
        calls = self.vault(str(shared / "winsvpn-vault.luks"), str(self.tmp / "mnt"))
        for call in calls:
            if call.startswith(("chmod", "install")):
                self.assertNotIn(str(shared), call.split(), call)

    def test_mount_dir_is_created_0700(self) -> None:
        shared = self.tmp / "var" / "lib"
        shared.mkdir(parents=True)
        mnt = str(self.tmp / "mnt")
        calls = self.vault(str(shared / "winsvpn-vault.luks"), mnt)
        self.assertTrue(
            any(c.startswith("install -d -m 700") and c.endswith(" " + mnt) for c in calls), calls
        )

    def test_missing_dedicated_parent_is_created_0700(self) -> None:
        own = self.tmp / "dedicated"
        calls = self.vault(str(own / "vault.luks"), str(self.tmp / "mnt"))
        self.assertIn(f"install -d -m 700 {own}", calls)

    def test_default_image_never_chmods_var_lib_700(self) -> None:
        calls = self.vault("/var/lib/winsvpn-vault.luks", str(self.tmp / "mnt"), "/var/lib=755")
        self.assertFalse(any(c.startswith("chmod") and "/var/lib" in c.split() for c in calls), calls)

    def test_rerun_heals_var_lib_left_at_0700(self) -> None:
        calls = self.vault("/var/lib/winsvpn-vault.luks", str(self.tmp / "mnt"), "/var/lib=700")
        self.assertIn("chmod 755 /var/lib", calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
