#!/usr/bin/env python3
"""Regressions for the IA-SYNC data-plane findings (installer fix wave 2).

SYNC-01  every data plane carries the winn3-gateway group and /etc/winn in the
         exact form the hub's registry push script requires.
SYNC-05  NODE_HOST (the AmneziaWG UDP endpoint) is never a Cloudflare-proxied
         stealth name, by default or by input, and a bad value is refused
         before the hub withdrawal.
SYNC-09  the code-drift refusal happens before the hub withdrawal.
SYNC-12  (pin) the pubkey sync and the self-resync run only after a
         successful register POST in the same run.
SYNC-13  node backups are keyed on a pinned, fleet-unique BACKUP_HOST_ID.
SYNC-14  the heartbeat reports the gateway installer revision (which the
         gateway installer now stamps) and the data-plane source revision.
SYNC-19  a refused registration logs the hub's reason, bounded and masked.
SYNC-20  the node canary verdict reaches the heartbeat.
SYNC-26  the bootstrap grant is exchanged before the package reboot pause and
         the token survives that pause.

Every test runs the installer's own functions, heredocs or main() text with
bash against stubs. No root, network, systemd or package manager is needed.
WINS_SYNC_DP_DATA, WINS_SYNC_DP_GATEWAY and WINS_SYNC_DP_HUB point the suite at
other copies (the snapshot for fail-before proof, or a mutant). The fleet's
public addresses in known_node_defaults are read from the installer itself and
are never printed.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = pathlib.Path(os.environ.get("WINS_SYNC_DP_DATA", str(ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh")))
# Slice S6: the real wins_winn3_gateway_install.sh is a tombstone. The SYNC-14
# stamp tests below prove the standalone installer's own stamp writer and main(),
# so they read the frozen copy of it (deleted with the tombstone).
GATEWAY = pathlib.Path(os.environ.get(
    "WINS_SYNC_DP_GATEWAY",
    str(ROOT / "server" / "testdata" / "winn3_gateway_install_retired" / "wins_winn3_gateway_install.sh.snapshot")))
HUB = pathlib.Path(os.environ.get("WINS_SYNC_DP_HUB", str(ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh")))
BASH = shutil.which("bash") or "/bin/bash"
SRC = DATA.read_text(encoding="utf-8")
GSRC = GATEWAY.read_text(encoding="utf-8")

NODE_TOKEN = "nT_" + "k9-Q" * 15 + "Z"  # 64 URL-safe characters, the hub's issued shape
OTHER_TOKEN = "zZ_" + "a1-B" * 15 + "Y"
XRAY_UUID = "7f1c2d3e-4b5a-4c6d-8e9f-0a1b2c3d4e5f"
GRANT = "g" * 43

LOG_STUBS = "\n".join([
    'log() { printf "[LOG] %s\\n" "$*"; }',
    'warn() { printf "[WARN] %s\\n" "$*" >&2; }',
    'err() { printf "[ERR] %s\\n" "$*" >&2; }',
])
# macOS has no install -o root for a non-root user; drop owner and group.
INSTALL_SHIM = (
    'install() { local a=(); while (($#)); do case "$1" in -o|-g) shift 2 ;; '
    '*) a+=("$1"); shift ;; esac; done; command install "${a[@]}"; }'
)
# OI-SYNCDP-18: hub_dns_lookup runs `timeout -s KILL N getent ...`. The
# harnesses define getent as a shell function, which timeout(1) cannot run,
# and macOS has no timeout(1), so this function stands in for it: it runs the
# command, sends the signal at N seconds, and returns what coreutils returns
# (137 after SIGKILL, 124 after any other signal). With TIMEOUT_TRACE set it
# records each call.
TIMEOUT_STUB = "\n".join([
    "timeout() {",
    '  local sig=TERM limit pid end',
    '  [[ "$1" == -s ]] && { sig="$2"; shift 2; }',
    '  limit="$1"; shift',
    '  if [[ -n "${TIMEOUT_TRACE:-}" ]]; then printf "timeout -s %s %s %s\\n" "$sig" "$limit" "$*" >> "$TIMEOUT_TRACE"; fi',
    '  "$@" &',
    "  pid=$!",
    "  end=$(( ${EPOCHREALTIME/./} + limit * 1000000 ))",
    '  while builtin kill -0 "$pid" 2>/dev/null; do',
    "    if (( ${EPOCHREALTIME/./} >= end )); then",
    '      builtin kill -s "$sig" "$pid" 2>/dev/null || :',
    '      wait "$pid" 2>/dev/null || :',
    '      [[ "$sig" == KILL ]] && return 137',
    "      return 124",
    "    fi",
    "    /bin/sleep 0.02",
    "  done",
    '  wait "$pid"',
    "}",
])


def function_body(text: str, name: str) -> str:
    marker = f"\n{name}() {{\n"
    start = text.index(marker) + 1
    cursor = text.index("\n}\n", start)
    while True:
        candidate = text[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate + "\n"
        cursor = text.index("\n}\n", cursor + 2)


def has_function(text: str, name: str) -> bool:
    return f"\n{name}() {{\n" in text


def optional_functions(text: str, *names: str) -> str:
    return "".join(function_body(text, n) for n in names if has_function(text, n))


def heredoc(text: str, opener: str) -> str:
    at = text.index(opener)
    start = text.index("\n", at) + 1
    end = text.index("\nEOF\n", start)
    return text[start:end] + "\n"


REGISTER = heredoc(SRC, "cat > /usr/local/bin/wins-node-register <<'EOF'")
CANARY = heredoc(SRC, "cat > /usr/local/bin/wins-node-canary <<'EOF'")
BACKUP = heredoc(SRC, "cat > /usr/local/bin/wins-node-backup <<'EOF'")
MAIN = function_body(SRC, "main")
MAIN_CALLS = [line.strip() for line in MAIN.splitlines()]


def run(script: str, env: dict[str, str] | None = None, cwd: str | None = None, timeout: int = 60):
    full = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C"}
    full.update(env or {})
    return subprocess.run([BASH, "-c", script], env=full, cwd=cwd, text=True, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=timeout, check=False)


def write_exec(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def stat_shim(bin_dir: pathlib.Path) -> None:
    # GNU `stat -c '%u'|'%a' PATH`, which the installer uses; macOS stat has no
    # -c. Files owned by the user running the suite report uid 0, standing in
    # for the root-owned files the installer requires. On Linux the real GNU
    # tools are used, so the suite must run as root there.
    if not sys.platform.startswith("darwin"):
        return
    write_exec(bin_dir / "stat", "#!/usr/bin/env python3\n"
               "import os, sys\n"
               "a = sys.argv[1:]\n"
               "if len(a) != 3 or a[0] != '-c':\n"
               "    os.execv('/usr/bin/stat', ['/usr/bin/stat'] + a)\n"
               "st = os.lstat(a[2])\n"
               f"uid = 0 if st.st_uid == {os.getuid()} else st.st_uid\n"
               "print({'%u': uid, '%a': format(st.st_mode & 0o7777, 'o')}[a[1]])\n")
    # GNU find's `-perm /MODE` (any bit set) is BSD find's `-perm +MODE`.
    write_exec(bin_dir / "find", "#!/usr/bin/env bash\n"
               "args=()\n"
               "for a in \"$@\"; do [[ \"$a\" == /[0-7]* && \"${prev:-}\" == -perm ]] && a=\"+${a#/}\"; "
               "args+=(\"$a\"); prev=\"$a\"; done\n"
               "exec /usr/bin/find \"${args[@]}\"\n")


def main_segment(after: str, through: str) -> str:
    """main()'s text after the line `after` up to and including `through`."""
    a = MAIN.index(f"\n{after}\n") + len(after) + 2
    b = MAIN.index(f"\n{through}\n", a) + len(through) + 2
    return MAIN[a:b]


def stubs_for(segment: str, real: set[str], trace: str) -> str:
    real = set(real) | {"log", "warn", "err"}
    names = []
    for line in segment.splitlines():
        m = re.match(r"\s*([a-z_][a-z0-9_]*)\b", line)
        if m and m.group(1) not in real and has_function(SRC, m.group(1)) and m.group(1) not in names:
            names.append(m.group(1))
    return "\n".join(f'{n}() {{ printf "%s\\n" {n} >> "{trace}"; }}' for n in names)


# --------------------------------------------------------------------------
# SYNC-01
# --------------------------------------------------------------------------
class RegistryGroup(unittest.TestCase):
    def _run(self, group_present: bool):
        with tempfile.TemporaryDirectory(prefix="sync01-") as tmp:
            calls = pathlib.Path(tmp, "calls")
            prog = "\n".join([
                "set -Eeuo pipefail", LOG_STUBS,
                f'getent() {{ printf "getent %s\\n" "$*" >> "{calls}"; return {0 if group_present else 2}; }}',
                f'groupadd() {{ printf "groupadd %s\\n" "$*" >> "{calls}"; }}',
                f'install() {{ printf "install %s\\n" "$*" >> "{calls}"; }}',
                self.definitions(),
                "ensure_winn3_registry_group",
            ])
            out = run(prog)
            return out, (calls.read_text() if calls.exists() else "")

    def definitions(self) -> str:
        body = function_body(SRC, "ensure_winn3_registry_group")
        consts = re.findall(r"^WINN3_REGISTRY_(?:GROUP|DIR)=.*$", SRC, re.M)
        return "\n".join(consts) + "\n" + body

    def test_group_and_directory_created_in_the_hub_scripts_form(self):
        out, calls = self._run(group_present=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("groupadd --system winn3-gateway", calls)
        self.assertIn("install -d -m 0750 -o root -g winn3-gateway /etc/winn", calls)

    def test_existing_group_is_reused(self):
        out, calls = self._run(group_present=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("groupadd", calls)
        self.assertIn("install -d -m 0750 -o root -g winn3-gateway /etc/winn", calls)

    def test_matches_the_hub_remote_script_literals(self):
        hub = HUB.read_text(encoding="utf-8")
        start = hub.index("remote_cmd = (\n", hub.index("def sync_winn3_registry_to_node"))
        preamble = hub[start:start + 400]
        m_group = re.search(r'getent group ([a-z0-9-]+) >/dev/null', preamble)
        m_dir = re.search(r'install -d -m (\d+) -o root -g ([a-z0-9-]+) (/[a-z/]+);', preamble)
        self.assertIsNotNone(m_group, preamble)
        self.assertIsNotNone(m_dir, preamble)
        _, calls = self._run(group_present=False)
        self.assertIn(f"groupadd --system {m_group.group(1)}", calls)
        self.assertIn(f"install -d -m {m_dir.group(1)} -o root -g {m_dir.group(2)} {m_dir.group(3)}", calls)

    def test_main_creates_it_before_the_register_timer_and_hub_verification(self):
        self.assertEqual(MAIN_CALLS.count("ensure_winn3_registry_group"), 1)
        at = MAIN_CALLS.index("ensure_winn3_registry_group")
        self.assertLess(at, MAIN_CALLS.index("write_register_script"))
        self.assertLess(at, MAIN_CALLS.index("verify_hub_node_management"))
        self.assertGreater(at, MAIN_CALLS.index("begin_data_deployment_withdrawal_before_mutation"))

    def test_gateway_installer_still_tolerates_an_existing_group(self):
        body = function_body(GSRC, "ensure_service_user")
        self.assertIn('if ! getent group "${WINN3_SERVICE_USER}"', body)
        self.assertIn('WINN3_SERVICE_USER="${WINN3_SERVICE_USER:-winn3-gateway}"', GSRC)


# --------------------------------------------------------------------------
# SYNC-05
# --------------------------------------------------------------------------
PROXIED_FUNCS = ("is_ipv4_literal", "normalize_alias_list", "data_node_host_is_proxied_edge_name",
                 "data_refuse_proxied_node_host")


class ProxiedNodeHost(unittest.TestCase):
    def test_known_nodes_default_to_their_own_address(self):
        body = function_body(SRC, "known_node_defaults")
        labels = re.findall(r"^\s+((?:\d{1,3}\.){3}\d{1,3})\)$", body, re.M)
        self.assertEqual(len(labels), 3, "expected the three built-in nodes")
        prog = "\n".join(["set -Eeuo pipefail", 'NODE_DEFAULTS_FILE=/nonexistent', body,
                          'for ip in "$@"; do known_node_defaults "$ip"; done'])
        out = subprocess.run([BASH, "-c", prog, "x", *labels], text=True, capture_output=True, check=False,
                             stdin=subprocess.DEVNULL)
        self.assertEqual(out.returncode, 0)
        lines = out.stdout.splitlines()
        self.assertEqual(len(lines), 3)
        for index, (ip, line) in enumerate(zip(labels, lines)):
            host = line.split("|")[3]
            # Messages name the index only: the addresses are never printed.
            self.assertTrue(host == ip, f"built-in node #{index}: NODE_HOST default is not its own address")
            self.assertNotIn("stealth-zone", line, f"built-in node #{index} still defaults to the stealth name")

    def _predicate(self, host: str, stealth: str = "", aliases: str = "") -> int:
        prog = "\n".join([LOG_STUBS, 'CLOUDFLARE_STEALTH_ZONE_DEFAULT="app-cloud-sync.net"',
                          *(function_body(SRC, f) for f in PROXIED_FUNCS[:3]),
                          'data_node_host_is_proxied_edge_name "$1"'])
        env = {"STEALTH_HOST": stealth, "REGIONAL_GATEWAY_ALIASES": aliases}
        out = subprocess.run([BASH, "-c", prog, "x", host], text=True, capture_output=True, check=False,
                             stdin=subprocess.DEVNULL, env={**os.environ, **env})
        return out.returncode

    def test_proxied_names_are_recognised(self):
        self.assertEqual(self._predicate("canada-ca1.app-cloud-sync.net"), 0)
        self.assertEqual(self._predicate("CANADA-CA1.App-Cloud-Sync.NET."), 0)
        self.assertEqual(self._predicate("app-cloud-sync.net"), 0)
        self.assertEqual(self._predicate("stealth.example.org", stealth="stealth.example.org"), 0)
        self.assertEqual(self._predicate("alias.example.org", aliases="first.example.org, alias.example.org"), 0)

    def test_addresses_and_dns_only_names_are_allowed(self):
        self.assertEqual(self._predicate("203.0.113.5", stealth="203.0.113.5"), 1)
        self.assertEqual(self._predicate("node1.example.net", stealth="node1-stealth.app-cloud-sync.net"), 1)
        self.assertEqual(self._predicate("notapp-cloud-sync.net"), 1)
        self.assertEqual(self._predicate(""), 1)

    def test_collect_inputs_refuses_before_writing_node_env(self):
        body = function_body(SRC, "collect_inputs")
        call = "data_refuse_proxied_node_host || exit 1"
        self.assertIn(call, body)
        self.assertLess(body.index("maybe_prompt_or_default STEALTH_HOST"), body.index(call))
        self.assertLess(body.index('REGIONAL_GATEWAY_ALIASES="$(normalize_alias_list'), body.index(call))
        self.assertLess(body.index(call), body.index("write_env_kv NODE_SLUG"))
        self.assertLess(body.index(call), body.index("atomic_replace_file"))


# --------------------------------------------------------------------------
# SYNC-09 and SYNC-05: refusals run before the hub withdrawal
# --------------------------------------------------------------------------
GUARD_FUNCS = ("data_plane_installer_path", "data_plane_already_installed", "guard_data_plane_code_drift",
               "data_plane_approved_installers_file", "data_plane_installer_approved",
               "data_preflight_sync_contract", "data_verify_pending_node_token", *PROXIED_FUNCS)


class RefusalsBeforeWithdrawal(unittest.TestCase):
    def _main(self, tmp: str, *, installed: bool, stamp_sha: str | None, node_host: str = "",
              stealth: str = "", overwrite: str = "0", pending_token: str = "", hub_code: str = "200"):
        tmpd = pathlib.Path(tmp)
        trace = tmpd / "trace"
        installer = tmpd / "installer.sh"
        installer.write_text("# the installer whose provenance is checked\n", encoding="utf-8")
        awg = tmpd / "awg0.conf"
        if installed:
            awg.write_text("[Interface]\n", encoding="utf-8")
        stamp = tmpd / "stamp"
        if stamp_sha is not None:
            stamp.write_text(f"{stamp_sha}\ninstall_mode=main\n", encoding="utf-8")
        segment = main_segment("  preflight_data_plane", "  begin_data_deployment_withdrawal_before_mutation")
        real = set(GUARD_FUNCS)
        prog = "\n".join([
            "set -Eeuo pipefail", LOG_STUBS,
            'CLOUDFLARE_STEALTH_ZONE_DEFAULT="app-cloud-sync.net"',
            'XRAY_VERSION_DEFAULT="0"', 'XRAY_LINUX_64_SHA256_DEFAULT="0"',
            "docker() { return 1; }",
            f'curl() {{ cat > /dev/null; printf "%s" "{hub_code}"; }}',
            optional_functions(SRC, *GUARD_FUNCS),
            stubs_for(segment, real, str(trace)),
            f'begin_data_deployment_withdrawal_before_mutation() {{ printf "WITHDRAWN\\n" >> "{trace}"; exit 0; }}',
            "run_main_segment() {", segment, "}",
            "run_main_segment",
        ])
        env = {"AWG_CONF_PATH": str(awg), "DATA_PLANE_CODE_STAMP": str(stamp),
               "WINS_DATA_PLANE_INSTALLER_PATH": str(installer), "NODE_HOST": node_host,
               "STEALTH_HOST": stealth, "ALLOW_DATA_PLANE_OVERWRITE": overwrite,
               "DATA_PENDING_NODE_TOKEN": pending_token, "NODE_SLUG": "germany-de1",
               "HUB_API_BASE": "https://hub.example.test", "DATA_PENDING_NODE_TOKEN_FILE": "/var/lib/x/data.node-token"}
        out = run(prog, env)
        sha = hashlib.sha256(installer.read_bytes()).hexdigest()
        return out, (trace.read_text() if trace.exists() else ""), sha

    def test_drift_refusal_happens_before_the_withdrawal(self):
        with tempfile.TemporaryDirectory(prefix="sync09-") as tmp:
            out, trace, _ = self._main(tmp, installed=True, stamp_sha="0" * 64)
            self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("REFUSING TO REINSTALL THE DATA PLANE", out.stderr)
            self.assertNotIn("WITHDRAWN", trace, "the hub withdrawal ran before the drift refusal")

    def test_unstamped_existing_plane_is_refused_before_the_withdrawal(self):
        with tempfile.TemporaryDirectory(prefix="sync09-") as tmp:
            out, trace, _ = self._main(tmp, installed=True, stamp_sha=None)
            self.assertNotEqual(out.returncode, 0)
            self.assertNotIn("WITHDRAWN", trace)

    def test_matching_stamp_and_fresh_host_reach_the_withdrawal(self):
        with tempfile.TemporaryDirectory(prefix="sync09-") as tmp:
            installer = pathlib.Path(tmp, "installer.sh")
            installer.write_text("# the installer whose provenance is checked\n", encoding="utf-8")
            sha = hashlib.sha256(installer.read_bytes()).hexdigest()
            out, trace, _ = self._main(tmp, installed=True, stamp_sha=sha)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("WITHDRAWN", trace)
        with tempfile.TemporaryDirectory(prefix="sync09-") as tmp:
            out, trace, _ = self._main(tmp, installed=False, stamp_sha=None)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("WITHDRAWN", trace)

    def test_documented_override_still_proceeds(self):
        with tempfile.TemporaryDirectory(prefix="sync09-") as tmp:
            out, trace, _ = self._main(tmp, installed=True, stamp_sha="0" * 64, overwrite="1")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("WITHDRAWN", trace)

    def test_proxied_node_host_is_refused_before_the_withdrawal(self):
        with tempfile.TemporaryDirectory(prefix="sync05-") as tmp:
            out, trace, _ = self._main(tmp, installed=False, stamp_sha=None,
                                       node_host="germany-de1.app-cloud-sync.net",
                                       stealth="germany-de1.app-cloud-sync.net")
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("Cloudflare-proxied stealth name", out.stderr)
            self.assertNotIn("WITHDRAWN", trace)
        with tempfile.TemporaryDirectory(prefix="sync05-") as tmp:
            out, trace, _ = self._main(tmp, installed=False, stamp_sha=None, node_host="198.51.100.20",
                                       stealth="germany-de1.app-cloud-sync.net")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("WITHDRAWN", trace)

    def test_superseded_pending_token_is_refused_before_the_withdrawal(self):
        # OI-SYNCDP-3: the refusal names the pending file and happens before
        # the withdrawal (and before --preflight returns).
        for code, needle in (("401", "superseded"), ("000", "Could not check")):
            with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
                out, trace, _ = self._main(tmp, installed=False, stamp_sha=None, pending_token=NODE_TOKEN,
                                           hub_code=code)
                self.assertNotEqual(out.returncode, 0, (code, out.stdout, out.stderr))
                self.assertIn(needle, out.stderr)
                self.assertIn("/var/lib/x/data.node-token", out.stderr)
                self.assertNotIn("WITHDRAWN", trace)
                self.assertNotIn(NODE_TOKEN, out.stdout + out.stderr)
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out, trace, _ = self._main(tmp, installed=False, stamp_sha=None, pending_token=NODE_TOKEN, hub_code="200")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("WITHDRAWN", trace)

    def test_install_awg_keeps_its_own_guard_for_stage_scripts(self):
        body = function_body(SRC, "install_awg")
        self.assertIn("  guard_data_plane_code_drift\n", body)
        self.assertLess(body.index("  guard_data_plane_code_drift\n"), body.index("install -d -m 700 /etc/amnezia\n"))

    def test_preflight_pin_sequence_is_kept(self):
        self.assertIn("  refuse_retired_winn_protocol_v3_enable\n  require_root\n  preflight_data_plane\n", MAIN)
        self.assertLess(MAIN_CALLS.index("data_preflight_sync_contract"),
                        MAIN_CALLS.index("begin_data_deployment_withdrawal_before_mutation"))


# --------------------------------------------------------------------------
# SYNC-26
# --------------------------------------------------------------------------
def pending_block() -> str:
    start = SRC.index('DATA_PENDING_NODE_TOKEN_FILE="${DATA_PENDING_NODE_TOKEN_FILE:-')
    end = SRC.index('\nif [[ -z "${XRAY_UUID}" && -r "${NODE_ENV_FILE}" ]]; then\n', start)
    return SRC[start:end] + "\n"


BOOTSTRAP_FUNCS = ("write_env_kv", "persist_node_token", "data_clear_pending_node_token", "bootstrap_node_token",
                   "data_exchange_grant_before_reboot", "data_verify_pending_node_token",
                   "data_require_subject_credential", "sanitize_slug")


class GrantBeforeReboot(unittest.TestCase):
    """SYNC-26 with Sol's OI-SYNCDP-2, OI-SYNCDP-3 and N-1."""

    def _run(self, work: pathlib.Path, *, pending: pathlib.Path, node_env_text: str | None = None,
             hub_token: str = NODE_TOKEN, grant: str = GRANT, extra_stubs: str = "",
             with_loader: bool = False, verify_code: str = "200", slug: str = "germany-de1"):
        work.mkdir(parents=True, exist_ok=True)
        trace = work / "trace"
        calls = work / "curl_calls"
        argv_log = work / "argv"
        config = work / "config"
        request = work / "request.json"
        node_env = work / "node.env"
        if node_env_text is not None:
            node_env.write_text(node_env_text, encoding="utf-8")
            node_env.chmod(0o600)
        bin_dir = work / "bin"
        bin_dir.mkdir(exist_ok=True)
        tmp_dir = work / "tmpdir"
        tmp_dir.mkdir(exist_ok=True)
        stat_shim(bin_dir)
        if sys.platform.startswith("darwin"):
            # GNU mktemp (the node's) puts a template-less file in TMPDIR; BSD
            # mktemp ignores TMPDIR, which would hide a leaked request file.
            write_exec(bin_dir / "mktemp", '#!/bin/sh\nif [ "$#" -eq 0 ]; then exec /usr/bin/mktemp "${TMPDIR}/tmp.XXXXXXXX"; fi\n'
                       'exec /usr/bin/mktemp "$@"\n')
        real_py = shutil.which("python3") or sys.executable
        # Every python3 argv is logged: the grant and the token must never be in one.
        write_exec(bin_dir / "python3", f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{argv_log}"\nexec "{real_py}" "$@"\n')
        segment = main_segment("  begin_data_deployment_withdrawal_before_mutation", "  pause_for_required_reboot data")
        curl_stub = "\n".join([
            "curl() {",
            f'  printf "%s\\n" "$*" >> "{argv_log}"',
            '  if [[ " $* " == *" --config - "* ]]; then',
            f'    cat >> "{config}"; printf "%s" "{verify_code}"; return 0',
            "  fi",
            "  local a",
            f'  for a in "$@"; do [[ "$a" == @* ]] && cp "${{a#@}}" "{request}"; done',
            f'  printf "call\\n" >> "{calls}"; printf "EXCHANGE\\n" >> "{trace}"',
            f"  printf '{{\"node_token\":\"%s\"}}' \"{hub_token}\"",
            "}",
        ])
        prog = "\n".join([
            "set -Eeuo pipefail", LOG_STUBS, INSTALL_SHIM,
            'NODE_TOKEN="${NODE_TOKEN:-}"',
            pending_block() if with_loader else 'DATA_PENDING_NODE_TOKEN=""',
            optional_functions(SRC, *BOOTSTRAP_FUNCS),
            stubs_for(segment, set(BOOTSTRAP_FUNCS), str(trace)),
            curl_stub,
            f'pause_for_required_reboot() {{ if [[ "${{NODE_TOKEN:-}}" == "$EXPECT" ]]; then '
            f'printf "PAUSE token=expected\\n" >> "{trace}"; else printf "PAUSE token=other\\n" >> "{trace}"; fi; return 75; }}',
            extra_stubs,
            # What preflight would do on the rerun: accept the pending token as
            # the credential and check it with the hub before the withdrawal.
            "data_require_subject_credential || exit 1" if with_loader else ":",
            "data_verify_pending_node_token || exit 1" if with_loader else ":",
            # The withdrawal (begin_data_deployment_withdrawal_before_mutation)
            # must still see a node with no hub identity.
            f'printf "withdrawal token=%s\\n" "${{NODE_TOKEN:+set}}" >> "{trace}"',
            "run_segment() {", segment, "}",
            "run_segment",
        ])
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "NODE_SLUG": slug, "NODE_BOOTSTRAP_TOKEN": grant,
               "TMPDIR": str(tmp_dir),
               "NODE_TOKEN": "", "NODE_ENV_FILE": str(node_env), "DATA_PENDING_NODE_TOKEN_FILE": str(pending),
               "HUB_API_BASE": "https://hub.example.test", "EXPECT": hub_token}
        out = run(prog, env)
        read = lambda f: f.read_text() if f.exists() else ""  # noqa: E731
        return {
            "out": out, "trace": read(trace), "calls": read(calls).count("call"), "argv": read(argv_log),
            "config": read(config), "request": read(request), "node_env": node_env,
            "tmpdir": sorted(p.name for p in tmp_dir.iterdir()),
        }

    def _assert_quiet(self, r):
        both = r["out"].stdout + r["out"].stderr
        self.assertNotIn(NODE_TOKEN, both, "the node token was logged")
        self.assertNotIn(GRANT, both, "the grant was logged")
        self.assertNotIn(NODE_TOKEN, r["argv"], "the node token reached an argv")
        self.assertNotIn(GRANT, r["argv"], "the grant reached an argv")

    def test_fresh_install_spends_the_grant_before_apt_and_the_reboot_pause(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            pending = pathlib.Path(tmp, "state", "data.node-token")
            r = self._run(pathlib.Path(tmp, "w"), pending=pending)
            self.assertEqual(r["out"].returncode, 75, r["out"].stdout + r["out"].stderr)
            self.assertEqual(r["calls"], 1, "the grant was not exchanged exactly once")
            order = [line.split()[0] for line in r["trace"].splitlines()]
            for later in ("mark_data_role", "apt_install", "PAUSE"):
                self.assertLess(order.index("EXCHANGE"), order.index(later), (later, order))
            self.assertIn("PAUSE token=expected", r["trace"])
            self.assertTrue(pending.is_file(), "the token did not survive the pause")
            self.assertEqual(stat.S_IMODE(pending.stat().st_mode), 0o600)
            self.assertEqual(pending.read_text(), f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n")
            self.assertEqual(json.loads(r["request"]), {"slug": "germany-de1", "bootstrap_token": GRANT})
            self.assertEqual(sorted(p.name for p in pending.parent.iterdir()), ["data.node-token"])
            self._assert_quiet(r)
            # CLAUDE-N-5: the exchange is bounded like bootstrap_node_token, and
            # the 0600 request file holding the grant is gone afterwards.
            exchange = [l for l in r["argv"].splitlines() if "/api/v1/nodes/bootstrap" in l]
            self.assertEqual(len(exchange), 1, r["argv"])
            self.assertIn("--connect-timeout 10 --max-time 30", exchange[0])
            self.assertEqual(r["tmpdir"], [], "the grant request file was left in TMPDIR")

    def test_partial_first_install_keeps_node_env_without_a_token(self):
        # FX-DP-MED IA-DP-06 lets a tokenless node.env continue as a first
        # install. The token goes to the pending file, so a rerun after the
        # reboot still reaches the withdrawal as a node with no hub identity.
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            pending = pathlib.Path(tmp, "state", "data.node-token")
            text = 'NODE_SLUG="germany-de1"\nNODE_TOKEN=""\n'
            r = self._run(pathlib.Path(tmp, "w"), pending=pending, node_env_text=text)
            self.assertEqual(r["out"].returncode, 75, r["out"].stdout + r["out"].stderr)
            self.assertEqual(r["calls"], 1)
            self.assertTrue(pending.is_file())
            self.assertEqual(r["node_env"].read_text(), text)

    def test_unwritable_pending_location_refuses_before_the_grant_is_spent(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            blocker = pathlib.Path(tmp, "not-a-dir")
            blocker.write_text("x")
            r = self._run(pathlib.Path(tmp, "w"), pending=blocker / "data.node-token")
            self.assertEqual(r["out"].returncode, 1, r["out"].stdout + r["out"].stderr)
            self.assertEqual(r["calls"], 0, "the grant was spent although the token could not be kept")
            self.assertIn("was NOT spent", r["out"].stderr)
            self.assertNotIn("apt_install", r["trace"])
            self.assertNotIn("PAUSE", r["trace"])

    def test_failure_to_keep_the_token_after_the_exchange_stops_before_apt(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            pending = pathlib.Path(tmp, "state", "data.node-token")
            r = self._run(pathlib.Path(tmp, "w"), pending=pending, extra_stubs="mv() { return 1; }")
            self.assertEqual(r["out"].returncode, 1, r["out"].stdout + r["out"].stderr)
            self.assertEqual(r["calls"], 1)
            self.assertIn("The grant is spent", r["out"].stderr)
            self.assertNotIn("mark_data_role", r["trace"])
            self.assertNotIn("apt_install", r["trace"])
            self.assertNotIn("PAUSE", r["trace"])
            self.assertFalse(pending.exists())
            self.assertEqual(list(pending.parent.iterdir()), [], "a temporary token copy was left behind")
            self.assertEqual(r["tmpdir"], [], "the grant request file was left in TMPDIR")
            self._assert_quiet(r)

    def test_a_malformed_hub_token_is_never_kept(self):
        for bad in ("short", "a" * 40 + "+/=", "a" * 300):
            with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
                pending = pathlib.Path(tmp, "state", "data.node-token")
                r = self._run(pathlib.Path(tmp, "w"), pending=pending, hub_token=bad)
                self.assertEqual(r["out"].returncode, 1, bad)
                self.assertFalse(pending.exists())
                self.assertEqual(list(pending.parent.iterdir()), [])
                self.assertEqual(r["tmpdir"], [], "the grant request file was left in TMPDIR")
                self.assertNotIn("apt_install", r["trace"])

    def test_rerun_after_the_reboot_adopts_the_checked_pending_token(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            pending = pathlib.Path(tmp, "state", "data.node-token")
            first = self._run(pathlib.Path(tmp, "run1"), pending=pending)
            self.assertEqual(first["out"].returncode, 75)
            # The rerun: no grant any more (it is spent), the top-level loader
            # and the preflight check run first.
            for node_env_text in (None, 'NODE_SLUG="germany-de1"\nNODE_TOKEN=""\n'):
                work = pathlib.Path(tmp, f"run2-{node_env_text is None}")
                r = self._run(work, pending=pending, grant="", with_loader=True, node_env_text=node_env_text)
                self.assertEqual(r["out"].returncode, 75, r["out"].stdout + r["out"].stderr)
                self.assertEqual(r["calls"], 0, "a second grant exchange was attempted")
                self.assertIn("withdrawal token=\n", r["trace"], "the withdrawal saw the unregistered token")
                self.assertIn("PAUSE token=expected", r["trace"])
                self.assertIn(f"x-node-token: {NODE_TOKEN}", r["config"], "the hub check did not use the token")
                check = [l for l in r["argv"].splitlines() if "--config -" in l]
                self.assertEqual(len(check), 1, r["argv"])
                # CLAUDE-N-5: the check of the pending token is bounded.
                self.assertIn("--connect-timeout 10 --max-time 30", check[0])
                self.assertIn(str(pending), r["out"].stderr + r["out"].stdout)
                self._assert_quiet(r)

    def test_superseded_pending_token_is_refused_naming_the_file(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            pending = pathlib.Path(tmp, "state", "data.node-token")
            self.assertEqual(self._run(pathlib.Path(tmp, "run1"), pending=pending)["out"].returncode, 75)
            for code, needle in (("401", "superseded"), ("403", "superseded"), ("000", "Could not check"),
                                 ("503", "Could not check"), ("302", "Could not check"), ("204", "Could not check")):
                r = self._run(pathlib.Path(tmp, f"run2-{code}"), pending=pending, grant="", with_loader=True,
                              verify_code=code)
                self.assertEqual(r["out"].returncode, 1, (code, r["out"].stdout, r["out"].stderr))
                self.assertIn(needle, r["out"].stderr)
                self.assertIn(str(pending), r["out"].stderr)
                self.assertEqual(r["calls"], 0)
                self.assertNotIn("withdrawal", r["trace"])
                self._assert_quiet(r)

    def test_a_non_canonical_slug_is_refused_before_the_grant_is_spent(self):
        # CLAUDE-N-4: collect_inputs would rename these; the grant must not be
        # spent under a name node.env never uses.
        base = ["set -Eeuo pipefail", LOG_STUBS, function_body(SRC, "sanitize_slug"),
                function_body(SRC, "data_require_subject_credential"), "data_require_subject_credential"]
        for slug in ("abc-", "de1-", "a--b"):
            out = run("\n".join(base), {"NODE_TOKEN": "", "DATA_PENDING_NODE_TOKEN": "",
                                         "NODE_BOOTSTRAP_TOKEN": GRANT, "NODE_SLUG": slug})
            self.assertEqual(out.returncode, 1, slug)
            self.assertIn("not canonical", out.stderr)
            with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
                r = self._run(pathlib.Path(tmp, "w"), pending=pathlib.Path(tmp, "state", "data.node-token"), slug=slug)
                self.assertEqual(r["out"].returncode, 1, (slug, r["out"].stderr))
                self.assertEqual(r["calls"], 0, "the grant was spent under a non-canonical slug")
        ok = run("\n".join(base), {"NODE_TOKEN": "", "DATA_PENDING_NODE_TOKEN": "", "NODE_BOOTSTRAP_TOKEN": GRANT,
                                    "NODE_SLUG": "germany-de1"})
        self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_pending_token_counts_as_the_subject_credential(self):
        body = function_body(SRC, "data_require_subject_credential")
        base = ["set -Eeuo pipefail", LOG_STUBS, function_body(SRC, "sanitize_slug"), body,
                "data_require_subject_credential"]
        ok = run("\n".join(base), {"NODE_TOKEN": "", "DATA_PENDING_NODE_TOKEN": NODE_TOKEN, "NODE_BOOTSTRAP_TOKEN": ""})
        self.assertEqual(ok.returncode, 0, ok.stderr)
        bad = run("\n".join(base), {"NODE_TOKEN": "", "DATA_PENDING_NODE_TOKEN": "", "NODE_BOOTSTRAP_TOKEN": ""})
        self.assertEqual(bad.returncode, 1)

    def test_main_order(self):
        names = ("begin_data_deployment_withdrawal_before_mutation", "data_exchange_grant_before_reboot",
                 "mark_data_role", "apt_install", "pause_for_required_reboot data", "collect_inputs",
                 "bootstrap_node_token")
        for n in names:
            self.assertEqual(MAIN_CALLS.count(n), 1, n)
        order = [MAIN_CALLS.index(n) for n in names]
        self.assertEqual(order, sorted(order))
        self.assertIn("  data_verify_pending_node_token || exit 1\n", function_body(SRC, "data_preflight_sync_contract"))

    def _top_level(self, tmp: str, content: str | None, mode: int = 0o600, slug: str = "", symlink: bool = False):
        tmpd = pathlib.Path(tmp)
        bin_dir = tmpd / "bin"
        bin_dir.mkdir()
        stat_shim(bin_dir)
        pending = tmpd / "data.node-token"
        if content is not None:
            target = tmpd / "real-token" if symlink else pending
            target.write_text(content, encoding="utf-8")
            target.chmod(mode)
            if symlink:
                pending.symlink_to(target)
                if hasattr(os, "lchmod"):
                    # A link with owner-only bits (possible on macOS) passes
                    # the mode check, so only the -L test refuses it.
                    os.lchmod(pending, 0o600)
        prog = "\n".join([
            "set -Eeuo pipefail", 'NODE_TOKEN=""', pending_block(),
            'printf "slug=%s\\n" "${NODE_SLUG:-}"',
            'if [[ -n "${NODE_TOKEN}" ]]; then printf "token=loaded\\n"; else printf "token=empty\\n"; fi',
            'if [[ -n "${DATA_PENDING_NODE_TOKEN}" ]]; then printf "pending=loaded\\n"; else printf "pending=empty\\n"; fi',
            '[[ -z "${DATA_PENDING_NODE_TOKEN}" || "${DATA_PENDING_NODE_TOKEN}" == "$EXPECT" ]] || { echo mismatch; exit 9; }',
        ])
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "DATA_PENDING_NODE_TOKEN_FILE": str(pending),
               "EXPECT": NODE_TOKEN, "DATA_PENDING_NODE_TOKEN": OTHER_TOKEN}
        if slug:
            env["NODE_SLUG"] = slug
        return run(prog, env)

    def test_rerun_after_the_reboot_loads_the_pending_token_aside(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out = self._top_level(tmp, f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("slug=germany-de1", out.stdout)
            # Loaded aside, never straight into NODE_TOKEN (see the withdrawal).
            self.assertIn("token=empty", out.stdout)
            self.assertIn("pending=loaded", out.stdout)
            self.assertIn(str(pathlib.Path(tmp, "data.node-token")), out.stderr, "loaded silently")
            self.assertNotIn(NODE_TOKEN, out.stdout + out.stderr)
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out = self._top_level(tmp, f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n", slug="germany-de1")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("pending=loaded", out.stdout)

    def test_pending_token_for_another_slug_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out = self._top_level(tmp, f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n", slug="canada-ca1")
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("slug=canada-ca1", out.stdout)
            self.assertIn("pending=empty", out.stdout)
            self.assertIn("issued for germany-de1", out.stderr)

    def test_unsafe_or_malformed_pending_file_is_refused(self):
        cases = [
            (f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n", 0o640, False),
            (f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n", 0o600, True),
            (f"NODE_SLUG=germany-de1\nNODE_TOKEN=short\n", 0o600, False),
            (f"NODE_SLUG=Bad_Slug\nNODE_TOKEN={NODE_TOKEN}\n", 0o600, False),
            (f"NODE_TOKEN={NODE_TOKEN}\n", 0o600, False),
        ]
        for content, mode, symlink in cases:
            with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
                out = self._top_level(tmp, content, mode=mode, symlink=symlink)
                self.assertEqual(out.returncode, 1, (oct(mode), symlink, out.stdout, out.stderr))
                self.assertNotIn(NODE_TOKEN, out.stdout + out.stderr)

    def test_no_pending_file_changes_nothing_and_ignores_an_injected_value(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out = self._top_level(tmp, None)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("token=empty", out.stdout)
            self.assertIn("pending=empty", out.stdout)

    def _clear(self, tmp: str, node_env_text: str, token: str):
        tmpd = pathlib.Path(tmp)
        pending = tmpd / "data.node-token"
        pending.write_text(f"NODE_SLUG=germany-de1\nNODE_TOKEN={NODE_TOKEN}\n", encoding="utf-8")
        node_env = tmpd / "node.env"
        node_env.write_text(node_env_text, encoding="utf-8")
        prog = "\n".join(["set -Eeuo pipefail", LOG_STUBS, optional_functions(SRC, *BOOTSTRAP_FUNCS),
                          "bootstrap_node_token"])
        env = {"NODE_TOKEN": token, "NODE_SLUG": "germany-de1", "NODE_ENV_FILE": str(node_env),
               "DATA_PENDING_NODE_TOKEN_FILE": str(pending)}
        return run(prog, env), pending

    def test_pending_copy_goes_once_node_env_holds_the_token(self):
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out, pending = self._clear(tmp, f'NODE_TOKEN="{NODE_TOKEN}"\n', NODE_TOKEN)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(pending.exists(), "pending token copy left behind after node.env holds it")
        with tempfile.TemporaryDirectory(prefix="sync26-") as tmp:
            out, pending = self._clear(tmp, 'NODE_TOKEN=""\n', NODE_TOKEN)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertTrue(pending.exists(), "pending token removed before node.env held it")

    def test_pending_file_is_in_the_secret_inventory(self):
        body = function_body(SRC, "data_secret_path_specs")
        self.assertIn('"${DATA_PENDING_NODE_TOKEN_FILE}|077|', body)


# --------------------------------------------------------------------------
# SYNC-12: registration proves only that the host it went through resolved.
# The pubkey sync and the self-resync each wait (bounded) for their own host
# to resolve, never re-send a request, and run only after a registered POST.
# --------------------------------------------------------------------------
class HubCallsAfterRegistration(unittest.TestCase):
    def test_pubkey_and_resync_run_only_after_a_successful_register(self):
        reg_block = REGISTER.index('if ! registration_response="$(post_registration "$HUB_REGISTER_URL")"; then')
        pub_call = REGISTER.index("\n  sync_hub_ssh_pubkey || true\n")
        resync = REGISTER.index('resync_response="$(printf')
        self.assertLess(reg_block, pub_call)
        self.assertLess(pub_call, resync)
        failure = REGISTER[reg_block:pub_call]
        self.assertIn("exit 1", failure)
        self.assertIn("set -Eeuo pipefail", REGISTER.splitlines()[1])
        self.assertEqual(REGISTER.count("sync_hub_ssh_pubkey || true"), 1)

    def _tail(self, tmp: str, unresolved: dict[str, int], *, pubkey_url: str, api_base: str, register_url: str,
              resync_url: str | None = None, hang: tuple[str, ...] = (), env_extra: dict | None = None,
              real_sleep: bool = False):
        """unresolved: host -> number of failing lookups before it resolves.
        hang: hosts whose lookup never answers (it sleeps until killed)."""
        tmpd = pathlib.Path(tmp)
        trace = tmpd / "trace"
        state = tmpd / "state"
        state.mkdir()
        (state / "unresolved").write_text("".join(f"{h}={n}\n" for h, n in unresolved.items()))
        (state / "hang").write_text("".join(f"{h}\n" for h in hang))
        tail = REGISTER[REGISTER.index('fallback_register_url="${HUB_REGISTER_URL_FALLBACK:-'):]
        tail = tail.replace('peer_runtime_dir="/run/winsvpn"', f'peer_runtime_dir="{tmpd}/run"')
        prog = "\n".join([
            "set -Eeuo pipefail", "payload='{}'", TIMEOUT_STUB,
            "getent() {",
            f'  local host="$2" n=0 limit f="{state}/getent.$2"',
            '  [[ -f "$f" ]] && n="$(cat "$f")"',
            '  n=$((n + 1)); printf "%s" "$n" > "$f"',
            f'  printf "getent %s\\n" "$host" >> "{trace}"',
            # A resolver that never answers: this lookup blocks until killed.
            f'  if grep -qx "$host" "{state}/hang"; then exec sleep 60; fi',
            f'  limit="$(sed -n "s/^$host=//p" "{state}/unresolved")"',
            '  (( n > ${limit:-0} ))',
            "}",
            ":" if real_sleep else "sleep() { :; }",
            f'sync_hub_ssh_pubkey() {{ printf "PUBKEY\\n" >> "{trace}"; }}',
            "curl() {",
            '  if [[ " $* " == *" --config - "* ]]; then',
            f'    cat > /dev/null; printf "RESYNC\\n" >> "{trace}"; printf \'{{"ok":true,"failed":0}}\'; return 0',
            "  fi",
            f'  cat > /dev/null; printf "REGISTER\\n" >> "{trace}"',
            '  if [[ " $* " == *"fail.example.test"* ]]; then printf \'{"detail":"down"}\'; return 22; fi',
            "  printf '{\"ok\":true}'",
            "}",
            tail,
            'echo DONE',
        ])
        env = {"HUB_REGISTER_URL": register_url, "HUB_API_BASE": api_base, "HUB_PUBKEY_URL": pubkey_url,
               "NODE_TOKEN": NODE_TOKEN, "NODE_SLUG": "germany-de1", "active_awg_container": "amnezia-awg2",
               "container_started_at": "t1", "peer_count": "0", "HUB_DNS_WAIT_DELAY_SECONDS": "0"}
        if resync_url is not None:
            env["HUB_NODE_RESYNC_PEERS_URL"] = resync_url
        env.update(env_extra or {})
        begin = time.monotonic()
        out = run(prog, env, timeout=120)
        elapsed = time.monotonic() - begin
        return out, (trace.read_text() if trace.exists() else ""), elapsed

    def test_a_late_resolving_host_is_waited_for(self):
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(tmp, {"b.example.test": 2}, register_url="https://a.example.test/api/v1/nodes/register",
                                       pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://b.example.test",
                                       resync_url="https://b.example.test:8443/api/v1/nodes/germany-de1/resync-peers")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("DONE", out.stdout)
            lines = trace.splitlines()
            self.assertEqual(sum(l.startswith("REGISTER") for l in lines), 1)
            self.assertEqual(lines.count("PUBKEY"), 1, trace)
            self.assertEqual(lines.count("RESYNC"), 1, trace)
            self.assertLess(lines.index("getent b.example.test"), lines.index("PUBKEY"))
            # Resolved once, then remembered for the resync.
            self.assertEqual(lines.count("getent b.example.test"), 3, trace)

    def test_an_unresolvable_host_skips_its_call_and_says_so(self):
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(tmp, {"b.example.test": 99}, register_url="https://a.example.test/api/v1/nodes/register",
                                       pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://b.example.test")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("DONE", out.stdout)
            lines = trace.splitlines()
            self.assertNotIn("PUBKEY", lines)
            self.assertNotIn("RESYNC", lines, "the self-resync POST was sent to a host that does not resolve")
            self.assertIn("Hub host b.example.test did not resolve (5 lookups", out.stderr)
            self.assertIn("already failed to resolve in this run", out.stderr)
            # One bounded wait per host per run: 5 lookups, not 5 per call site.
            self.assertEqual(lines.count("getent b.example.test"), 5)

    def test_the_registration_host_needs_no_lookup(self):
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(tmp, {"a.example.test": 99}, register_url="https://a.example.test/api/v1/nodes/register",
                                       pubkey_url="https://a.example.test/api/v1/pubkey", api_base="https://A.example.test:443")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertNotIn("getent", trace)
            self.assertIn("PUBKEY", trace)
            self.assertIn("RESYNC", trace)

    def test_a_fallback_registration_proves_only_the_fallback_host(self):
        # The primary host failed; only the fallback's host is known to resolve.
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(tmp, {}, register_url="https://fail.example.test/api/v1/nodes/register",
                                       pubkey_url="https://fail.example.test/api/v1/pubkey",
                                       api_base="https://b.example.test",
                                       env_extra={"HUB_REGISTER_URL_FALLBACK": "https://b.example.test/api/v1/nodes/register"})
            self.assertEqual(out.returncode, 0, out.stderr)
            lines = trace.splitlines()
            self.assertEqual(sum(l.startswith("REGISTER") for l in lines), 2, trace)
            self.assertIn("getent fail.example.test", lines, "the failed primary host was treated as resolved")
            self.assertNotIn("getent b.example.test", lines, "the fallback host was looked up again")

    def test_the_pubkey_sync_falls_back_to_the_api_base_host(self):
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(tmp, {"b.example.test": 99}, register_url="https://a.example.test/api/v1/nodes/register",
                                       pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://a.example.test")
            self.assertEqual(out.returncode, 0, out.stderr)
            lines = trace.splitlines()
            self.assertEqual(lines.count("PUBKEY"), 1, trace)
            self.assertEqual(lines.count("RESYNC"), 1, "the self-resync POST was repeated or skipped")

    def test_an_ip_literal_host_needs_no_lookup(self):
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(tmp, {"192.0.2.10": 99}, register_url="https://a.example.test/api/v1/nodes/register",
                                       pubkey_url="https://192.0.2.10/api/v1/pubkey", api_base="https://192.0.2.10:443",
                                       resync_url="https://192.0.2.10:8443/api/v1/nodes/germany-de1/resync-peers")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertNotIn("getent", trace)
            self.assertIn("PUBKEY", trace)
            self.assertIn("RESYNC", trace)

    def test_the_dns_defaults_are_the_documented_ones(self):
        body = function_body(REGISTER, "wait_for_hub_host")
        for text in ('tries="${HUB_DNS_WAIT_TRIES:-5}"', 'delay="${HUB_DNS_WAIT_DELAY_SECONDS:-2}"',
                     'limit="${HUB_DNS_LOOKUP_TIMEOUT_SECONDS:-2}"', 'budget="${HUB_DNS_WAIT_BUDGET_SECONDS:-10}"',
                     'run_budget="${HUB_DNS_RUN_BUDGET_SECONDS:-20}"', "|| tries=5\n", "|| delay=2\n", "|| limit=2\n",
                     "|| budget=10\n", "|| run_budget=20\n"):
            self.assertIn(text, body)

    def test_default_bounds_with_three_hosts_that_never_answer(self):
        # CLAUDE-N-6: defaults only, real pauses. One wait at most budget + 1
        # (11 s), the whole run at most run budget + 3 (23 s); measured on
        # colima-l80 as 10.04 s and 20.08 s.
        hosts = ("b.example.test", "c.example.test", "d.example.test")
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, elapsed = self._tail(
                tmp, {}, hang=hosts, register_url="https://a.example.test/api/v1/nodes/register",
                pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://c.example.test",
                resync_url="https://d.example.test/api/v1/nodes/germany-de1/resync-peers",
                env_extra={"HUB_DNS_WAIT_DELAY_SECONDS": ""}, real_sleep=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            counts = [trace.count(f"getent {h}") for h in hosts]
            # Whole-second SECONDS moves the split (colima-l80: 3, 3, 0; macOS
            # also 3, 2, 1 and 2, 3, 1), never the per-host maximum of 3 or the
            # total of 6.
            self.assertTrue(all(c <= 3 for c in counts), counts)
            self.assertLessEqual(sum(counts), 6, counts)
            self.assertLess(elapsed, 23.5, f"three waits took {elapsed:.1f} s")
            self.assertGreater(elapsed, 18.0, f"three waits took only {elapsed:.1f} s")

    def test_a_host_never_tried_says_so(self):
        # Seat C T3: a host the spent budget leaves untried is not reported as
        # "did not resolve (0 lookups ...)".
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, _ = self._tail(
                tmp, {}, register_url="https://a.example.test/api/v1/nodes/register",
                pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://b.example.test",
                env_extra={"HUB_DNS_RUN_BUDGET_SECONDS": "1"})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertNotIn("getent b.example.test", trace)
            self.assertIn("Hub host b.example.test was not looked up: no DNS budget left", out.stderr)
            self.assertNotIn("(0 lookups", out.stderr)

    def test_the_pause_is_charged_to_the_wait_budget(self):
        # A pause starts only if it and one more lookup still fit (budget 2,
        # lookup 1 s, pause 2 s): one lookup, then stop, about 1 s.
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, elapsed = self._tail(
                tmp, {}, hang=("b.example.test",), register_url="https://a.example.test/api/v1/nodes/register",
                pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://b.example.test",
                env_extra={"HUB_DNS_LOOKUP_TIMEOUT_SECONDS": "1", "HUB_DNS_WAIT_BUDGET_SECONDS": "2",
                           "HUB_DNS_WAIT_DELAY_SECONDS": "2", "HUB_DNS_WAIT_TRIES": "50"}, real_sleep=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(trace.count("getent b.example.test"), 1, trace)
            self.assertLess(elapsed, 2.5, f"the wait took {elapsed:.1f} s")

    def test_a_slow_success_is_charged_to_the_run_budget(self):
        block = REGISTER[REGISTER.index("hub_url_host() {"):REGISTER.index("pubkey_host_ready=0\n")]
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            flag = pathlib.Path(tmp, "hung-once")
            prog = "\n".join([
                "set -Eeuo pipefail", 'registered_url="https://a.example.test/x"', TIMEOUT_STUB,
                # The first lookup never answers (killed at 1 s); the second resolves.
                f'getent() {{ if [[ ! -e "{flag}" ]]; then : > "{flag}"; exec sleep 60; fi; return 0; }}',
                "sleep() { :; }", block,
                'wait_for_hub_host "https://b.example.test/x"',
                'printf "spent=%s\\n" "${hub_dns_spent}"',
            ])
            out = run(prog, {"HUB_DNS_LOOKUP_TIMEOUT_SECONDS": "1", "HUB_DNS_WAIT_DELAY_SECONDS": "0"})
            self.assertEqual(out.returncode, 0, out.stderr)
            spent = int(re.search(r"spent=(\d+)", out.stdout).group(1))
            self.assertGreaterEqual(spent, 1, "a slow success was not charged to the run budget")

    def test_a_lookup_that_never_answers_is_killed_at_its_deadline(self):
        # OI-SYNCDP-11: glibc alone would hold one lookup for timeout x attempts.
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, elapsed = self._tail(
                tmp, {}, hang=("b.example.test",), register_url="https://a.example.test/api/v1/nodes/register",
                pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://b.example.test",
                env_extra={"HUB_DNS_LOOKUP_TIMEOUT_SECONDS": "1", "HUB_DNS_WAIT_BUDGET_SECONDS": "3",
                           "HUB_DNS_WAIT_TRIES": "50"})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertNotIn("PUBKEY", trace)
            self.assertNotIn("RESYNC", trace)
            self.assertIn("lookups of at most 1 s, within 3 s", out.stderr)
            # Budget 3 s, plus 1 s of SECONDS granularity, plus harness slack;
            # the tries count (50) does not bound it, the budget does.
            self.assertLess(elapsed, 6.5, f"one wait took {elapsed:.1f} s")
            self.assertGreaterEqual(trace.count("getent b.example.test"), 2)
            self.assertLessEqual(trace.count("getent b.example.test"), 4)

    def test_the_lookup_is_bounded_by_timeout_kill_not_a_pid_signal(self):
        # OI-SYNCDP-18: the deadline is `timeout -s KILL`, which signals its
        # own child. The lookup itself signals no numeric PID (which bash may
        # already have reaped) and starts no sleep timer.
        block = REGISTER[REGISTER.index("hub_url_host() {"):REGISTER.index("pubkey_host_ready=0\n")]
        with tempfile.TemporaryDirectory(prefix="sync18-") as tmp:
            tmpd = pathlib.Path(tmp)
            bindir = tmpd / "bin"
            bindir.mkdir()
            trace = tmpd / "trace"
            write_exec(bindir / "sleep", f'#!/bin/sh\necho "sleep $*" >> "{trace}"\nexec /bin/sleep "$@"\n')
            prog = "\n".join([
                "set -Eeuo pipefail", 'registered_url="https://a.example.test/x"', TIMEOUT_STUB,
                f'kill() {{ printf "kill %s\\n" "$*" >> "{trace}"; builtin kill "$@"; }}',
                'getent() { [[ "$2" == ok.example.test ]] && return 0; exec /bin/sleep 60; }',
                block,
                'rc=0; hub_dns_lookup ok.example.test 1 || rc=$?; printf "ok=%s\\n" "$rc"',
                'rc=0; hub_dns_lookup hang.example.test 1 || rc=$?; printf "hang=%s\\n" "$rc"',
            ])
            begin = time.monotonic()
            out = run(prog, {"PATH": f"{bindir}:{os.environ['PATH']}", "TIMEOUT_TRACE": str(trace)})
            elapsed = time.monotonic() - begin
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("ok=0", out.stdout)
            self.assertNotIn("hang=0", out.stdout)
            self.assertLess(elapsed, 4.0, f"a 1 s lookup deadline took {elapsed:.1f} s")
            self.assertEqual(trace.read_text().splitlines() if trace.exists() else [],
                             ["timeout -s KILL 1 getent ahosts ok.example.test",
                              "timeout -s KILL 1 getent ahosts hang.example.test"])

    def test_a_real_timeout_kills_a_hung_lookup(self):
        # OI-SYNCDP-18 with the real timeout(1) on PATH, GNU or not (Ubuntu
        # 26.04 ships uutils coreutils): any implementation that takes
        # `-s KILL N CMD` runs this. It asserts behaviour only: the hung
        # getent is gone by the deadline and the lookup is nonzero. The exit
        # status itself is not pinned; callers test nonzero only.
        timeout_bin = shutil.which("timeout")
        if timeout_bin is None:
            self.skipTest("no timeout(1) on PATH")
        try:
            probe = subprocess.run([timeout_bin, "-s", "KILL", "5", "true"], capture_output=True, timeout=30)
            usable = probe.returncode == 0
        except (OSError, subprocess.SubprocessError):
            usable = False
        if not usable:
            self.skipTest("the timeout(1) on PATH does not take -s KILL")
        block = REGISTER[REGISTER.index("hub_url_host() {"):REGISTER.index("pubkey_host_ready=0\n")]
        with tempfile.TemporaryDirectory(prefix="sync18-") as tmp:
            bindir = pathlib.Path(tmp, "bin")
            bindir.mkdir()
            pidfile = pathlib.Path(tmp, "getent.pid")
            write_exec(bindir / "getent", '#!/bin/sh\n[ "$2" = ok.example.test ] && exit 0\n'
                       f'echo $$ > "{pidfile}"\nexec sleep 60\n')
            prog = "\n".join([
                "set -Eeuo pipefail", 'registered_url="https://a.example.test/x"', block,
                'rc=0; hub_dns_lookup ok.example.test 1 || rc=$?; printf "ok=%s\\n" "$rc"',
                'rc=0; hub_dns_lookup hang.example.test 1 || rc=$?; printf "hang=%s\\n" "$rc"',
            ])
            begin = time.monotonic()
            out = run(prog, {"PATH": f"{bindir}:{os.environ['PATH']}"})
            elapsed = time.monotonic() - begin
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("ok=0", out.stdout)
            hang = re.search(r"hang=(\d+)", out.stdout)
            self.assertIsNotNone(hang, out.stdout)
            self.assertNotEqual(int(hang.group(1)), 0, "a hung lookup counted as resolved")
            self.assertLess(elapsed, 4.0, f"a 1 s lookup deadline took {elapsed:.1f} s")
            pid = int(pidfile.read_text().split()[0])
            for _ in range(40):          # a killed child may stay a zombie for a moment
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail(f"the hung getent (pid {pid}) outlived its deadline")

    def test_the_run_budget_caps_all_waits_together(self):
        hosts = ("b.example.test", "c.example.test", "d.example.test")
        with tempfile.TemporaryDirectory(prefix="sync12-") as tmp:
            out, trace, elapsed = self._tail(
                tmp, {}, hang=hosts, register_url="https://a.example.test/api/v1/nodes/register",
                pubkey_url="https://b.example.test/api/v1/pubkey", api_base="https://c.example.test",
                resync_url="https://d.example.test/api/v1/nodes/germany-de1/resync-peers",
                env_extra={"HUB_DNS_LOOKUP_TIMEOUT_SECONDS": "1", "HUB_DNS_WAIT_BUDGET_SECONDS": "3",
                           "HUB_DNS_RUN_BUDGET_SECONDS": "3", "HUB_DNS_WAIT_TRIES": "50"})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertNotIn("PUBKEY", trace)
            self.assertNotIn("RESYNC", trace)
            # Run budget 3 s (three per-wait budgets would be 9 s), plus 1 s of
            # granularity per host, plus harness slack.
            self.assertLess(elapsed, 7.0, f"three waits took {elapsed:.1f} s")
            self.assertLessEqual(trace.count("getent "), 5, trace)
            self.assertEqual(out.stderr.count("did not resolve") + out.stderr.count("was not looked up"), 3)


# --------------------------------------------------------------------------
# SYNC-13
# --------------------------------------------------------------------------
class BackupHostId(unittest.TestCase):
    def _resolve(self, tmp: str, env: dict[str, str], hostname: str = "ubuntu"):
        tmpd = pathlib.Path(tmp)
        bin_dir = tmpd / "bin"
        bin_dir.mkdir(exist_ok=True)
        write_exec(bin_dir / "hostname", f"#!/bin/sh\necho {hostname}\n")
        uuid_file = tmpd / "uuid"
        uuid_file.write_text(f"{uuid.uuid4()}\n")
        body = function_body(SRC, "resolve_node_backup_host_id")
        if not os.path.exists("/proc/sys/kernel/random/uuid"):
            # No /proc on macOS: point the function's entropy source at a fixture.
            body = body.replace("/proc/sys/kernel/random/uuid", str(uuid_file))
        prog = "\n".join(["set -Eeuo pipefail", LOG_STUBS, body,
                          'resolve_node_backup_host_id', 'printf "id=%s\\n" "${RESOLVED_BACKUP_HOST_ID}"'])
        full = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "BACKUP_HOST_ID_FILE": str(tmpd / "etc" / "backup-host-id")}
        full.update(env)
        return run(prog, full), tmpd / "etc" / "backup-host-id"

    def test_minted_from_the_slug_pinned_and_stable(self):
        with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
            out, id_file = self._resolve(tmp, {"NODE_SLUG": "germany-de1"})
            self.assertEqual(out.returncode, 0, out.stderr)
            first = re.search(r"^id=(.*)$", out.stdout, re.M).group(1)
            self.assertRegex(first, r"^germany-de1-[0-9a-f]{12}$")
            self.assertEqual(stat.S_IMODE(id_file.stat().st_mode), 0o600)
            again, _ = self._resolve(tmp, {"NODE_SLUG": "renamed-node"})
            self.assertIn(f"id={first}", again.stdout, "the pinned id changed with the slug")

    def test_two_ubuntu_hosts_get_different_ids(self):
        ids = []
        for _ in range(2):
            with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
                out, _ = self._resolve(tmp, {}, hostname="ubuntu")
                self.assertEqual(out.returncode, 0, out.stderr)
                ids.append(re.search(r"^id=(.*)$", out.stdout, re.M).group(1))
        self.assertNotEqual(ids[0], ids[1])
        for value in ids:
            self.assertRegex(value, r"^ubuntu-[0-9a-f]{12}$")

    def test_explicit_id_wins_and_bad_values_are_refused(self):
        with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
            out, id_file = self._resolve(tmp, {"BACKUP_HOST_ID": "spain-edge-01"})
            self.assertIn("id=spain-edge-01", out.stdout)
            self.assertFalse(id_file.exists())
            bad, _ = self._resolve(tmp, {"BACKUP_HOST_ID": "../escape"})
            self.assertEqual(bad.returncode, 1)
        with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
            etc = pathlib.Path(tmp, "etc")
            etc.mkdir()
            (etc / "backup-host-id").write_text("not valid/\n")
            bad, _ = self._resolve(tmp, {"NODE_SLUG": "germany-de1"})
            self.assertEqual(bad.returncode, 1)

    def test_backup_env_carries_the_id(self):
        body = function_body(SRC, "configure_rclone_credentials")
        self.assertIn("resolve_node_backup_host_id || return 1", body)
        self.assertIn("BACKUP_HOST_ID=%s", body)
        self.assertLess(body.index("resolve_node_backup_host_id"), body.index("> /etc/winsvpn/backup.env"))

    def _backup_head(self, tmp: str, backup_env: str | None):
        tmpd = pathlib.Path(tmp)
        bin_dir = tmpd / "bin"
        bin_dir.mkdir()
        write_exec(bin_dir / "hostname", "#!/bin/sh\necho ubuntu\n")
        src_root = tmpd / "root"
        (src_root / "etc" / "winsvpn").mkdir(parents=True)
        if backup_env is not None:
            (src_root / "etc" / "winsvpn" / "backup.env").write_text(backup_env)
        runtime = tmpd / "run"
        runtime.mkdir()
        head = BACKUP[:BACKUP.index('REQUIRED="${REQUIRE_REMOTE_BACKUP:-1}"\n')]
        prog = head + 'printf "REMOTE=%s\\nARCHIVE_NAME=%s\\n" "${REMOTE}" "${ARCHIVE_NAME}"\n'
        return run(prog, {"PATH": f"{bin_dir}:{os.environ['PATH']}", "WINS_BACKUP_SOURCE_ROOT": str(src_root),
                          "WINS_BACKUP_RUNTIME_ROOT": str(runtime)})

    def test_backup_script_keys_remote_and_archive_on_the_id(self):
        with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
            out = self._backup_head(tmp, "RCLONE_REMOTE=GoogleDrive_secured\nBACKUP_HOST_ID=germany-de1-0123456789ab\n")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("REMOTE=GoogleDrive_secured:winsvpn-backups/germany-de1-0123456789ab", out.stdout)
            self.assertRegex(out.stdout, r"ARCHIVE_NAME=wins-node-backup-germany-de1-0123456789ab-\d{8}_\d{6}\.tar\.gz")
        with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
            # No hostname fallback (implementation review T1 S2-Q7): a
            # backup.env without BACKUP_HOST_ID refuses before naming anything.
            out = self._backup_head(tmp, "RCLONE_REMOTE=GoogleDrive_secured\n")
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("BACKUP_HOST_ID missing; re-run the installer", out.stderr)
            self.assertNotIn("REMOTE=", out.stdout)
        with tempfile.TemporaryDirectory(prefix="sync13-") as tmp:
            out = self._backup_head(tmp, "BACKUP_HOST_ID=../other\n")
            self.assertEqual(out.returncode, 1)


# --------------------------------------------------------------------------
# SYNC-14
# --------------------------------------------------------------------------
class RevisionReporting(unittest.TestCase):
    def test_gateway_installer_stamps_itself(self):
        with tempfile.TemporaryDirectory(prefix="sync14-") as tmp:
            stamp = pathlib.Path(tmp, "winsvpn", ".winn3_gateway_installer.sha256")
            prog = "\n".join(["set -Eeuo pipefail", LOG_STUBS, 'MODE=install',
                              function_body(GSRC, "record_gateway_code_stamp"), "record_gateway_code_stamp"])
            out = run(prog, {"WINN3_GATEWAY_CODE_STAMP": str(stamp), "WINN3_GATEWAY_INSTALLER_PATH": str(GATEWAY)})
            self.assertEqual(out.returncode, 0, out.stderr)
            lines = stamp.read_text().splitlines()
            self.assertEqual(lines[0], hashlib.sha256(GATEWAY.read_bytes()).hexdigest())
            self.assertIn("install_mode=install", lines)
            self.assertEqual(stat.S_IMODE(stamp.stat().st_mode), 0o600)
            self.assertIn('WINN3_GATEWAY_CODE_STAMP="${WINN3_GATEWAY_CODE_STAMP:-/etc/winsvpn/.winn3_gateway_installer.sha256}"', GSRC)

    def test_gateway_stamp_failure_never_fails_the_install(self):
        prog = "\n".join(["set -Eeuo pipefail", LOG_STUBS, 'MODE=install',
                          function_body(GSRC, "record_gateway_code_stamp"), "record_gateway_code_stamp", "echo reached"])
        out = run(prog, {"WINN3_GATEWAY_CODE_STAMP": "/nonexistent-root-dir/x/stamp",
                         "WINN3_GATEWAY_INSTALLER_PATH": str(GATEWAY)})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("reached", out.stdout)

    def test_gateway_main_stamps_after_the_unit_is_written(self):
        gmain = function_body(GSRC, "main")
        calls = [l.strip() for l in gmain.splitlines()]
        self.assertEqual(calls.count("record_gateway_code_stamp"), 1)
        at = calls.index("record_gateway_code_stamp")
        self.assertGreater(at, calls.index("write_unit"))
        self.assertGreater(at, calls.index("write_env_file"))
        self.assertGreater(at, calls.index("install_binary"))
        # N-3: the previous stamp goes before the first gateway write.
        self.assertEqual(calls.count("invalidate_gateway_code_stamp"), 1)
        inv = calls.index("invalidate_gateway_code_stamp")
        self.assertGreater(inv, calls.index("verify_staged_binary"))
        self.assertLess(inv, calls.index("ensure_service_user"))
        self.assertLess(inv, calls.index("install_binary"))

    def _stamp_run(self, tmp: str, *, sha256sum_rc: int | None = None, extra: str = "", func: str = "record_gateway_code_stamp"):
        tmpd = pathlib.Path(tmp)
        stamp = tmpd / "winsvpn" / ".winn3_gateway_installer.sha256"
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(f"{'a' * 64}\ninstall_mode=install\n")
        bin_dir = tmpd / "bin"
        bin_dir.mkdir(exist_ok=True)
        if sha256sum_rc is not None:
            write_exec(bin_dir / "sha256sum", f"#!/bin/sh\nexit {sha256sum_rc}\n")
        prog = "\n".join(["set -Eeuo pipefail", LOG_STUBS, 'die() { err "$*"; exit 1; }', 'MODE=install',
                          function_body(GSRC, "invalidate_gateway_code_stamp"),
                          function_body(GSRC, "record_gateway_code_stamp"), extra, func, "echo reached"])
        out = run(prog, {"PATH": f"{bin_dir}:{os.environ['PATH']}", "WINN3_GATEWAY_CODE_STAMP": str(stamp),
                         "WINN3_GATEWAY_INSTALLER_PATH": str(GATEWAY)})
        return out, stamp

    def test_hash_command_failure_is_nonfatal_and_drops_the_old_stamp(self):
        # Sol N-2 and N-3: sha256sum exiting 1 under errexit, with an old valid stamp.
        with tempfile.TemporaryDirectory(prefix="sync14-") as tmp:
            out, stamp = self._stamp_run(tmp, sha256sum_rc=1)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("reached", out.stdout)
            self.assertIn("unprovable", out.stderr)
            self.assertFalse(stamp.exists(), "a failed hash kept the old stamp")
            unit = pathlib.Path(tmp, "unit")
            unit.write_text("[Service]\n")
            rev = run("\n".join(["set -Eeuo pipefail", function_body(REGISTER, "winn3_gateway_code_revision"),
                                  "winn3_gateway_code_revision"]),
                      {"WINN3_GATEWAY_UNIT_FILE": str(unit), "WINN3_GATEWAY_CODE_STAMP": str(stamp)})
            self.assertEqual(rev.stdout, "unprovable")

    def test_stamp_write_failure_leaves_no_stamp(self):
        with tempfile.TemporaryDirectory(prefix="sync14-") as tmp:
            out, stamp = self._stamp_run(tmp, extra="mv() { return 1; }")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("reached", out.stdout)
            self.assertFalse(stamp.exists(), "a failed write kept the old stamp")
            self.assertEqual([p.name for p in stamp.parent.iterdir()], [], "a temporary stamp was left behind")

    def test_install_invalidates_the_old_stamp_or_refuses(self):
        with tempfile.TemporaryDirectory(prefix="sync14-") as tmp:
            out, stamp = self._stamp_run(tmp, func="invalidate_gateway_code_stamp")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(stamp.exists())
        with tempfile.TemporaryDirectory(prefix="sync14-") as tmp:
            out, stamp = self._stamp_run(tmp, func="invalidate_gateway_code_stamp", extra="rm() { return 1; }")
            self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
            self.assertNotIn("reached", out.stdout)
            self.assertIn("refusing to install", out.stderr)

    def _register_rev(self, tmp: str, unit: bool, stamp_text: str | None, dp_stamp_text: str | None):
        tmpd = pathlib.Path(tmp)
        unit_file = tmpd / "winn3-gateway.service"
        if unit:
            unit_file.write_text("[Service]\n")
        stamp = tmpd / "gw.sha256"
        if isinstance(stamp_text, tuple):
            # Seat C N-1: a symlinked stamp, even to valid content, is unprovable.
            (tmpd / "elsewhere").write_text(stamp_text[1])
            stamp.symlink_to(tmpd / "elsewhere")
        elif stamp_text is not None:
            stamp.write_text(stamp_text)
        dp = tmpd / "dp.sha256"
        if dp_stamp_text is not None:
            dp.write_text(dp_stamp_text)
        prog = "\n".join(["set -Eeuo pipefail",
                          function_body(REGISTER, "winn3_gateway_code_revision"),
                          function_body(REGISTER, "data_plane_source_revision"),
                          'printf "gw=%s src=%s\\n" "$(winn3_gateway_code_revision)" "$(data_plane_source_revision)"'])
        return run(prog, {"WINN3_GATEWAY_UNIT_FILE": str(unit_file), "WINN3_GATEWAY_CODE_STAMP": str(stamp),
                          "DATA_PLANE_CODE_STAMP": str(dp)})

    def test_register_reports_the_gateway_and_source_revisions(self):
        sha = "a" * 64
        cases = [
            (False, None, None, "gw=none src=unknown"),
            (True, None, f"{sha}\nsource_revision=2b846c9a\n", "gw=unprovable src=2b846c9a"),
            (True, "garbage\n", f"{sha}\nsource_revision=bad value$\n", "gw=unprovable src=unknown"),
            (True, f"{sha}\ninstall_mode=install\n", f"{sha}\nsource_revision=unknown\n", f"gw=sha256:{sha} src=unknown"),
            (True, ("symlink", f"{sha}\ninstall_mode=install\n"), None, "gw=unprovable src=unknown"),
        ]
        for unit, gw, dp, want in cases:
            with tempfile.TemporaryDirectory(prefix="sync14-") as tmp:
                out = self._register_rev(tmp, unit, gw, dp)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn(want, out.stdout, (unit, gw, dp))

    def test_payload_carries_the_new_fields(self):
        payload = REGISTER[REGISTER.index('payload="$('):]
        payload = payload[:payload.index("\n)\"\n") + 4]
        numeric = ("wg_port", "stealth_public_port", "xray_inbound_port", "awg_rx_bytes", "awg_tx_bytes",
                   "wan_rx_bytes", "wan_tx_bytes", "peer_count", "NODE_MAX_PEERS")
        assigns = [f'{n}=1' for n in numeric] + [
            'WG_PORT=51820', 'STEALTH_PUBLIC_PORT=443', 'XRAY_INBOUND_PORT=10085',
            f'NODE_TOKEN="{NODE_TOKEN}"', f'XRAY_UUID="{XRAY_UUID}"', 'NODE_SLUG=s', 'NODE_NAME=n', 'NODE_FLAG=f',
            'NODE_HOST=198.51.100.20', 'STEALTH_HOST=h', 'NODE_SSH_HOST=x', 'XRAY_PATH=/p', 'XRAY_SECURITY=none',
            'XRAY_SNI=h', 'pubkey=k', 'obfs={}', 'tunnel_gateway_ipv4=', 'data_plane_code_revision_value=unprovable',
            'regional_aliases_json=[]', 'stealth_transports_json=[]', 'load_cpu_pct=null', 'load_net_pct=null',
            'load_sessions_pct=null', f'winn3_gateway_code_revision_value=sha256:{"b" * 64}',
            'data_plane_source_revision_value=2b846c9a', 'canary_ok=true', 'canary_at=1790000000']
        prog = "\n".join(["set -Eeuo pipefail", *assigns, payload, 'printf "%s" "${payload}"'])
        out = run(prog)
        self.assertEqual(out.returncode, 0, out.stderr)
        doc = json.loads(out.stdout)
        self.assertEqual(doc.get("winn3_gateway_code_revision"), f"sha256:{'b' * 64}")
        self.assertEqual(doc.get("data_plane_source_revision"), "2b846c9a")
        self.assertIs(doc.get("canary_ok"), True)
        self.assertEqual(doc.get("canary_at"), 1790000000)


# --------------------------------------------------------------------------
# SYNC-19
# --------------------------------------------------------------------------
class RegistrationFailureDetail(unittest.TestCase):
    def _block(self) -> str:
        start = REGISTER.index("fallback_register_url=")
        end = REGISTER.index("\n# SYNC-12: registration proves only", start)
        return REGISTER[start:end] + "\n"

    def _run(self, bodies: list[tuple[int, str]], fallback: str | None):
        with tempfile.TemporaryDirectory(prefix="sync19-") as tmp:
            tmpd = pathlib.Path(tmp)
            bin_dir = tmpd / "bin"
            bin_dir.mkdir()
            seq = tmpd / "seq.json"
            seq.write_text(json.dumps(bodies))
            write_exec(bin_dir / "curl", "#!/usr/bin/env python3\n"
                       "import json, sys\n"
                       f"p = {str(seq)!r}\n"
                       "sys.stdin.read()\n"
                       "if '--fail-with-body' not in sys.argv: sys.exit(99)\n"
                       "items = json.load(open(p))\n"
                       "code, body = items.pop(0)\n"
                       "json.dump(items, open(p, 'w'))\n"
                       "sys.stdout.write(body)\n"
                       "if code: sys.stderr.write('curl: (22) The requested URL returned error: 400\\n')\n"
                       "sys.exit(code)\n")
            env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HUB_REGISTER_URL": "https://hub.example.test/api/v1/nodes/register",
                   "HUB_API_BASE": "https://hub.example.test", "NODE_TOKEN": NODE_TOKEN, "XRAY_UUID": XRAY_UUID,
                   "payload": "{}"}
            if fallback is not None:
                env["HUB_REGISTER_URL_FALLBACK"] = fallback
            prog = "set -Eeuo pipefail\n" + self._block() + "echo REGISTERED\n"
            return run(prog, env)

    def test_refusal_reason_is_logged_and_no_fallback_is_named_honestly(self):
        out = self._run([(22, '{"detail":"Node ssh_host must be the provisioned management tunnel hostname."}')], None)
        self.assertEqual(out.returncode, 1)
        self.assertIn("failed: Node ssh_host must be the provisioned management tunnel hostname.", out.stderr)
        self.assertIn("No distinct fallback registration URL", out.stderr)
        self.assertNotIn("no fallback URL is configured", out.stderr)

    def test_validation_bodies_never_leak_submitted_secrets(self):
        body = json.dumps({"detail": [{"loc": ["body", "secret_token"], "msg": "String should have at most 256 characters",
                                       "input": NODE_TOKEN, "type": "string_too_long"},
                                      {"loc": ["body", "xray_uuid"], "msg": f"bad uuid {XRAY_UUID}", "input": XRAY_UUID}]})
        out = self._run([(22, body)], None)
        self.assertEqual(out.returncode, 1)
        self.assertIn("body.secret_token: String should have at most 256 characters", out.stderr)
        self.assertNotIn(NODE_TOKEN, out.stderr + out.stdout)
        self.assertNotIn(XRAY_UUID, out.stderr + out.stdout)
        out = self._run([(22, json.dumps({"detail": f"token {NODE_TOKEN} refused"}))], None)
        self.assertNotIn(NODE_TOKEN, out.stderr)
        self.assertIn("token <node-token> refused", out.stderr)

    def test_output_is_one_bounded_printable_line(self):
        out = self._run([(22, json.dumps({"detail": "x" * 2000 + "\nsecond\x1b[31m"}))], None)
        line = [l for l in out.stderr.splitlines() if "failed:" in l][0]
        self.assertLessEqual(len(line.split("failed: ", 1)[1]), 300)
        # Control characters inside the kept part: a forged second log line and
        # a terminal escape must not survive.
        out = self._run([(22, json.dumps({"detail": "first\nFAKE second line\x1b[31m red"}))], None)
        line = [l for l in out.stderr.splitlines() if "failed:" in l][0]
        self.assertIn("first FAKE second line", line)
        self.assertNotIn("\x1b", out.stderr)
        self.assertFalse(any(l.startswith("FAKE") for l in out.stderr.splitlines()))
        out = self._run([(22, "<html>502 Bad Gateway</html>")], None)
        self.assertIn("no hub detail", out.stderr)

    def test_bodies_of_retried_attempts_are_all_reported(self):
        # Merged with FX-DP-MED's --retry, curl writes every failed attempt's
        # body to stdout (measured on curl 8.7.1: 503 then 400 gives both).
        out = self._run([(22, '{"detail":"busy"}{"detail":"refused for a reason"}')], None)
        self.assertEqual(out.returncode, 1)
        self.assertIn("failed: busy refused for a reason", out.stderr)

    def test_distinct_fallback_is_tried_and_both_reasons_logged(self):
        out = self._run([(22, '{"detail":"first"}'), (0, '{"ok":true}')], "https://sync2.example.test/api/v1/nodes/register")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("REGISTERED", out.stdout)
        self.assertIn("failed: first", out.stderr)
        out = self._run([(22, '{"detail":"first"}'), (22, '{"detail":"second"}')], "https://sync2.example.test/api/v1/nodes/register")
        self.assertEqual(out.returncode, 1)
        self.assertIn("fallback https://sync2.example.test/api/v1/nodes/register failed: second", out.stderr)


class RealCurlFailWithBody(unittest.TestCase):
    """The installed curl really exits 22 with the body on stdout."""

    def test_fail_with_body_semantics(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = b'{"detail":"refused for a reason"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/api/v1/nodes/register"
            out = subprocess.run(["curl", "--noproxy", "*", "--fail-with-body", "-sS", "-X", "POST", url, "-H",
                                  "Content-Type: application/json", "--data-binary", "@-"],
                                 input="{}", text=True, capture_output=True, timeout=20, check=False)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(out.returncode, 22, out.stderr)
        self.assertIn("refused for a reason", out.stdout)


class RealCurlPendingTokenCheck(unittest.TestCase):
    """OI-SYNCDP-3 with the installed curl: the pending token reaches the hub
    only in the x-node-token header (curl reads it from stdin), and the check
    maps the hub's answer to accept or refuse."""

    def test_real_curl_against_a_local_hub(self):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                seen.append((self.path, self.headers.get("x-node-token")))
                ok = self.path == "/api/v1/pubkey?slug=germany-de1" and self.headers.get("x-node-token") == NODE_TOKEN
                body = b'{"pubkey":"ssh-ed25519 AAAA hub"}' if ok else b'{"detail":"Unauthorized"}'
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            prog = "\n".join(["set -Eeuo pipefail", LOG_STUBS, function_body(SRC, "data_verify_pending_node_token"),
                              "data_verify_pending_node_token"])
            results = {}
            for label, token in (("good", NODE_TOKEN), ("superseded", OTHER_TOKEN)):
                results[label] = run(prog, {"DATA_PENDING_NODE_TOKEN": token, "NODE_SLUG": "germany-de1",
                                            "HUB_API_BASE": base, "no_proxy": "*", "NO_PROXY": "*",
                                            "DATA_PENDING_NODE_TOKEN_FILE": "/var/lib/x/data.node-token"})
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(results["good"].returncode, 0, results["good"].stderr)
        self.assertEqual(results["superseded"].returncode, 1)
        self.assertIn("HTTP 401", results["superseded"].stderr)
        self.assertIn("/var/lib/x/data.node-token", results["superseded"].stderr)
        self.assertEqual([t for _, t in seen], [NODE_TOKEN, OTHER_TOKEN])
        for r in results.values():
            self.assertNotIn(NODE_TOKEN, r.stdout + r.stderr)
            self.assertNotIn(OTHER_TOKEN, r.stdout + r.stderr)


# --------------------------------------------------------------------------
# SYNC-20
# --------------------------------------------------------------------------
class CanaryVerdict(unittest.TestCase):
    def _script(self, tmpd: pathlib.Path, service_ok: bool, logdir: pathlib.Path | None = None,
                systemctl: str | None = None, inject: str = ""):
        bin_dir = tmpd / "bin"
        bin_dir.mkdir(exist_ok=True)
        write_exec(bin_dir / "systemctl", systemctl or f"#!/bin/sh\nexit {0 if service_ok else 3}\n")
        write_exec(bin_dir / "docker", "#!/bin/sh\necho amnezia-awg2\n")
        write_exec(bin_dir / "curl", "#!/bin/sh\nprintf 101\nexit 0\n")
        state = tmpd / "run" / "node-canary.state"
        marker = tmpd / "canary.unverified"
        logdir = logdir or (tmpd / "log")
        script = CANARY.replace('LOG_FILE="/var/log/winsvpn/node-canary.log"', f'LOG_FILE="{logdir}/node-canary.log"')
        script = script.replace("mkdir -p /var/log/winsvpn", f'mkdir -p "{logdir}"')
        script = script.replace("[[ -f /root/node.env ]] && source /root/node.env", ": no node.env")
        if inject:
            script = script.replace("set -Eeuo pipefail\n", "set -Eeuo pipefail\n" + inject + "\n", 1)
        path = tmpd / "canary.sh"
        path.write_text(script)
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmpd),
               "WINS_NODE_CANARY_STATE_FILE": str(state), "WINS_NODE_CANARY_UNVERIFIED_MARKER": str(marker),
               "STEALTH_HOST": "", "NODE_CANARY_STRICT_PUBLIC": "1"}
        return path, env, state, marker

    def _nodeenv_script(self, tmpd: pathlib.Path, inject: str = ""):
        """The canary with node.env as its only source of the two paths: the
        compiled-in defaults are moved under tmpd (default/), node.env names
        configured/ paths, and the process environment names neither."""
        path, env, _, _ = self._script(tmpd, False, inject=inject)
        default_dir = tmpd / "default"
        conf_dir = tmpd / "configured"
        default_dir.mkdir()
        conf_dir.mkdir()
        node_env = tmpd / "node.env"
        node_env.write_text(f'WINS_NODE_CANARY_STATE_FILE="{conf_dir}/node-canary.state"\n'
                            f'WINS_NODE_CANARY_UNVERIFIED_MARKER="{conf_dir}/canary.unverified"\n')
        text = path.read_text()
        text = text.replace(": no node.env", f'[[ -f "{node_env}" ]] && source "{node_env}"')
        text = text.replace("/run/winsvpn/node-canary.state", f"{default_dir}/node-canary.state")
        text = text.replace("/run/wins-node-canary.unverified", f"{default_dir}/canary.unverified")
        path.write_text(text)
        env = {k: v for k, v in env.items() if not k.startswith("WINS_NODE_CANARY_")}
        return path, env, node_env, default_dir, conf_dir

    def _nodeenv_reader(self, node_env: pathlib.Path, default_dir: pathlib.Path):
        start = REGISTER.index("# SYNC-20 (Round 4, Sol T3 N-1)")
        end = REGISTER.index('\nregional_aliases_json="$(', start)
        block = REGISTER[start:end]
        block = block.replace("/run/winsvpn/node-canary.state", f"{default_dir}/node-canary.state")
        block = block.replace("/run/wins-node-canary.unverified", f"{default_dir}/canary.unverified")
        prog = (f'set -Eeuo pipefail\nsource "{node_env}"\n' + block
                + '\nprintf "ok=%s at=%s\\n" "${canary_ok}" "${canary_at}"\n')
        return run(prog)

    def test_writer_and_reader_resolve_paths_with_the_same_text(self):
        for name in ("canary_state_file_path", "canary_unverified_marker_path"):
            self.assertEqual(function_body(CANARY, name), function_body(REGISTER, name), name)
        # The writer resolves them only after node.env (no capture before it).
        head = CANARY[:CANARY.index("[[ -f /root/node.env ]] && source /root/node.env")]
        self.assertNotRegex(head, r'^[A-Z_]+="\$\(canary_(state_file|unverified_marker)_path\)"', )
        self.assertNotIn("${WINS_NODE_CANARY_STATE_FILE", head.replace(function_body(CANARY, "canary_state_file_path"), ""))

    def test_a_direct_run_uses_the_paths_node_env_names(self):
        # Sol T3 N-1: node.env is the only place the marker path is set; the old
        # verdict cannot be removed and the new one cannot be written.
        inject = "\n".join([
            'rm() { case "$*" in *node-canary.state*) return 1 ;; esac; command rm "$@"; }',
            'install() { return 1; }',
        ])
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            tmpd = pathlib.Path(tmp)
            path, env, node_env, default_dir, conf_dir = self._nodeenv_script(tmpd, inject=inject)
            (conf_dir / "node-canary.state").write_text(f"canary_ok=true\ncanary_at={int(time.time()) - 30}\n")
            out = subprocess.run([BASH, str(path)], text=True, capture_output=True, timeout=60, check=False,
                                 stdin=subprocess.DEVNULL, env=env)
            self.assertNotEqual(out.returncode, 0)
            self.assertTrue((conf_dir / "canary.unverified").is_file(), "the configured marker was not written")
            self.assertFalse((default_dir / "canary.unverified").exists(), "the default marker was written instead")
            rep = self._nodeenv_reader(node_env, default_dir)
            self.assertRegex(rep.stdout, r"ok=false at=\d{9,}", rep.stdout + rep.stderr)
        # And a good direct run writes its verdict where node.env says.
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            tmpd = pathlib.Path(tmp)
            path, env, node_env, default_dir, conf_dir = self._nodeenv_script(tmpd)
            write_exec(tmpd / "bin" / "systemctl", "#!/bin/sh\nexit 0\n")
            out = subprocess.run([BASH, str(path)], text=True, capture_output=True, timeout=60, check=False,
                                 stdin=subprocess.DEVNULL, env=env)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("canary_ok=true", (conf_dir / "node-canary.state").read_text())
            self.assertFalse((default_dir / "node-canary.state").exists())
            rep = self._nodeenv_reader(node_env, default_dir)
            self.assertRegex(rep.stdout, r"ok=true at=\d{9,}", rep.stdout + rep.stderr)

    def test_a_direct_run_removes_the_old_verdict_node_env_names(self):
        # The start-of-run removal targets the configured path too: a direct
        # run killed outright (no trap runs) leaves no old success there.
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            tmpd = pathlib.Path(tmp)
            started = tmpd / "started"
            path, env, node_env, default_dir, conf_dir = self._nodeenv_script(tmpd)
            write_exec(tmpd / "bin" / "systemctl", f'#!/bin/sh\ntouch "{started}"\nexec sleep 30\n')
            (conf_dir / "node-canary.state").write_text(f"canary_ok=true\ncanary_at={int(time.time()) - 30}\n")
            proc = subprocess.Popen([BASH, str(path)], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                deadline = time.time() + 20
                while not started.exists() and time.time() < deadline:
                    time.sleep(0.05)
                self.assertTrue(started.exists(), "the canary never reached its first check")
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=20)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=10)
            self.assertFalse((conf_dir / "node-canary.state").exists(), "the configured old verdict survived")
            rep = self._nodeenv_reader(node_env, default_dir)
            self.assertIn("ok=null at=null", rep.stdout, rep.stdout + rep.stderr)

    def _canary(self, tmp: str, service_ok: bool, logdir: pathlib.Path | None = None, inject: str = ""):
        path, env, state, marker = self._script(pathlib.Path(tmp), service_ok, logdir, inject=inject)
        out = subprocess.run([BASH, str(path)], text=True, capture_output=True, timeout=60, check=False,
                             stdin=subprocess.DEVNULL, env=env)
        return out, state

    def test_canary_records_pass_and_fail_and_keeps_its_exit_status(self):
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            out, state = self._canary(tmp, service_ok=True)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("canary_ok=true", state.read_text())
            self.assertRegex(state.read_text(), r"canary_at=\d{9,}")
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            out, state = self._canary(tmp, service_ok=False)
            self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
            self.assertIn("canary_ok=false", state.read_text())

    def test_a_failed_start_replaces_the_previous_verdict(self):
        # Sol N-4: the log directory cannot be created, before any check runs.
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            state = pathlib.Path(tmp, "run", "node-canary.state")
            state.parent.mkdir()
            state.write_text("canary_ok=true\ncanary_at=1000\n")
            blocker = pathlib.Path(tmp, "blocker")
            blocker.write_text("x")
            out, state = self._canary(tmp, service_ok=True, logdir=blocker / "log")
            self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
            text = state.read_text()
            self.assertIn("canary_ok=false", text)
            at = int(re.search(r"canary_at=(\d+)", text).group(1))
            self.assertGreater(at, 1000)

    def _killed(self, sig: int, inject: str = "", with_marker: bool = False):
        """A canary blocked in a check, then killed as systemd kills a unit: the
        whole process group gets the signal."""
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            tmpd = pathlib.Path(tmp)
            started = tmpd / "started"
            path, env, state, marker = self._script(
                tmpd, True, systemctl=f'#!/bin/sh\ntouch "{started}"\nexec sleep 30\n', inject=inject)
            state.parent.mkdir(parents=True)
            state.write_text(f"canary_ok=true\ncanary_at={int(time.time()) - 60}\n")
            # systemd starts a unit with every signal at its default. A harness
            # launched in the background inherits SIGINT ignored, and bash cannot
            # trap a signal ignored on entry, so reset it as systemd would.
            proc = subprocess.Popen([BASH, str(path)], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True,
                                    preexec_fn=lambda: (signal.signal(signal.SIGINT, signal.SIG_DFL),
                                                        signal.signal(signal.SIGQUIT, signal.SIG_DFL)))
            try:
                deadline = time.time() + 20
                while not started.exists() and time.time() < deadline:
                    time.sleep(0.05)
                self.assertTrue(started.exists(), "the canary never reached its first check")
                os.killpg(proc.pid, sig)
                proc.wait(timeout=20)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=10)
            if with_marker:
                return proc.returncode, (state.read_text() if state.exists() else None), \
                    (marker.read_text() if marker.exists() else None)
            return proc.returncode, (state.read_text() if state.exists() else None)

    def test_a_run_ended_by_a_signal_records_failure(self):
        # CLAUDE-N-3: SIGTERM (systemctl stop, shutdown, a unit timeout), SIGHUP
        # and SIGINT must never record the success the EXIT trap's $? of 0 implied.
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            rc, text = self._killed(sig)
            self.assertNotEqual(rc, 0, sig)
            self.assertIsNotNone(text, sig)
            self.assertIn("canary_ok=false", text, sig)

    def test_a_run_killed_outright_leaves_no_old_verdict(self):
        # OI-SYNCDP-13 / CLAUDE-N-5: SIGKILL runs no trap; the start-of-run
        # removal is what keeps the previous success from standing.
        rc, text = self._killed(signal.SIGKILL)
        self.assertNotEqual(rc, 0)
        self.assertIsNone(text, "the previous verdict survived a killed run")

    def test_an_unremovable_old_verdict_is_marked_at_start(self):
        # Sol N-2, start half: the old verdict cannot be removed and the run is
        # then killed outright (no EXIT trap); the start-of-run marker remains.
        inject = 'rm() { case "$*" in *node-canary.state*) return 1 ;; esac; command rm "$@"; }'
        rc, text, marker = self._killed(signal.SIGKILL, inject=inject, with_marker=True)
        self.assertNotEqual(rc, 0)
        self.assertIsNotNone(text, "the model did not hold: the old verdict was removed")
        self.assertIsNotNone(marker, "no unverified marker after an unremovable old verdict")
        self.assertRegex(marker, r"^canary_at=\d{9,}\n$")

    def test_unremovable_old_verdict_and_unwritable_state_mark_the_run_unverified(self):
        # Sol N-2: the old verdict cannot be removed and the new one cannot be
        # written; the marker outside the state directory must win.
        inject = "\n".join([
            'rm() { case "$*" in *node-canary.state*) return 1 ;; esac; command rm "$@"; }',
            'install() { return 1; }',
        ])
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            tmpd = pathlib.Path(tmp)
            path, env, state, marker = self._script(tmpd, False, inject=inject)
            state.parent.mkdir(parents=True)
            fresh = int(time.time()) - 30
            state.write_text(f"canary_ok=true\ncanary_at={fresh}\n")
            out = subprocess.run([BASH, str(path)], text=True, capture_output=True, timeout=60, check=False,
                                 stdin=subprocess.DEVNULL, env=env)
            self.assertNotEqual(out.returncode, 0)
            self.assertEqual(state.read_text(), f"canary_ok=true\ncanary_at={fresh}\n", "the model did not hold")
            self.assertTrue(marker.is_file(), "no unverified marker")
            rep = self._register(tmp, None, marker_path=marker, state_path=state)
            self.assertRegex(rep.stdout, r"ok=false at=\d{9,}", rep.stdout + rep.stderr)
        # A later run that can write clears the marker again.
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            tmpd = pathlib.Path(tmp)
            path, env, state, marker = self._script(tmpd, True)
            marker.write_text("canary_at=1000\n")
            out = subprocess.run([BASH, str(path)], text=True, capture_output=True, timeout=60, check=False,
                                 stdin=subprocess.DEVNULL, env=env)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertFalse(marker.exists())
            self.assertIn("canary_ok=true", state.read_text())

    def test_sourced_helpers_set_no_trap(self):
        # tools/test_deployment_runtime_configs.sh sources the canary up to
        # its start line for the helper functions; that must not write state.
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            state = pathlib.Path(tmp, "node-canary.state")
            state.write_text("canary_ok=true\ncanary_at=1000\n")
            helpers = CANARY[:CANARY.index('\nlog "Node canary started')] + "\n"
            helpers = helpers.replace('LOG_FILE="/var/log/winsvpn/node-canary.log"', f'LOG_FILE="{tmp}/c.log"')
            helpers = helpers.replace("mkdir -p /var/log/winsvpn", f'mkdir -p "{tmp}"')
            helpers = helpers.replace("[[ -f /root/node.env ]] && source /root/node.env", ": no node.env")
            path = pathlib.Path(tmp, "helpers.sh")
            path.write_text(helpers)
            marker = pathlib.Path(tmp, "unverified")
            out = run(f'set -Eeuo pipefail\n( source "{path}"; [[ "$(type -t fail)" == function ]] )\necho ok\n',
                      {"WINS_NODE_CANARY_STATE_FILE": str(state), "WINS_NODE_CANARY_UNVERIFIED_MARKER": str(marker)})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(state.read_text(), "canary_ok=true\ncanary_at=1000\n")
            self.assertFalse(marker.exists())

    def test_state_writer_ignores_an_unwritable_location_and_marks_it(self):
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            marker = pathlib.Path(tmp, "unverified")
            prog = "\n".join(["set -Eeuo pipefail",
                              *(function_body(CANARY, f) for f in ("canary_state_file_path", "canary_unverified_marker_path",
                                                                   "mark_canary_unverified", "record_canary_state")),
                              'record_canary_state 1', 'echo survived'])
            out = run(prog, {"WINS_NODE_CANARY_STATE_FILE": "/nonexistent-root-dir/x/state",
                             "WINS_NODE_CANARY_UNVERIFIED_MARKER": str(marker)})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("survived", out.stdout)
            self.assertRegex(marker.read_text(), r"^canary_at=\d{9,}\n$")

    def _register(self, tmp: str, text: str | None, symlink: bool = False, marker_path: pathlib.Path | None = None,
                  state_path: pathlib.Path | None = None, marker_text: str | None = None, env: dict | None = None):
        tmpd = pathlib.Path(tmp)
        state = state_path or (tmpd / "reader" / "node-canary.state")
        state.parent.mkdir(parents=True, exist_ok=True)
        if text is not None:
            target = state.parent / "real" if symlink else state
            target.write_text(text)
            if symlink:
                state.symlink_to(target)
        marker = marker_path or (tmpd / "reader" / "unverified")
        if marker_text is not None:
            marker.write_text(marker_text)
        start = REGISTER.index("# SYNC-20 (Round 4, Sol T3 N-1)")
        end = REGISTER.index('\nregional_aliases_json="$(', start)
        prog = "set -Eeuo pipefail\n" + REGISTER[start:end] + '\nprintf "ok=%s at=%s\\n" "${canary_ok}" "${canary_at}"\n'
        return run(prog, {"WINS_NODE_CANARY_STATE_FILE": str(state),
                          "WINS_NODE_CANARY_UNVERIFIED_MARKER": str(marker), **(env or {})})

    def test_register_reads_the_verdict_strictly(self):
        now = int(time.time())
        t0, t1 = str(now - 60), str(now - 59)
        cases = [
            ("canary_ok=true\ncanary_at=T0\n", False, "ok=true at=T0"),
            ("canary_ok=false\ncanary_at=T1", False, "ok=false at=T1"),
            (None, False, "ok=null at=null"),
            ("canary_ok=true\n", False, "ok=null at=null"),
            ("canary_ok=yes\ncanary_at=T0\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_at=17x\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_at=T0\n", True, "ok=null at=null"),
            # Sol N-5: a later bad or repeated line never hides behind a good one.
            ("canary_ok=true\ncanary_ok=yes\ncanary_at=T0\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_at=T0\ncanary_at=bad\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_ok=false\ncanary_at=T0\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_at=T0\ncanary_at=T1\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_at=T0\njunk\n", False, "ok=null at=null"),
            ("canary_ok=true\ncanary_at=T0\n\n", False, "ok=null at=null"),
        ]
        for text, symlink, want in cases:
            text = text.replace("T0", t0).replace("T1", t1) if text else text
            want = want.replace("T0", t0).replace("T1", t1)
            with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
                out = self._register(tmp, text, symlink)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn(want, out.stdout, (text, symlink))

    def test_an_old_verdict_is_no_verdict(self):
        now = int(time.time())
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            out = self._register(tmp, f"canary_ok=true\ncanary_at={now - 2800}\n")
            self.assertIn("ok=null at=null", out.stdout)
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            out = self._register(tmp, f"canary_ok=true\ncanary_at={now - 2600}\n")
            self.assertIn(f"ok=true at={now - 2600}", out.stdout)
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            out = self._register(tmp, f"canary_ok=true\ncanary_at={now - 200}\n",
                                 env={"NODE_CANARY_VERDICT_MAX_AGE_SECONDS": "100"})
            self.assertIn("ok=null at=null", out.stdout)

    def test_a_future_or_zero_padded_time_is_no_verdict(self):
        now = int(time.time())
        for text in (f"canary_ok=true\ncanary_at={now + 86400}\n", "canary_ok=true\ncanary_at=0999\n",
                     f"canary_ok=true\ncanary_at=0{now - 10}\n"):
            with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
                out = self._register(tmp, text)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn("ok=null at=null", out.stdout, text)
                self.assertNotIn("value too great", out.stderr)
        with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
            out = self._register(tmp, f"canary_ok=true\ncanary_at={now + 100}\n")
            self.assertIn(f"ok=true at={now + 100}", out.stdout, "a small clock skew is still a verdict")

    def test_the_unverified_marker_wins(self):
        now = int(time.time())
        good = f"canary_ok=true\ncanary_at={now - 10}\n"
        for marker_text, want in ((f"canary_at={now - 5}\n", f"ok=false at={now - 5}"),
                                  ("garbage\n", "ok=null at=null"), ("", "ok=null at=null"),
                                  ("canary_at=0999\n", "ok=null at=null")):
            with tempfile.TemporaryDirectory(prefix="sync20-") as tmp:
                out = self._register(tmp, good, marker_text=marker_text)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn(want, out.stdout, marker_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
