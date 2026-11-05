#!/usr/bin/env python3
"""Regression tests for the Core installer fix wave, lane FX-CORE-B (2026-09-29).

Each class pins one finding from the IA-CORE audit of
server/wins_core_server_setup_ONETOUCH.sh and
tools/relay_core_installer_transaction.py. Installer functions are sliced out
of the shipped text and executed with bash against PATH stubs (iptables,
systemctl, ip, stat, sed and friends), so the tests run offline on Linux or
macOS and never touch the host firewall. Every finding class has at least one
test that fails on the audited snapshot (BASE_COMMIT 2b846c9); the others guard
behaviour that must not change. Turn 2 tests (review items from the two seats)
also fail on the Turn 1 fix and pass on the Turn 2 fix.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.stage_core_sync_agent import stage
from tools.validate_deployment_scripts import parse_heredocs

CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
RELAY = ROOT / "tools" / "relay_core_installer_transaction.py"

# Bash 4+ is required (the installer uses ${var,,}, declare -g, mapfile).
BASH = shutil.which("bash") or "/bin/bash"
BASH_DIR = str(Path(BASH).resolve().parent)

HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _core() -> str:
    return CORE.read_text(encoding="utf-8")


def _function(source: str, name: str, occurrence: int = 0) -> str:
    """Return `name() { ... }` verbatim: the Nth top-level definition, heredoc aware."""
    lines = source.splitlines()
    starts = [i for i, line in enumerate(lines) if line == f"{name}() {{"]
    if not -len(starts) <= occurrence < len(starts):
        raise AssertionError(f"function {name} (occurrence {occurrence}) not found")
    index = starts[occurrence]
    out = [lines[index]]
    index += 1
    heredoc_tag = None
    while index < len(lines):
        line = lines[index]
        out.append(line)
        if heredoc_tag is not None:
            if line.lstrip("\t") == heredoc_tag:
                heredoc_tag = None
        else:
            if line == "}":
                return "\n".join(out) + "\n"
            match = HEREDOC_OPEN.search(line)
            if match and "<<<" not in line:
                heredoc_tag = match.group(2)
        index += 1
    raise AssertionError(f"function {name} is not terminated")


def _staged_agent_text() -> str:
    with tempfile.TemporaryDirectory() as value:
        output = Path(value) / "stage"
        stage(CORE, output)
        return (output / "wins-core-sync").read_text(encoding="utf-8")


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class Sandbox:
    """A temporary directory with a stub bin/ directory placed first on PATH."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="wins-core-fixb-")
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.log"
        self.log.write_text("", encoding="utf-8")
        # GNU `stat -c` shim (the installer's trust checks use it); the uid is
        # reported as STUB_STAT_UID so root ownership can be simulated.
        _write_exec(self.bin / "stat", textwrap.dedent('''\
            #!/usr/bin/env python3
            import os, sys
            args = sys.argv[1:]
            if len(args) >= 3 and args[0] == "-c":
                info = os.lstat(args[2])
                out = args[1]
                out = out.replace("%u", os.environ.get("STUB_STAT_UID", "0"))
                out = out.replace("%g", os.environ.get("STUB_STAT_GID", "0"))
                out = out.replace("%a", format(info.st_mode & 0o7777, "o"))
                out = out.replace("%h", str(info.st_nlink))
                print(out)
                raise SystemExit(0)
            os.execv("/usr/bin/stat", ["stat", *args])
            '''))
        # GNU `sed -i SCRIPT FILE` shim for BSD userlands; everything else is
        # passed straight through.
        _write_exec(self.bin / "sed", textwrap.dedent('''\
            #!/usr/bin/env bash
            real=/usr/bin/sed; [[ -x "${real}" ]] || real=/bin/sed
            if [[ "${1:-}" == "-i" && $# -eq 3 ]]; then
              "${real}" -e "$2" "$3" > "$3.sedtmp" && mv -f -- "$3.sedtmp" "$3"
              exit $?
            fi
            exec "${real}" "$@"
            '''))

        # GNU `find -perm /MODE` is `-perm +MODE` on BSD find; translate only
        # when the host find is BSD.
        _write_exec(self.bin / "find", textwrap.dedent('''\
            #!/usr/bin/env bash
            real=/usr/bin/find; [[ -x "${real}" ]] || real=/bin/find
            if [[ "$(uname -s)" != Linux ]]; then
              args=(); previous=""
              for arg in "$@"; do
                if [[ "${previous}" == "-perm" && "${arg}" == /* ]]; then arg="+${arg#/}"; fi
                args+=("${arg}"); previous="${arg}"
              done
              exec "${real}" "${args[@]}"
            fi
            exec "${real}" "$@"
            '''))

        # util-linux `flock -w SECONDS FD` shim (macOS has none). It locks the
        # inherited open file description, exactly as util-linux does.
        _write_exec(self.bin / "flock", textwrap.dedent('''\
            #!/usr/bin/env python3
            import fcntl, sys, time
            args = sys.argv[1:]
            wait = None
            if args[:1] == ["-w"]:
                wait = float(args[1]); args = args[2:]
            elif args[:1] == ["-n"]:
                wait = 0.0; args = args[1:]
            fd = int(args[0])
            deadline = None if wait is None else time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    raise SystemExit(0)
                except BlockingIOError:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise SystemExit(1)
                    time.sleep(0.05)
            '''))

        # lockprobe PATH: prints LOCK_HELD when another open file description
        # holds an exclusive flock on PATH, LOCK_FREE otherwise.
        _write_exec(self.bin / "lockprobe", textwrap.dedent('''\
            #!/usr/bin/env python3
            import fcntl, sys
            with open(sys.argv[1], "a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    print("LOCK_HELD")
                else:
                    print("LOCK_FREE")
            '''))

    def stub(self, name: str, body: str) -> None:
        _write_exec(self.bin / name, "#!/usr/bin/env bash\n" + textwrap.dedent(body))

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()

    def run(self, script: str, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        harness = self.root / "harness.sh"
        harness.write_text(script, encoding="utf-8")
        environment = {
            "PATH": f"{self.bin}:{BASH_DIR}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "CALL_LOG": str(self.log),
            "WORK": str(self.root),
        }
        environment.update(env or {})
        return subprocess.run(
            [BASH, str(harness)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=timeout,
            check=False,
        )

    def close(self) -> None:
        self._tmp.cleanup()


PRELUDE = textwrap.dedent('''\
    set -Eeuo pipefail
    log() { printf '[CORE] %s\\n' "$*"; }
    warn() { printf '[WARN] %s\\n' "$*" >&2; }
    err() { printf '[ERR] %s\\n' "$*" >&2; }
    ''')


# ---------------------------------------------------------------------------
# write_firewall harness (IA-CORE-04, 09, 12, 18)
# ---------------------------------------------------------------------------


class FirewallHarness:
    def __init__(self) -> None:
        self.box = Sandbox()
        root = self.box.root
        (root / "proc_ipv6").mkdir()
        (root / "nfqueue").write_text("0 1 0 2 65531 0 0 0 1\n", encoding="ascii")
        self.box.stub("iptables", '''\
            printf 'iptables %s\\n' "$*" >> "${CALL_LOG}"
            if [[ "${1:-}" == "-S" && "${2:-}" == "INPUT" ]]; then
              printf '%s\\n' "${STUB_INPUT_RULES:-}"
              exit "${STUB_IPT_S_RC:-0}"
            fi
            if [[ "${1:-}" == "-S" && "${2:-}" == "FORWARD" ]]; then
              printf '%s\\n' "${STUB_FORWARD_RULES:-}"
              exit 0
            fi
            if [[ "${1:-}" == "-C" || "${3:-}" == "-C" ]]; then
              spec="$*"
              while IFS= read -r present; do
                [[ -n "${present}" && "${spec}" == *"${present}" ]] && exit 0
              done <<<"${STUB_IPT_PRESENT:-}"
              exit 1
            fi
            if [[ "${1:-}" == "-m" ]]; then exit 0; fi
            exit 0
            ''')
        self.box.stub("iptables-save", '''\
            printf '*filter\\n:INPUT DROP [0:0]\\nCOMMIT\\n'
            ''')
        self.box.stub("iptables-restore", '''\
            args="$*"
            printf 'iptables-restore %s\\n' "${args}" >> "${CALL_LOG}"
            if [[ "${args}" == *--test* ]]; then cat > "${WORK}/tested.rules"; exit 0; fi
            cat > "${WORK}/committed.rules"
            exit 0
            ''')
        self.box.stub("ip6tables", '''\
            printf 'ip6tables %s\\n' "$*" >> "${CALL_LOG}"
            exit "${STUB_IP6_RC:-0}"
            ''')
        self.box.stub("ip6tables-save", '''\
            printf 'ip6tables-save\\n' >> "${CALL_LOG}"
            [[ "${STUB_IP6_SAVE_RC:-0}" == 0 ]] || exit "${STUB_IP6_SAVE_RC}"
            printf '*filter\\n:INPUT DROP [0:0]\\nCOMMIT\\n'
            ''')
        self.box.stub("ip", '''\
            printf 'ip %s\\n' "$*" >> "${CALL_LOG}"
            if [[ "$*" == "-4 rule show" || "$*" == "rule show" ]]; then
              printf '%s\\n' "${STUB_IP_RULES:-}"
            fi
            exit 0
            ''')
        self.box.stub("systemctl", '''\
            printf 'systemctl %s\\n' "$*" >> "${CALL_LOG}"
            if [[ "$*" == *"-p ExecStart --value"* ]]; then
              echo "{ path=/usr/bin/suricata ; argv[]=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0 ; }"
            fi
            exit 0
            ''')
        self.box.stub("suricatasc", "exit 0\n")
        self.box.stub("suricata", "echo 'NFQueue support: yes NFQ'\n")
        self.box.stub("netfilter-persistent", "exit 0\n")
        source = _core()
        firewall = _function(source, "write_firewall")
        firewall = firewall.replace(
            "/usr/local/sbin/winsvpn-core-hardening.sh", str(root / "winsvpn-core-hardening.sh")
        ).replace(
            "/etc/systemd/system/winsvpn-core-hardening.service", str(root / "winsvpn-core-hardening.service")
        )
        self.functions = "\n".join(
            [
                _function(source, "cleanup_core_firewall_transaction_workspace"),
                _function(source, "core_tcp_mss_for_mtu"),
                firewall,
                "install_core_failure_hold_firewall() { printf 'HOLD %s\\n' \"$*\" >> \"${CALL_LOG}\"; }",
            ]
        )

    def run(
        self, ids: str, admission: str, replace_variables: dict[str, str] | None = None, **overrides: str
    ) -> subprocess.CompletedProcess[str]:
        root = self.box.root
        variables = {
            "CORE_INGRESS_IFACE": "core0",
            "CORE_INGRESS_ADDR": "10.9.1.1/16",
            "CORE_INGRESS_CIDR": "10.9.0.0/16",
            "CORE_INGRESS_PORT": "9210",
            "CORE_STEALTH_TRANSPORTS": "80:none,443:tls",
            "CORE_ADMIN_CIDR": "192.168.50.0/24",
            "CORE_OPEN_PUBLIC_INGRESS": "1",
            "CORE_UDP_RATE_LIMIT": "0",
            "CORE_UDP_RATE_BURST": "100000",
            "CORE_EXIT_IFACE": "coreexit0",
            "CORE_EXIT_IFACE_PREFIX": "corex",
            "CORE_AWG_MTU": "1280",
            "INSTALL_CORE_IDS_IPS_DEFAULT": "1",
            "SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT": "0",
            "CORE_INSTALLER_RERUN_ACTIVE": "0",
        }
        env = {
            "CORE_IPTABLES_RULES_V4_PATH": str(root / "rules.v4"),
            "CORE_IPTABLES_RULES_V6_PATH": str(root / "rules.v6"),
            "CORE_NFQUEUE_PROC_PATH": str(root / "nfqueue"),
            "CORE_IPV6_PROC_DIR": str(root / "proc_ipv6"),
        }
        if replace_variables is not None:
            variables = dict(replace_variables)
        for key, value in overrides.items():
            if key in variables:
                variables[key] = value
            else:
                env[key] = value
        assignments = "".join(f"{k}={json.dumps(v)}\n" for k, v in variables.items())
        script = (
            PRELUDE
            + assignments
            + self.functions
            # As main() and the runtime suite do: a failure inside the
            # transaction build still removes the /tmp workspace.
            + "\ntrap 'cleanup_core_firewall_transaction_workspace' ERR"
            + "\ntrap 'printf \"%s\" \"${CORE_FIREWALL_TRANSACTION_WORKSPACE:-}\" > \"${WORK}/workspace.left\"' EXIT"
            + f'\nwrite_firewall {ids} {admission}\necho "WRITE_FIREWALL_RC=0"\n'
        )
        for name in ("committed.rules", "tested.rules", "winsvpn-core-hardening.sh"):
            (root / name).unlink(missing_ok=True)
        self.box.log.write_text("", encoding="utf-8")
        return self.box.run(script, env)

    def committed(self) -> list[str]:
        path = self.box.root / "committed.rules"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def close(self) -> None:
        self.box.close()


PUBLIC_UDP = "-A WINVPN-CORE-INPUT -p udp --dport 9210 -j ACCEPT"
ADMIN_UDP = "-A WINVPN-CORE-INPUT -s 192.168.50.0/24 -p udp --dport 9210 -j ACCEPT"


class CoreOpenPublicIngressUdpTests(unittest.TestCase):
    """IA-CORE-04: CORE_OPEN_PUBLIC_INGRESS=0 must close UDP/9210 with IPS on."""

    def setUp(self) -> None:
        self.fw = FirewallHarness()

    def tearDown(self) -> None:
        self.fw.close()

    def test_closed_public_ingress_keeps_udp_admin_only_with_ips_on(self) -> None:
        result = self.fw.run("1", "1", CORE_OPEN_PUBLIC_INGRESS="0")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        rules = self.fw.committed()
        self.assertNotIn(PUBLIC_UDP, rules)
        self.assertIn(ADMIN_UDP, rules)

    def test_closed_admission_keeps_udp_admin_only_with_ips_on(self) -> None:
        result = self.fw.run("1", "0", CORE_OPEN_PUBLIC_INGRESS="1")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        self.assertNotIn(PUBLIC_UDP, self.fw.committed())

    def test_open_ingress_accepts_udp_once_before_queue_and_conntrack(self) -> None:
        result = self.fw.run("1", "1")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        rules = self.fw.committed()
        self.assertEqual(1, rules.count(PUBLIC_UDP))
        udp = rules.index(PUBLIC_UDP)
        queue = next(i for i, r in enumerate(rules) if "--queue-num 0" in r)
        conntrack = rules.index("-A WINVPN-CORE-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        self.assertLess(udp, queue)
        self.assertLess(udp, conntrack)
        self.assertEqual(2, sum("--queue-num 0" in r for r in rules))

    def test_runtime_verifier_agrees_with_the_firewall(self) -> None:
        body = _function(_core(), "verify_core_suricata_runtime")
        stubs = Sandbox()
        try:
            stubs.stub("iptables", '''\
                printf 'iptables %s\\n' "$*" >> "${CALL_LOG}"
                spec="$*"
                while IFS= read -r present; do
                  [[ -n "${present}" && "${spec}" == *"${present}" ]] && exit 0
                done <<<"${STUB_IPT_PRESENT:-}"
                exit 1
                ''')
            # Only the UDP ingress assertions are sliced out and run, so no
            # Suricata host state is needed.
            start = body.index("  # IA-CORE-04") if "  # IA-CORE-04" in body else body.index(
                '  iptables -C WINVPN-CORE-INPUT -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT'
            )
            end = body.index("  while IFS= read -r route; do", start)
            probe = "verify_udp() {\n" + body[start:end] + "}\n"
            script = PRELUDE + (
                'CORE_INGRESS_PORT=9210\nCORE_ADMIN_CIDR=192.168.50.0/24\n'
                'CORE_OPEN_PUBLIC_INGRESS="${OPEN}"\n'
            ) + probe + (
                # Plain call, as postflight does: a failing `iptables -C` must
                # abort under errexit, so it cannot sit in a conditional here.
                'trap \'echo VERIFY=fail\' ERR\nverify_udp\necho VERIFY=pass\n'
            )
            closed_rules = "-s 192.168.50.0/24 -p udp --dport 9210 -j ACCEPT"
            result = stubs.run(script, {"OPEN": "0", "STUB_IPT_PRESENT": closed_rules})
            self.assertIn("VERIFY=pass", result.stdout, result.stderr)
            result = stubs.run(
                script,
                {"OPEN": "0", "STUB_IPT_PRESENT": closed_rules + "\nWINVPN-CORE-INPUT -p udp --dport 9210 -j ACCEPT"},
            )
            self.assertIn("VERIFY=fail", result.stdout, result.stderr)
            self.assertNotIn("VERIFY=pass", result.stdout)
            result = stubs.run(script, {"OPEN": "0", "STUB_IPT_PRESENT": ""})
            self.assertNotIn("VERIFY=pass", result.stdout)
            result = stubs.run(script, {"OPEN": "1", "STUB_IPT_PRESENT": "WINVPN-CORE-INPUT -p udp --dport 9210 -j ACCEPT"})
            self.assertIn("VERIFY=pass", result.stdout, result.stderr)
        finally:
            stubs.close()


class CoreForwardEncryptedDnsTests(unittest.TestCase):
    """R1-GLM-3 (the Core copy of Gemini L04 F-1.2a): forwarded VPN-client
    DoT/DoQ is refused, as WINVPN-CORE-INPUT and both data-plane writers
    refuse it, and the refusal sits before the UDP limiter and every ACCEPT."""

    DOT_DOQ = (("tcp", "853"), ("udp", "853"), ("udp", "784"), ("udp", "8853"))

    def setUp(self) -> None:
        self.fw = FirewallHarness()

    def tearDown(self) -> None:
        self.fw.close()

    def test_forwarded_dot_and_doq_are_rejected_before_any_accept(self) -> None:
        result = self.fw.run("1", "1", CORE_UDP_RATE_LIMIT="2000/sec")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        forward = [r for r in self.fw.committed() if r.startswith("-A WINVPN-CORE-FORWARD ")]
        limiter = next(i for i, r in enumerate(forward) if "--hashlimit-name wins_core_udp" in r)
        first_accept = next(i for i, r in enumerate(forward) if r.endswith("-j ACCEPT"))
        for proto, port in self.DOT_DOQ:
            matching = [r for r in forward if f" -p {proto} --dport {port} " in r]
            self.assertEqual(
                [f"-A WINVPN-CORE-FORWARD -i core0 -p {proto} --dport {port} -j REJECT --reject-with icmp-port-unreachable"],
                matching,
            )
            at = forward.index(matching[0])
            self.assertLess(at, limiter, f"{proto}/{port} must be refused before the UDP limiter")
            self.assertLess(at, first_accept, f"{proto}/{port} must be refused before any ACCEPT")


class CoreReservedPortsTests(unittest.TestCase):
    """R1-GLM-2 (the data plane's Mythos L04 F-1): setup_sysctl widens the
    ephemeral range to 1024-65535, so the Core's fixed listeners (the AWG
    ingress, the loopback Xray inbound, the local AI endpoint) are reserved in
    the file systemd-sysctl applies at boot, before this run's own
    `sysctl --system`."""

    RESERVED = "net.ipv4.ip_local_reserved_ports="

    def render(self, **ports: str) -> str:
        box = Sandbox()
        try:
            for iface in ("lo", "eth0"):
                conf = box.root / "proc_ipv6_conf" / iface
                conf.mkdir(parents=True)
                for name in ("disable_ipv6", "accept_ra", "autoconf"):
                    (conf / name).write_text("0\n", encoding="ascii")
            (box.root / "etc" / "sysctl.d").mkdir(parents=True)
            box.stub("sysctl", '''\
                if [[ "${1:-}" == "--system" ]]; then
                  if grep -q '^net.ipv4.ip_local_reserved_ports=' "${WORK}/etc/sysctl.d/99-winsvpn-core.conf"; then
                    printf 'sysctl --system with-reservation\\n' >> "${CALL_LOG}"
                  else
                    printf 'sysctl --system without-reservation\\n' >> "${CALL_LOG}"
                  fi
                  exit 0
                fi
                printf 'sysctl %s\\n' "$*" >> "${CALL_LOG}"
                ''')
            body = _function(_core(), "setup_sysctl")
            body = body.replace("/etc/sysctl.d/", "${WORK}/etc/sysctl.d/").replace(
                "/proc/sys/net/ipv6/conf/", "${WORK}/proc_ipv6_conf/")
            assignments = "".join(f"{k}={json.dumps(v)}\n" for k, v in ports.items())
            result = box.run(PRELUDE + assignments + body + "\nsetup_sysctl\nsetup_sysctl\n")
            self.assertEqual(0, result.returncode, result.stderr)
            lines = (box.root / "etc" / "sysctl.d" / "99-winsvpn-core.conf").read_text(encoding="utf-8").splitlines()
            calls = box.calls()
        finally:
            box.close()
        reserved = [line for line in lines if line.startswith(self.RESERVED)]
        self.assertEqual(1, len(reserved), f"a rerun must rewrite, not repeat, the reservation: {reserved}")
        self.assertIn("net.ipv4.ip_local_port_range=1024 65535", lines)
        self.assertEqual(2, calls.count("sysctl --system with-reservation"), calls)
        self.assertNotIn("sysctl --system without-reservation", calls)
        return reserved[0][len(self.RESERVED):]

    def test_default_ports_are_reserved(self) -> None:
        self.assertEqual(
            "9210,10110,11434",
            self.render(CORE_INGRESS_PORT="9210", CORE_XRAY_INBOUND_PORT="10110", CORE_AI_PORT="11434"),
        )

    def test_reservation_follows_this_runs_ports(self) -> None:
        self.assertEqual(
            "9310,10210,11534",
            self.render(CORE_INGRESS_PORT="9310", CORE_XRAY_INBOUND_PORT="10210", CORE_AI_PORT="11534"),
        )


class CoreIngressIpDerivationTests(unittest.TestCase):
    """IA-CORE-09: the 32764 rule follows CORE_INGRESS_ADDR, not 10.9.1.1."""

    def setUp(self) -> None:
        self.fw = FirewallHarness()

    def tearDown(self) -> None:
        self.fw.close()

    def test_existing_owned_jumps_move_ahead_of_earlier_allows(self) -> None:
        result = self.fw.run(
            "0", "0",
            STUB_INPUT_RULES="-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j WINVPN-CORE-INPUT",
            STUB_FORWARD_RULES="-P FORWARD DROP\n-A FORWARD -j ACCEPT\n-A FORWARD -j WINVPN-CORE-FORWARD",
        )
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        rules = self.fw.committed()
        self.assertEqual(1, rules.count("-D INPUT -j WINVPN-CORE-INPUT"))
        self.assertEqual(1, rules.count("-D FORWARD -j WINVPN-CORE-FORWARD"))
        self.assertLess(rules.index("-D INPUT -j WINVPN-CORE-INPUT"),
                        rules.index("-I INPUT 1 -j WINVPN-CORE-INPUT"))
        self.assertLess(rules.index("-D FORWARD -j WINVPN-CORE-FORWARD"),
                        rules.index("-I FORWARD 1 -j WINVPN-CORE-FORWARD"))

    def test_unreadable_base_chain_changes_nothing(self) -> None:
        result = self.fw.run("0", "0", STUB_IPT_S_RC="1")
        self.assertNotIn("WRITE_FIREWALL_RC=0", result.stdout)
        self.assertIn("could not read the INPUT chain", result.stderr)
        self.assertEqual([], self.fw.committed())

    def test_non_default_pool_renders_its_own_address(self) -> None:
        result = self.fw.run(
            "0", "0", CORE_INGRESS_ADDR="10.77.0.1/16", CORE_INGRESS_CIDR="10.77.0.0/16"
        )
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        hardening = (self.fw.box.root / "winsvpn-core-hardening.sh").read_text(encoding="utf-8")
        self.assertIn('CLIENT_IP="10.77.0.1"', hardening)
        self.assertNotIn("10.9.1.1", hardening)
        self.assertIn("ip rule add from 10.77.0.1/32 table main priority 32764", self.fw.box.calls())

    def test_stale_rule_for_another_address_does_not_suppress_the_new_one(self) -> None:
        result = self.fw.run(
            "0", "0", CORE_INGRESS_ADDR="10.9.1.1/16",
            STUB_IP_RULES="32764:\tfrom 10.9.1.10 lookup main\n32764:\tfrom 10.77.0.1 lookup main",
        )
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        self.assertIn("ip rule add from 10.9.1.1/32 table main priority 32764", self.fw.box.calls())

    def test_boot_hardening_matches_the_rule_exactly(self) -> None:
        # Turn 2 (Sol N-4): a 32764 rule for 10.9.1.10 is not one for 10.9.1.1.
        result = self.fw.run("0", "0")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        hardening = (self.fw.box.root / "winsvpn-core-hardening.sh").read_text(encoding="utf-8")
        hardening = hardening.replace("export PATH=/usr/sbin:/usr/bin:/sbin:/bin\n", "")
        self.fw.box.log.write_text("", encoding="utf-8")
        run = self.fw.box.run(hardening, {"STUB_IP_RULES": "32764:\tfrom 10.9.1.10 lookup main"})
        self.assertEqual(0, run.returncode, run.stderr)
        self.assertIn("ip -4 rule add priority 32764 from 10.9.1.1/32 lookup main", self.fw.box.calls())

    def test_sync_agent_matches_the_rule_exactly(self) -> None:
        agent = _staged_agent_text()
        anchor = "  ip route replace blackhole default table 5299 metric 42760 2>/dev/null || true\n"
        self.assertEqual(1, agent.count(anchor))
        start = agent.index(anchor) + len(anchor)
        end = agent.index("priority 32764 2>/dev/null || true\n", start)
        end = agent.index("  fi\n", end) + len("  fi\n")
        script = PRELUDE + "CORE_INGRESS_IP=10.9.1.1\ncheck() {\n" + agent[start:end] + "}\ncheck\n"
        self.fw.box.log.write_text("", encoding="utf-8")
        run = self.fw.box.run(script, {"STUB_IP_RULES": "32764:\tfrom 10.9.1.10 lookup main"})
        self.assertEqual(0, run.returncode, run.stderr)
        self.assertIn("ip rule add from 10.9.1.1/32 table main priority 32764", self.fw.box.calls())

    def test_existing_rule_is_not_duplicated(self) -> None:
        result = self.fw.run(
            "0", "0", STUB_IP_RULES="32764:\tfrom 10.9.1.1 lookup main\n32765:\tfrom 10.9.0.0/16 lookup 5299"
        )
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        self.assertFalse(any("priority 32764" in c for c in self.fw.box.calls() if c.startswith("ip rule add")))

    def test_invalid_address_is_refused_before_any_rule_is_built(self) -> None:
        result = self.fw.run("0", "0", CORE_INGRESS_ADDR="not-an-ip/16")
        self.assertNotIn("WRITE_FIREWALL_RC=0", result.stdout)
        self.assertFalse(any(c.startswith("iptables-restore") for c in self.fw.box.calls()))

    def test_sync_agent_derives_the_address_from_the_persisted_pool(self) -> None:
        agent = _staged_agent_text().replace('\nmain "$@"\n', "\n")
        box = Sandbox()
        try:
            agent_path = box.root / "agent.sh"
            agent_path.write_text(agent, encoding="utf-8")
            result = box.run(
                f'set -Eeuo pipefail\nCORE_ENV_FILE=/dev/null\nsource "{agent_path}"\nprintf "IP=%s\\n" "${{CORE_INGRESS_IP:-}}"\n',
                {"CORE_INGRESS_ADDR": "10.77.0.1/16"},
            )
            self.assertIn("IP=10.77.0.1", result.stdout, result.stderr)
        finally:
            box.close()


class CoreIpv6PolicyPersistenceTests(unittest.TestCase):
    """IA-CORE-12: IPv6 DROP policies are set and persisted, or the run fails."""

    def setUp(self) -> None:
        self.fw = FirewallHarness()

    def tearDown(self) -> None:
        self.fw.close()

    def test_policies_are_set_and_saved(self) -> None:
        result = self.fw.run("0", "0")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        calls = self.fw.box.calls()
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            self.assertIn(f"ip6tables -P {chain} DROP", calls)
        self.assertTrue((self.fw.box.root / "rules.v6").read_text(encoding="utf-8").startswith("*filter"))

    def test_policy_failure_fails_the_transaction(self) -> None:
        result = self.fw.run("0", "0", STUB_IP6_RC="1")
        self.assertNotIn("WRITE_FIREWALL_RC=0", result.stdout)
        self.assertIn("IPv6 fail-closed policies could not be set", result.stderr)

    def test_persist_failure_fails_the_transaction(self) -> None:
        result = self.fw.run("0", "0", STUB_IP6_SAVE_RC="1")
        self.assertNotIn("WRITE_FIREWALL_RC=0", result.stdout)
        self.assertIn("could not be persisted", result.stderr)

    def test_active_stack_without_ip6tables_fails_closed(self) -> None:
        # Turn 2 (Sol N-6): missing tooling is not a reason to skip enforcement.
        for name in ("ip6tables", "ip6tables-save"):
            (self.fw.box.bin / name).unlink()
        result = self.fw.run("0", "0", PATH=f"{self.fw.box.bin}:{BASH_DIR}:/usr/bin:/bin")
        self.assertNotIn("WRITE_FIREWALL_RC=0", result.stdout)
        self.assertIn("ip6tables/ip6tables-save is missing", result.stderr)

    def test_kernel_without_ipv6_is_skipped(self) -> None:
        result = self.fw.run("0", "0", CORE_IPV6_PROC_DIR=str(self.fw.box.root / "absent"), STUB_IP6_RC="1")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        self.assertFalse(any(c.startswith("ip6tables") for c in self.fw.box.calls()))


class CoreRerunJumpPositionTests(unittest.TestCase):
    """IA-CORE-18: a missing owned-chain jump never lands above the rerun hold."""

    HOLD = "INPUT -j WINVPN-CORE-FAILURE-HOLD-IN\nFORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD"

    def setUp(self) -> None:
        self.fw = FirewallHarness()

    def tearDown(self) -> None:
        self.fw.close()

    def test_rerun_with_hold_inserts_below_the_hold(self) -> None:
        result = self.fw.run("0", "0", CORE_INSTALLER_RERUN_ACTIVE="1", STUB_IPT_PRESENT=self.HOLD)
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        rules = self.fw.committed()
        self.assertIn("-I INPUT 2 -j WINVPN-CORE-INPUT", rules)
        self.assertIn("-I FORWARD 2 -j WINVPN-CORE-FORWARD", rules)
        self.assertNotIn("-I INPUT 1 -j WINVPN-CORE-INPUT", rules)
        # The rerun hold itself is left in place for release after postflight.
        self.assertFalse(any(r.startswith("-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN") for r in rules))

    def test_rerun_with_hold_moves_existing_jump_directly_below_the_hold(self) -> None:
        result = self.fw.run(
            "0", "0", CORE_INSTALLER_RERUN_ACTIVE="1", STUB_IPT_PRESENT=self.HOLD,
            STUB_INPUT_RULES="-P INPUT DROP\n-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN\n"
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j WINVPN-CORE-INPUT",
            STUB_FORWARD_RULES="-P FORWARD DROP\n-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD\n"
            "-A FORWARD -j ACCEPT\n-A FORWARD -j WINVPN-CORE-FORWARD",
        )
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        rules = self.fw.committed()
        self.assertLess(rules.index("-D INPUT -j WINVPN-CORE-INPUT"),
                        rules.index("-I INPUT 2 -j WINVPN-CORE-INPUT"))
        self.assertLess(rules.index("-D FORWARD -j WINVPN-CORE-FORWARD"),
                        rules.index("-I FORWARD 2 -j WINVPN-CORE-FORWARD"))
        self.assertNotIn("-I INPUT 1 -j WINVPN-CORE-INPUT", rules)
        self.assertFalse(any(r.startswith("-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN") for r in rules))

    def test_fresh_install_still_inserts_first(self) -> None:
        result = self.fw.run("0", "0")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        rules = self.fw.committed()
        self.assertIn("-I INPUT 1 -j WINVPN-CORE-INPUT", rules)
        self.assertIn("-I FORWARD 1 -j WINVPN-CORE-FORWARD", rules)

    def test_rerun_without_hold_inserts_first(self) -> None:
        result = self.fw.run("0", "0", CORE_INSTALLER_RERUN_ACTIVE="1")
        self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)
        self.assertIn("-I INPUT 1 -j WINVPN-CORE-INPUT", self.fw.committed())


class CoreRuntimeSuiteFirewallProbeTests(unittest.TestCase):
    """Turn 2 (Seat C N-1): tools/test_deployment_runtime_configs.sh runs the
    real write_firewall with its own variable set; that set must cover
    CORE_INGRESS_ADDR, which write_firewall now dereferences."""

    def test_runtime_suite_probe_blocks_reach_the_intended_outcome(self) -> None:
        import shlex
        text = (ROOT / "tools" / "test_deployment_runtime_configs.sh").read_text(encoding="utf-8")
        start = text.index("test_atomic_firewall_rebuild_contract() {")
        section = text[start:text.index('echo "PASS control/data/Core firewall replacement', start)]
        blocks = re.findall(r"SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT=0 (.*?)(?:write_firewall 1 1|unshare -m -n bash)", section, re.S)
        self.assertEqual(2, len(blocks))
        for block, refused in zip(blocks, (False, True)):
            tokens = shlex.split(block.replace("\\\n", " "))
            variables = {k: v for k, _, v in (t.partition("=") for t in tokens) if "$" not in v}
            variables["SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT"] = "0"
            # Rot P4 (recorded by lane IA-E2E, outside this lane): the suite
            # does not set CORE_AWG_MTU; P6 (core_tcp_mss_for_mtu) is supplied
            # by the harness. Nothing else is added.
            variables["CORE_AWG_MTU"] = "1280"
            fw = FirewallHarness()
            try:
                result = fw.run("1", "1", replace_variables=variables)
                # This run's own transaction workspace must be gone either way
                # (other lanes may use /tmp/winsvpn-core-firewall.* at the same
                # time, so only this run's recorded path is checked).
                left = (fw.box.root / "workspace.left").read_text(encoding="utf-8")
                self.assertFalse(left and Path(left).exists(), f"leaked {left}")
            finally:
                fw.close()
            self.assertNotIn("unbound variable", result.stderr)
            if refused:
                self.assertNotIn("WRITE_FIREWALL_RC=0", result.stdout)
                self.assertIn("Refusing unsafe whitespace", result.stderr)
            else:
                self.assertIn("WRITE_FIREWALL_RC=0", result.stdout, result.stderr)


# ---------------------------------------------------------------------------
# IA-CORE-03: relay_core_installer_transaction.py
# ---------------------------------------------------------------------------


def _relay_tree() -> ast.Module:
    return ast.parse(RELAY.read_text(encoding="utf-8"))


def _module_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                constants[node.targets[0].id] = node.value.value
    return constants


def _resolve_string(node: ast.AST, constants: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    raise AssertionError(f"cannot resolve string from {ast.dump(node)}")


def _relay_local_string(name: str) -> str:
    tree = _relay_tree()
    constants = _module_constants(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return _resolve_string(node.value, constants)
    raise AssertionError(f"relay assignment {name} not found")


def _emitted_texts(source: str) -> list[tuple[str | None, str]]:
    """(enclosing function, emitted literal) for each log/echo/err/warn line."""
    out: list[tuple[str | None, str]] = []
    current: str | None = None
    for line in source.splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) [{(]$", line)
        if match:
            current = match.group(1)
            continue
        if line in ("}", ")"):
            current = None
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for verb, prefix in (("log", "[CORE] "), ("echo", ""), ("err", "[ERR] "), ("warn", "[WARN] ")):
            emitted = re.match(rf'^{verb} "([^"]*)"', stripped)
            if emitted:
                out.append((current, prefix + emitted.group(1)))
    return out


def _called_functions(source: str) -> set[str]:
    names: set[str] = set()
    definitions = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) [{(]$", source, re.MULTILINE))
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\) [{(]$", line):
            continue
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
            if word in definitions:
                names.add(word)
    return names


class RelayCoreInstallerTransactionTests(unittest.TestCase):
    """IA-CORE-03: the relay helper must agree with what the installer does."""

    def test_preflight_marker_is_what_main_logs(self) -> None:
        tree = _relay_tree()
        constants = _module_constants(tree)
        needles = []
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "preflight_passed":
                for compare in ast.walk(node.value):
                    if isinstance(compare, ast.Compare) and isinstance(compare.ops[0], ast.In):
                        needles.append(_resolve_string(compare.left, constants))
        self.assertEqual(1, len(needles))
        main_body = _function(_core(), "main", -1)
        self.assertTrue(
            any(needles[0] in text for _, text in _emitted_texts(main_body)),
            f"{needles[0]!r} is not logged by main()",
        )

    def test_status_markers_are_live_and_ordered_by_last_occurrence(self) -> None:
        probe = _relay_local_string("probe")
        markers = None
        for node in ast.walk(ast.parse(probe)):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "markers" for t in node.targets):
                markers = ast.literal_eval(node.value)
        self.assertIsNotNone(markers)
        source = _core()
        emitted = _emitted_texts(source)
        called = _called_functions(source)
        for name, needle in markers:
            live = [text for function, text in emitted if needle in text and (function is None or function in called)]
            self.assertTrue(live, f"marker {name}: {needle!r} is not emitted by any live function")
        # rfind() picks the last occurrence, so nothing main() prints after the
        # completion marker may match another stage's needle.
        main_body = _function(source, "main", -1)
        tail = main_body[main_body.index('log "Core server setup complete"'):]
        tail_texts = [t for _, t in _emitted_texts(tail)]
        for function in _called_functions(source) & set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail)):
            tail_texts.extend(t for _, t in _emitted_texts(_function(source, function)))
        for name, needle in markers:
            if name == "complete":
                continue
            self.assertFalse(
                [t for t in tail_texts if needle in t],
                f"marker {name}: {needle!r} also matches output printed after completion",
            )

    def _run_recovery(
        self,
        queue_rules_per_transport: int = 1,
        remediation: str = "inactive",
        hold: bool | str = False,
        hold_lock: bool = False,
        list_fail: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], Sandbox]:
        recovery = _relay_local_string("recovery")
        box = Sandbox()
        root = box.root
        source = _core()
        installer = root / "installer.sh"
        installer.write_text(
            PRELUDE.replace("set -Eeuo pipefail\n", "")
            + _function(source, "valid_port")
            + _function(source, "normalize_core_stealth_transports")
            + textwrap.dedent(f'''\
                INSTALL_CORE_IDS_IPS_DEFAULT=1
                load_existing_core_env_for_preflight() {{
                  CORE_STEALTH_TRANSPORTS="80:none,443:tls"
                  CORE_STEALTH_ORIGIN_PORT=80
                  CORE_XRAY_SECURITY=none
                  INSTALL_CORE_IDS_IPS=1
                }}
                write_firewall() {{
                  printf 'WRITE_FIREWALL %s\\n' "$*" >> "${{CALL_LOG}}"
                  lockprobe "${{WORK}}/deployment.lock" | sed 's/^/AT_COMMIT_/' >> "${{CALL_LOG}}"
                  local route n
                  # The real write_firewall persists both rule files and fails on either.
                  printf '*filter persisted-by-write_firewall\\n' > "${{WORK}}/etc/rules.v6"
                  : > "${{WORK}}/active.rules"
                  printf -- '-P INPUT DROP\\n' >> "${{WORK}}/active.rules"
                  while IFS= read -r route; do
                    [[ -n "${{route}}" ]] || continue
                    for ((n = 0; n < {queue_rules_per_transport}; n++)); do
                      printf -- '-A WINVPN-CORE-INPUT -p tcp --dport %s -j NFQUEUE --queue-num 0\\n' "${{route%%:*}}" >> "${{WORK}}/active.rules"
                    done
                    if [[ "${{2:-0}}" == 1 ]]; then
                      printf -- '-A WINVPN-CORE-INPUT -p tcp --dport %s -j ACCEPT\\n' "${{route%%:*}}" >> "${{WORK}}/active.rules"
                    fi
                  done < <(tr ',' '\\n' <<<"${{CORE_STEALTH_TRANSPORTS}}")
                }}
                '''),
            encoding="utf-8",
        )
        (root / "nfqueue").write_text("0 1 0 2 65531 0 0 0 1\n", encoding="ascii")
        (root / "etc").mkdir()
        box.stub("systemctl", f'''\
            if [[ "$*" == *"-p ExecStart --value"* ]]; then echo "argv[]=/usr/bin/suricata -D -q 0 ;"; fi
            if [[ "$*" == "is-active winsvpn-core-live-remediation.service" ]]; then echo {remediation}; fi
            exit 0
            ''')
        box.stub("suricatasc", "exit 0\n")
        box.stub("iptables-save", 'cat "${WORK}/active.rules"\n')
        # Turn 2 (Sol N-3): a later ip6tables-save that fails must not be able
        # to truncate what write_firewall persisted.
        box.stub("ip6tables-save", "exit 1\n")
        # Follow-up N-7(c): the hold jumps are visible in `-S CHAIN`; a chain
        # named in list_fail cannot be listed (rc 4, as for a busy xtables
        # lock), and `-C` then fails with the same rc 4.
        hold_chains = "INPUT\nFORWARD\n" if hold is True else (f"{hold}\n" if hold else "")
        (root / "hold_chains").write_text(hold_chains, encoding="ascii")
        (root / "list_fail").write_text(f"{list_fail}\n" if list_fail else "", encoding="ascii")
        box.stub("iptables", '''\
            if [[ "$1" == "-w" ]]; then shift 2; fi
            if [[ "$1" == "-S" ]]; then
              if grep -qx -- "$2" "${WORK}/list_fail"; then exit 4; fi
              printf -- '-P %s DROP\\n' "$2"
              if grep -qx -- "$2" "${WORK}/hold_chains"; then
                case "$2" in INPUT) printf -- '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN\\n' ;; FORWARD) printf -- '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD\\n' ;; esac
              fi
            fi
            if [[ "$1" == "-C" ]]; then
              if [[ -s "${WORK}/list_fail" ]]; then exit 4; fi
              grep -qx -- "$2" "${WORK}/hold_chains"; exit $?
            fi
            exit 0
            ''')
        script = (
            recovery.replace("/root/wins_core_server_setup_ONETOUCH.sh", str(installer))
            .replace("/run/lock/wins-core-deployment.lock", str(root / "deployment.lock"))
            .replace("/etc/iptables/", str(root / "etc") + "/")
            .replace("/proc/net/netfilter/nfnetlink_queue", str(root / "nfqueue"))
        )
        holder = None
        if hold_lock:
            holder = subprocess.Popen(
                [sys.executable, "-c",
                 "import fcntl,sys,time\nf=open(sys.argv[1],'a')\nfcntl.flock(f,fcntl.LOCK_EX)\nprint('locked',flush=True)\ntime.sleep(60)",
                 str(root / "deployment.lock")],
                stdout=subprocess.PIPE, text=True,
            )
            self.assertEqual("locked", holder.stdout.readline().strip())
        try:
            return box.run(script), box
        finally:
            if holder is not None:
                holder.kill()
                holder.wait()
                holder.stdout.close()

    def test_recovery_restores_the_serving_firewall_and_reports_success(self) -> None:
        result, box = self._run_recovery()
        try:
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            payload = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertIs(True, payload["ok"])
            self.assertEqual(2, payload["nfqueue_rule_count"])
            self.assertIn("WRITE_FIREWALL 1 1", box.calls())
            active = (box.root / "active.rules").read_text(encoding="utf-8")
            self.assertIn("--dport 443 -j ACCEPT", active)
            self.assertEqual(
                "*filter persisted-by-write_firewall\n",
                (box.root / "etc" / "rules.v6").read_text(encoding="utf-8"),
            )
        finally:
            box.close()

    def _select(self, rows: list[tuple[str, str, str, str | None]]) -> list[str]:
        """Run the relay's own Core selection SQL on an in-memory hub table."""
        import sqlite3
        tree = _relay_tree()
        constants = _module_constants(tree)
        sql = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
            ):
                sql = _resolve_string(node.args[0], constants)
        self.assertIsNotNone(sql)
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.execute(
            "CREATE TABLE core_servers (core_id TEXT, management_host TEXT, management_user TEXT, "
            "status TEXT, management_status TEXT, deployment_withdrawal_id TEXT)"
        )
        for core_id, status, management_status, withdrawal in rows:
            db.execute(
                "INSERT INTO core_servers VALUES (?, ?, 'ubuntu', ?, ?, ?)",
                (core_id, core_id + ".invalid", status, management_status, withdrawal),
            )
        hosts = [row["host"] for row in db.execute(sql).fetchall()]
        db.close()
        return hosts

    def test_relay_still_reaches_a_core_withdrawn_for_a_rerun(self) -> None:
        # Turn 2 (Seat C OI-COREB-5): the hub keeps a withdrawn Core in
        # maintenance until its new agent registers.
        self.assertEqual(["a.invalid"], self._select([("a", "online", "ok", None)]))
        self.assertEqual(["a.invalid"], self._select([("a", "maintenance", "ok", "0" * 32)]))

    def test_relay_never_selects_other_non_serving_cores(self) -> None:
        self.assertEqual([], self._select([("a", "maintenance", "ok", None)]))
        self.assertEqual([], self._select([("a", "maintenance", "ok", "")]))
        self.assertEqual([], self._select([("a", "offline", "ok", "0" * 32)]))
        self.assertEqual([], self._select([("a", "maintenance", "failed", "0" * 32)]))

    # ---- Turn 4 (Sol N-9): recovery is serialized with deployment ----

    def test_recovery_refuses_while_a_deployment_holds_the_lock(self) -> None:
        result, box = self._run_recovery(hold_lock=True)
        try:
            self.assertEqual(72, result.returncode, result.stdout + result.stderr)
            self.assertFalse([c for c in box.calls() if c.startswith("WRITE_FIREWALL")])
        finally:
            box.close()

    def test_recovery_holds_the_deployment_lock_through_its_commit(self) -> None:
        result, box = self._run_recovery()
        try:
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            calls = box.calls()
            self.assertIn("AT_COMMIT_LOCK_HELD", calls)
            self.assertNotIn("AT_COMMIT_LOCK_FREE", calls)
        finally:
            box.close()

    def test_recovery_checks_holds_only_after_taking_the_lock(self) -> None:
        script = _relay_local_string("recovery")
        lock = script.index("flock -n 7 || exit 72")
        self.assertLess(lock, script.index("exit 73"))
        self.assertLess(lock, script.index("exit 74"))
        self.assertLess(script.index("exit 74"), script.index("write_firewall"))
        # Follow-up OI-COREB-T2-3 / SOL-N-9: one literal path on both sides.
        installer_literal = re.search(
            r"^  local lock_file=(/\S+)$", _function(_core(), "acquire_core_deployment_lock"), re.M
        ).group(1)
        self.assertEqual("/run/lock/wins-core-deployment.lock", installer_literal)
        self.assertIn(f"exec 7>>{installer_literal}\n", script)

    def test_recovery_refuses_while_an_installer_transaction_runs(self) -> None:
        # Turn 3 (OI-COREB-T2-3): never beside an active rerun transaction.
        for state in ("active", "activating", "deactivating"):
            result, box = self._run_recovery(remediation=state)
            try:
                self.assertEqual(73, result.returncode, result.stdout + result.stderr)
                self.assertFalse([c for c in box.calls() if c.startswith("WRITE_FIREWALL")])
            finally:
                box.close()

    def test_recovery_refuses_while_a_fail_closed_hold_is_in_place(self) -> None:
        # Turn 3 (OI-COREB-T2-3): the hold is released only by postflight.
        for hold in (True, "INPUT", "FORWARD"):
            result, box = self._run_recovery(hold=hold)
            try:
                self.assertEqual(74, result.returncode, f"{hold}: " + result.stdout + result.stderr)
                self.assertFalse([c for c in box.calls() if c.startswith("WRITE_FIREWALL")])
            finally:
                box.close()

    def test_recovery_fails_closed_when_a_chain_cannot_be_listed(self) -> None:
        # Follow-up N-7(c): an iptables error is not "no hold".
        for chain in ("INPUT", "FORWARD"):
            result, box = self._run_recovery(list_fail=chain)
            try:
                self.assertNotEqual(0, result.returncode, chain)
                self.assertNotIn(result.returncode, (72, 73, 74), chain)
                self.assertFalse([c for c in box.calls() if c.startswith("WRITE_FIREWALL")], chain)
            finally:
                box.close()

    def _main_remote_rc(self, returncode: int) -> dict:
        """Run the relay's real main() for recover-firewall with the remote
        recovery script exiting `returncode` (follow-up N-12, X1 and X2)."""
        import importlib.util
        import io
        import sqlite3
        from unittest import mock
        spec = importlib.util.spec_from_file_location("relay_under_test", RELAY)
        relay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(relay)
        db = sqlite3.connect(":memory:")
        db.execute(
            "CREATE TABLE core_servers (core_id TEXT, management_host TEXT, management_user TEXT, "
            "status TEXT, management_status TEXT, deployment_withdrawal_id TEXT)"
        )
        db.execute("INSERT INTO core_servers VALUES ('c', 'core.invalid', 'ubuntu', 'online', 'ok', NULL)")

        class Stat:
            st_mode = 0o100600
            st_uid = 0

        def remote(argv, **kwargs):
            return subprocess.CompletedProcess(argv, returncode, b"", b"")

        out = io.StringIO()
        with mock.patch.dict(os.environ, {"WINS_CORE_INSTALL_ACTION": "recover-firewall"}), \
                mock.patch.object(relay.sys, "stdin", io.StringIO("password\n")), \
                mock.patch.object(relay.os, "geteuid", return_value=0), \
                mock.patch.object(relay.sqlite3, "connect", return_value=db), \
                mock.patch.object(relay.subprocess, "run", side_effect=remote), \
                mock.patch.object(relay.pathlib.Path, "is_file", return_value=True), \
                mock.patch.object(relay.pathlib.Path, "is_symlink", return_value=False), \
                mock.patch.object(relay.pathlib.Path, "stat", return_value=Stat()), \
                mock.patch.object(relay.pathlib.Path, "read_text", return_value="core.invalid ssh-ed25519 AAAA\n"), \
                mock.patch("sys.stdout", out):
            relay.main()
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def test_relay_names_each_recovery_refusal(self) -> None:
        for returncode, error_type in (
            (72, "deployment_in_progress"),
            (73, "installer_transaction_active"),
            (74, "deployment_hold_active"),
            (1, "firewall_recovery_failed"),
        ):
            payload = self._main_remote_rc(returncode)
            self.assertIs(False, payload["ok"], returncode)
            self.assertEqual(error_type, payload.get("error_type"), returncode)

    def _main(self, action: str, withdrawal_id: str | None) -> tuple[dict, list[str]]:
        """Run the relay's real main() up to its first remote call."""
        import importlib.util
        import io
        import sqlite3
        from unittest import mock
        spec = importlib.util.spec_from_file_location("relay_under_test", RELAY)
        relay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(relay)
        db = sqlite3.connect(":memory:")
        db.execute(
            "CREATE TABLE core_servers (core_id TEXT, management_host TEXT, management_user TEXT, "
            "status TEXT, management_status TEXT, deployment_withdrawal_id TEXT)"
        )
        db.execute(
            "INSERT INTO core_servers VALUES ('c', 'core.invalid', 'ubuntu', ?, 'ok', ?)",
            ("maintenance" if withdrawal_id else "online", withdrawal_id),
        )
        remote_calls: list[str] = []

        def no_remote(*args, **kwargs):
            remote_calls.append(repr(args))
            raise AssertionError("the relay must not reach the Core here")

        out = io.StringIO()
        with mock.patch.dict(os.environ, {"WINS_CORE_INSTALL_ACTION": action}), \
                mock.patch.object(relay.sys, "stdin", io.StringIO("password\n")), \
                mock.patch.object(relay.os, "geteuid", return_value=0), \
                mock.patch.object(relay.sqlite3, "connect", return_value=db), \
                mock.patch.object(relay.subprocess, "run", side_effect=no_remote), \
                mock.patch.object(relay.pathlib.Path, "is_file", return_value=False), \
                mock.patch("sys.stdout", out):
            relay.main()
        return json.loads(out.getvalue().strip().splitlines()[-1]), remote_calls

    def test_relay_refuses_recover_firewall_on_a_withdrawn_core(self) -> None:
        payload, remote_calls = self._main("recover-firewall", "0" * 32)
        self.assertIs(False, payload["ok"])
        self.assertEqual("core_withdrawn_for_deployment", payload["error_type"])
        self.assertEqual([], remote_calls)

    def test_relay_keeps_other_actions_for_a_withdrawn_core(self) -> None:
        # These get past Core selection and stop at the hub SSH prerequisites
        # (reported absent by the patched Path.is_file, so the result does not
        # depend on whether the test user can read /root), never at the
        # withdrawal refusal.
        for action in ("status", "reboot", "start", "stage-validate"):
            payload, _ = self._main(action, "0" * 32)
            self.assertEqual("unsafe_management_prerequisite", payload.get("error_type"), action)
        payload, _ = self._main("recover-firewall", None)
        self.assertEqual("unsafe_management_prerequisite", payload.get("error_type"))

    def test_recovery_reports_failure_when_queue_rules_drift(self) -> None:
        result, box = self._run_recovery(queue_rules_per_transport=2)
        try:
            self.assertNotEqual(0, result.returncode)
            payload = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertIs(False, payload["ok"])
        finally:
            box.close()


# ---------------------------------------------------------------------------
# IA-CORE-06: the installer's own image build must not be killed by the monitor
# ---------------------------------------------------------------------------


class CoreBuildMonitorPauseTests(unittest.TestCase):
    def _run(
        self, timer_active: bool, producer_rc: int, term_on_stop: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        box = Sandbox()
        try:
            state = box.root / "monitor.state"
            state.write_text("running\n" if timer_active else "inactive\n", encoding="ascii")
            box.stub("systemctl", '''\
                printf 'systemctl %s\\n' "$*" >> "${CALL_LOG}"
                state="${WORK}/monitor.state"
                case "$1" in
                  is-active) [[ "$(cat "${state}")" == running ]]; exit $? ;;
                  stop) [[ "$*" == *wins-core-build-monitor.timer* ]] && echo stopped > "${state}"
                        # Turn 2 (Sol OI-COREB-1): the installer is terminated
                        # right after the monitor was paused.
                        [[ "${STUB_TERM_ON_STOP:-0}" == 1 ]] && kill -TERM "${PPID}"
                        exit 0 ;;
                  start) [[ "$*" == *wins-core-build-monitor.timer* ]] && echo running > "${state}"; exit 0 ;;
                esac
                exit 0
                ''')
            producer = box.root / "producer.sh"
            producer.write_text(textwrap.dedent(f'''\
                #!/usr/bin/env bash
                printf 'PRODUCER monitor=%s args=%s\\n' "$(cat "${{WORK}}/monitor.state")" "$*" >> "${{CALL_LOG}}"
                [[ {producer_rc} == 0 ]] || exit {producer_rc}
                printf 'amneziavpn/amneziawg-go:v3.1.20260828'
                '''), encoding="utf-8")
            digest = hashlib.sha256(producer.read_bytes()).hexdigest()
            function = _function(_core(), "select_awg_image", 0)
            script = PRELUDE + textwrap.dedent(f'''\
                AWG_SERVER_IMAGE_PRODUCER_INSTALLED="{producer}"
                AWG_SERVER_IMAGE_PRODUCER_SOURCE="{box.root}/absent-source.sh"
                AWG_SERVER_IMAGE_PRODUCER_SHA256="{digest}"
                AWG_DOCKER_IMAGE="amneziavpn/amneziawg-go:v3.1.20260828"
                ''') + function + '\nif image="$(select_awg_image)"; then echo "IMAGE=${image}"; else echo "SELECT_RC=$?"; fi\n'
            result = box.run(script, {"STUB_TERM_ON_STOP": "1" if term_on_stop else "0"})
            calls = box.calls() + ["STATE " + state.read_text(encoding="ascii").strip()]
            return result, calls
        finally:
            box.close()

    def test_termination_after_the_pause_still_restores_the_monitor(self) -> None:
        result, calls = self._run(True, 0, term_on_stop=True)
        self.assertNotIn("IMAGE=", result.stdout)
        self.assertFalse([c for c in calls if c.startswith("PRODUCER")])
        self.assertIn("systemctl start wins-core-build-monitor.timer", calls)
        self.assertEqual("STATE running", calls[-1])

    def test_build_runs_with_the_monitor_paused_and_restored(self) -> None:
        result, calls = self._run(True, 0)
        self.assertIn("IMAGE=amneziavpn/amneziawg-go:v3.1.20260828", result.stdout, result.stderr)
        producer = [c for c in calls if c.startswith("PRODUCER")]
        self.assertEqual(["PRODUCER monitor=stopped args=--ensure"], producer)
        self.assertEqual("systemctl start wins-core-build-monitor.timer", [c for c in calls if c.startswith("systemctl start")][-1])
        self.assertGreater(calls.index("systemctl start wins-core-build-monitor.timer"), calls.index(producer[0]))

    def test_failed_build_still_restores_the_monitor(self) -> None:
        result, calls = self._run(True, 3)
        self.assertIn("SELECT_RC=1", result.stdout, result.stderr)
        self.assertIn("systemctl start wins-core-build-monitor.timer", calls)
        self.assertIn("Could not build and verify", result.stderr)

    def test_inactive_monitor_is_left_alone(self) -> None:
        result, calls = self._run(False, 0)
        self.assertIn("IMAGE=", result.stdout, result.stderr)
        self.assertFalse([c for c in calls if c.startswith(("systemctl stop", "systemctl start"))])


# ---------------------------------------------------------------------------
# IA-CORE-08: persisted env values that override operator input are named
# ---------------------------------------------------------------------------


class CorePersistedEnvOverrideTests(unittest.TestCase):
    def _run(self, operator: dict[str, str]) -> subprocess.CompletedProcess[str]:
        source = _core()
        box = Sandbox()
        try:
            env_file = box.root / "wins_core.env"
            env_file.write_text(
                "CORE_OPEN_PUBLIC_INGRESS=1\nCORE_MAX_XRAY_CONNECTIONS=65535\n"
                "CORE_XRAY_UUID=11111111-2222-3333-4444-555555555555\nADMIN_TOKEN=''\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            marker = "# IA-CORE-08: remember what the operator supplied"
            snapshot = ""
            if marker in source:
                start = source.index(marker)
                end = source.index("unset wins_supplied_name\n", start) + len("unset wins_supplied_name\n")
                snapshot = source[start:end]
            script = (
                PRELUDE
                + snapshot
                + 'CORE_OPEN_PUBLIC_INGRESS="${CORE_OPEN_PUBLIC_INGRESS:-1}"\n'
                + 'CORE_MAX_XRAY_CONNECTIONS="${CORE_MAX_XRAY_CONNECTIONS:-auto}"\n'
                + f'CORE_ENV_FILE="{env_file}"\n'
                # FLEET1 TP-C3: the loader calls this helper right after sourcing.
                + (_function(source, "core_restore_operator_supplied_pairing_inputs")
                   if "\ncore_restore_operator_supplied_pairing_inputs() {\n" in source else "")
                + _function(source, "load_existing_core_env_for_preflight")
                + 'load_existing_core_env_for_preflight\nprintf "OPEN=%s\\n" "${CORE_OPEN_PUBLIC_INGRESS}"\n'
            )
            return box.run(script, operator)
        finally:
            box.close()

    def test_operator_value_overridden_by_persisted_value_is_named(self) -> None:
        result = self._run({"CORE_OPEN_PUBLIC_INGRESS": "0", "CORE_XRAY_UUID": "99999999-0000-0000-0000-000000000000"})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("OPEN=1", result.stdout)
        self.assertIn("CORE_OPEN_PUBLIC_INGRESS from", result.stderr)
        self.assertIn("CORE_XRAY_UUID from", result.stderr)
        # Values are never printed, and built-in defaults are not compared.
        self.assertNotIn("11111111-2222", result.stderr + result.stdout)
        self.assertNotIn("99999999", result.stderr + result.stdout)
        self.assertNotIn("CORE_MAX_XRAY_CONNECTIONS", result.stderr)

    def test_unchanged_rerun_is_quiet(self) -> None:
        result = self._run({"CORE_OPEN_PUBLIC_INGRESS": "1"})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("[WARN]", result.stderr)


# ---------------------------------------------------------------------------
# IA-CORE-10: request bodies are never passed in curl argv
# ---------------------------------------------------------------------------


class CoreCurlArgvTests(unittest.TestCase):
    def test_no_request_body_is_passed_as_a_curl_argument(self) -> None:
        source = _core()
        self.assertEqual([], re.findall(r'--data(?:-raw|-urlencode)? "\$\{?[a-z_]+', source))
        self.assertEqual(5, source.count("--data-binary @-"))

    @unittest.skipUnless(shutil.which("jq"), "register_core builds its payload with jq")
    def test_registration_uuid_travels_on_stdin_not_argv(self) -> None:
        agent = _staged_agent_text().replace('\nmain "$@"\n', "\n")
        box = Sandbox()
        try:
            agent_path = box.root / "agent.sh"
            agent_path.write_text(agent, encoding="utf-8")
            uuid = "0c9a3f4e-1b2d-4c5e-8f60-7a8b9c0d1e2f"
            # Turn 2 (Sol N-5): every jq invocation's argv is recorded too.
            real_jq = shutil.which("jq") or "/usr/bin/jq"
            box.stub("jq", f'printf "%s\\n" "$*" >> "${{WORK}}/jq-argv"\nexec {real_jq} "$@"\n')
            script = textwrap.dedent(f'''\
                set -Eeuo pipefail
                CORE_ENV_FILE=/dev/null
                source "{agent_path}"
                CORE_TOKEN=token-for-test
                CORE_XRAY_UUID={uuid}
                CORE_INGRESS_PUBLIC_KEY=ingress
                CORE_EXIT_PUBLIC_KEY=exit
                persist_core_advertised_state() {{ :; }}
                curl() {{
                  printf '%s\\n' "$@" > "${{WORK}}/argv"
                  cat > "${{WORK}}/stdin"
                  printf '{{"ok":true}}'
                }}
                register_core false
                echo REGISTERED
                ''')
            result = box.run(script)
            self.assertIn("REGISTERED", result.stdout, result.stderr)
            argv = (box.root / "argv").read_text(encoding="utf-8")
            body = json.loads((box.root / "stdin").read_text(encoding="utf-8"))
            self.assertNotIn(uuid, argv)
            self.assertEqual(uuid, body["xray_uuid"])
            jq_argv = (box.root / "jq-argv").read_text(encoding="utf-8")
            self.assertIn("--arg core_id", jq_argv)
            self.assertNotIn(uuid, jq_argv)
        finally:
            box.close()

    # ---- Turn 3 (Seat C N-4): every jq call that handles a UUID or token ----

    SENSITIVE = re.compile(r"(?i)(uuid|token|grant|secret|psk|preshared|private|password)")

    def _jq_commands(self, text: str) -> list[str]:
        commands: list[str] = []
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            line = lines[index]
            if re.search(r"(^|[\s(|;$])jq\s", line):
                joined = line
                while joined.rstrip().endswith("\\") and index + 1 < len(lines):
                    index += 1
                    joined = joined.rstrip()[:-1] + " " + lines[index]
                commands.append(joined)
            index += 1
        return commands

    def test_no_jq_call_takes_a_credential_through_argv(self) -> None:
        offending = []
        for text in (_core(), _staged_agent_text()):
            for command in self._jq_commands(text):
                for name, value in re.findall(r'--arg(?:json)?\s+(\w+)\s+"([^"]*)"', command):
                    variables = re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", value)
                    if any(self.SENSITIVE.search(v) and "public" not in v.lower() for v in variables + [name]) \
                            and "public" not in name.lower():
                        offending.append(f"--arg {name} {value}")
        self.assertEqual([], offending)

    def _jq_shim(self, box: Sandbox) -> None:
        real_jq = shutil.which("jq") or "/usr/bin/jq"
        box.stub("jq", f'printf "%s\\n" "$*" >> "${{WORK}}/jq-argv"\nexec {real_jq} "$@"\n')

    @unittest.skipUnless(shutil.which("jq"), "the exit Xray config is rendered with jq")
    def test_exit_xray_uuid_never_reaches_jq_argv(self) -> None:
        uuid = "11111111-2222-4333-8444-555555555555"
        agent = _staged_agent_text().replace('\nmain "$@"\n', "\n")
        box = Sandbox()
        try:
            self._jq_shim(box)
            config_dir = box.root / "core-exits"
            agent_path = box.root / "agent.sh"
            agent_path.write_text(agent, encoding="utf-8")
            function = _function(agent, "ensure_exit_xray").replace(
                "/usr/local/etc/xray/core-exits", str(config_dir)
            )
            selected = json.dumps({
                "host": "exit.invalid", "port": 443, "security": "tls", "server_name": "exit.invalid",
                "path": "/p", "uuid": uuid, "remote_awg_port": 9110,
            })
            script = (
                "set -Eeuo pipefail\nCORE_ENV_FILE=/dev/null\n"
                f'source "{agent_path}"\n'
                f"select_reachable_xray_transport() {{ printf '%s' '{selected}'; }}\n"
                "wins_exec_reviewed_xray() { :; }\n"
                "chown() { :; }\nsystemctl() { return 0; }\n"
                'install() { if [[ "$1" == -d ]]; then command mkdir -p "${@: -1}"; else : > "${@: -1}"; fi; }\n'
                + function
                + "ensure_exit_xray '{}' corex1 20001 >/dev/null\necho RENDERED\n"
            )
            result = box.run(script)
            self.assertIn("RENDERED", result.stdout, result.stderr)
            argv = (box.root / "jq-argv").read_text(encoding="utf-8")
            self.assertIn("--arg host", argv)
            self.assertNotIn(uuid, argv)
            config = json.loads((config_dir / "corex1.json").read_text(encoding="utf-8"))
            self.assertEqual(uuid, config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"])
        finally:
            box.close()

    @unittest.skipUnless(shutil.which("jq"), "the bootstrap request is built with jq")
    def test_bootstrap_grant_never_reaches_jq_argv(self) -> None:
        grant = "grant-" + "a1" * 20
        box = Sandbox()
        try:
            self._jq_shim(box)
            script = (
                PRELUDE
                + "CORE_ID=test-core\nHUB_API_BASE=https://hub.invalid\n"
                + f"CORE_BOOTSTRAP_TOKEN={grant}\n"
                + "persist_core_token() { :; }\n"
                + 'curl() { local prev="" a; for a in "$@"; do [[ "${prev}" == --data-binary ]] && cp -- "${a#@}" "${WORK}/request"; prev="$a"; done; printf \'{"core_token":"issued"}\'; }\n'
                + _function(_core(), "bootstrap_core_token")
                + 'bootstrap_core_token\nprintf "TOKEN=%s\\n" "${CORE_TOKEN}"\n'
            )
            result = box.run(script)
            self.assertIn("TOKEN=issued", result.stdout, result.stderr)
            self.assertNotIn(grant, (box.root / "jq-argv").read_text(encoding="utf-8"))
            request = json.loads((box.root / "request").read_text(encoding="utf-8"))
            self.assertEqual(grant, request["bootstrap_token"])
        finally:
            box.close()


# ---------------------------------------------------------------------------
# IA-CORE-11: the AWG obfuscation profile is trust-checked before sourcing
# ---------------------------------------------------------------------------


class CoreObfuscationProfileTrustTests(unittest.TestCase):
    PROFILE_LINE = 'AWG_OBFUSCATION_PROFILE="${AWG_OBFUSCATION_PROFILE:-/etc/winsvpn/awg-obfuscation.env}"'

    def _snippet(self, text: str) -> str:
        start = text.index(self.PROFILE_LINE)
        end = text.index("\nfi\n", start) + len("\nfi\n")
        return text[start:end]

    def _cases(self, snippet: str, extra: str = "") -> None:
        box = Sandbox()
        try:
            profile = box.root / "awg-obfuscation.env"
            profile.write_text("AWG_H1=123456789\n", encoding="ascii")
            script = PRELUDE + extra + snippet + 'printf "H1=%s\\n" "${AWG_H1:-unset}"\n'
            env = {"AWG_OBFUSCATION_PROFILE": str(profile)}
            profile.chmod(0o600)
            result = box.run(script, env)
            self.assertIn("H1=123456789", result.stdout, result.stderr)
            profile.chmod(0o644)
            result = box.run(script, env)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("H1=123456789", result.stdout)
            profile.chmod(0o600)
            result = box.run(script, {**env, "STUB_STAT_UID": "1000"})
            self.assertNotEqual(0, result.returncode)
            link = box.root / "link.env"
            link.symlink_to(profile)
            result = box.run(script, {"AWG_OBFUSCATION_PROFILE": str(link)})
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("H1=123456789", result.stdout)
        finally:
            box.close()

    def test_installer_refuses_an_untrusted_profile(self) -> None:
        source = _core()
        self._cases(self._snippet(source), _function(source, "wins_require_trusted_env_file"))

    def test_sync_agent_refuses_an_untrusted_profile(self) -> None:
        self._cases(self._snippet(_staged_agent_text()))


class CoreRelativeEnvPathTests(unittest.TestCase):
    """A1-ARGON-F3: for a name with no slash, `.` and `source` search PATH
    before the working directory, while the trust checks (stat, find) look in
    the working directory, so the file that passed is not the file that runs.
    Every Core gate refuses a relative path, as the control plane's (Muse L03
    F-5) and the data plane's (R1-ARGON-5) wins_require_trusted_env_file do."""

    NAME = "probe.env"
    CORE_ENV_BLOCK = 'CORE_ENV_FILE="${CORE_ENV_FILE:-/root/wins_core.env}"\nif [[ -f "${CORE_ENV_FILE}" ]]; then\n'

    @staticmethod
    def _block(text: str, start_marker: str) -> str:
        start = text.index(start_marker)
        return text[start:text.index("\nfi\n", start) + len("\nfi\n")]

    def _assert_refused(self, body: str, variable: str) -> None:
        box = Sandbox()
        try:
            work = box.root / "cwd"
            work.mkdir(mode=0o700)
            checked = work / self.NAME
            checked.write_text("SRC=checked\n", encoding="ascii")
            checked.chmod(0o600)
            planted = box.bin / self.NAME
            planted.write_text("SRC=planted\n", encoding="ascii")
            planted.chmod(0o666)
            script = PRELUDE + f"cd '{work}'\n" + body + 'printf "SRC=%s\\n" "${SRC:-none}"\n'
            result = box.run(script, {variable: self.NAME})
        finally:
            box.close()
        self.assertNotIn("SRC=planted", result.stdout, "the gate checked ./probe.env and sourced the copy on PATH")
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("must be an absolute path", result.stderr)

    def test_installer_gate_refuses_a_relative_path(self) -> None:
        source = _core()
        snippet = CoreObfuscationProfileTrustTests()._snippet(source)
        self._assert_refused(_function(source, "wins_require_trusted_env_file") + snippet,
                             "AWG_OBFUSCATION_PROFILE")

    def test_preflight_env_loader_refuses_a_relative_path(self) -> None:
        body = textwrap.dedent("""\
            declare -A WINS_CORE_OPERATOR_SUPPLIED=()
            core_restore_operator_supplied_pairing_inputs() { :; }
            """) + _function(_core(), "load_existing_core_env_for_preflight") + "load_existing_core_env_for_preflight\n"
        self._assert_refused(body, "CORE_ENV_FILE")

    def test_sync_agent_refuses_a_relative_path(self) -> None:
        agent = _staged_agent_text()
        self._assert_refused(self._block(agent, self.CORE_ENV_BLOCK), "CORE_ENV_FILE")
        self._assert_refused(CoreObfuscationProfileTrustTests()._snippet(agent), "AWG_OBFUSCATION_PROFILE")

    def test_ai_tunnel_refuses_a_relative_path(self) -> None:
        source = _core()
        helper = source[source.index("cat > /usr/local/bin/wins-core-ai-tunnel <<'EOF'\n"):]
        self._assert_refused(self._block(helper, self.CORE_ENV_BLOCK), "CORE_ENV_FILE")


# ---------------------------------------------------------------------------
# IA-CORE-14: the Xray binary is published atomically
# ---------------------------------------------------------------------------


class CoreXrayAtomicInstallTests(unittest.TestCase):
    def _run(self, install_rc: int) -> tuple[subprocess.CompletedProcess[str], Sandbox]:
        box = Sandbox()
        bindir = box.root / "usrlocalbin"
        bindir.mkdir()
        (bindir / "xray").write_text("old-binary\n", encoding="ascii")
        function = _function(_core(), "install_xray")
        cut = function.index("  wins_require_reviewed_xray_binary /usr/local/bin/xray || return 1")
        function = function[:cut] + "}\n"
        function = function.replace("/usr/local/bin", str(bindir)).replace("/usr/bin/sha256sum", "sha256sum_ok")
        script = PRELUDE + textwrap.dedent(f'''\
            XRAY_VERSION=26.9.30
            XRAY_LINUX_64_SHA256=0000000000000000000000000000000000000000000000000000000000000000
            wins_lock_deployed_xray_pin() {{ :; }}
            wins_reviewed_xray_binary_installed() {{ return 1; }}
            wins_require_linux_amd64_xray_preflight() {{ :; }}
            wins_require_reviewed_xray_binary() {{ :; }}
            sha256sum_ok() {{ cat >/dev/null; }}
            curl() {{ :; }}
            unzip() {{ printf 'new-binary\\n' > "${{@: -1}}/xray"; }}
            install() {{
              printf 'install %s\\n' "$*" >> "${{CALL_LOG}}"
              [[ {install_rc} == 0 ]] || return {install_rc}
              cp -- "${{@: -2:1}}" "${{@: -1}}"
            }}
            mv() {{ printf 'mv %s\\n' "$*" >> "${{CALL_LOG}}"; command mv "$@"; }}
            ''') + function + '\nif install_xray; then echo INSTALL_RC=0; else echo "INSTALL_RC=$?"; fi\n'
        return box.run(script), box

    def test_binary_is_written_to_a_temp_file_then_renamed(self) -> None:
        result, box = self._run(0)
        try:
            self.assertIn("INSTALL_RC=0", result.stdout, result.stderr)
            bindir = box.root / "usrlocalbin"
            installs = [c for c in box.calls() if c.startswith("install ")]
            self.assertEqual(1, len(installs))
            destination = installs[0].split()[-1]
            self.assertNotEqual(str(bindir / "xray"), destination)
            self.assertTrue(Path(destination).name.startswith(".xray."))
            self.assertEqual(str(bindir), str(Path(destination).parent))
            self.assertIn(f"mv -f -- {destination} {bindir / 'xray'}", box.calls())
            self.assertEqual("new-binary\n", (bindir / "xray").read_text(encoding="ascii"))
            self.assertEqual(["xray"], sorted(p.name for p in bindir.iterdir()))
        finally:
            box.close()

    def test_failed_copy_leaves_the_old_binary_and_no_temp(self) -> None:
        result, box = self._run(1)
        try:
            self.assertNotIn("INSTALL_RC=0", result.stdout)
            bindir = box.root / "usrlocalbin"
            self.assertEqual("old-binary\n", (bindir / "xray").read_text(encoding="ascii"))
            self.assertEqual(["xray"], sorted(p.name for p in bindir.iterdir()))
        finally:
            box.close()


# ---------------------------------------------------------------------------
# IA-CORE-15: the Ollama binary digest is enforced once pinned
# ---------------------------------------------------------------------------


class CoreOllamaBinaryDigestTests(unittest.TestCase):
    """IA-CORE-15 plus Turn 2 (Sol OI-COREB-2, N-2) and Turn 3 (Sol
    OI-COREB-T2-2, Seat C N-5): no pin, no AI setup, and an honest report of
    what is left running; a fresh install comes from the pinned release
    archive, never from upstream install.sh, and nothing downloaded runs
    before both digests match; IA-CORE-16 lands independently of the pin."""

    HELPERS = (
        "write_core_ai_tunnel_unit",
        "core_ai_tunnel_process_holds_core_secrets",
        "ensure_core_ai_tunnel_unit_effective",
        "harden_existing_core_ai_tunnel_unit",
        "report_unpinned_core_ai_runtime",
        "install_pinned_ollama_release",
    )

    def _run(
        self,
        pin: str,
        *,
        installed: bool = True,
        archive_pin: str = "",
        archive_members: dict[str, bytes | tuple[str, str]] | None = None,
        running: bool = False,
        existing_unit: str | None = None,
        loaded: dict[str, str] | None = None,
        reload_rc: int = 0,
        restart_rc: int = 0,
        restart_keeps_secrets: bool = False,
        fail_cp_a: bool = False,
        fail_bin_mv: bool = False,
        existing_lib: bool = False,
        umask0: bool = False,
        show_fail: tuple[str, ...] = (),
        show_fail_after_restart: tuple[str, ...] = (),
        restart_environ_missing: bool = False,
        max_bytes: str = "4294967296",
        fail: str = "",
        ollama_unit_is_dir: bool = False,
        existing_ollama_unit: str | None = None,
        runs: int = 1,
    ) -> tuple[subprocess.CompletedProcess[str], str, list[str], Path]:
        source = _core()
        body = _function(source, "install_local_ai_support")
        end = body.index("  # ADDED 2026-08-11")
        box = Sandbox()
        self.addCleanup(box.close)
        root = box.root
        prefix = root / "usrlocal"
        units = root / "units"
        (prefix / "bin").mkdir(parents=True)
        units.mkdir()
        if existing_unit is not None:
            (units / "wins-core-ai-tunnel.service").write_text(existing_unit, encoding="utf-8")
        if ollama_unit_is_dir:
            # A path that cannot be written as a file, even by root.
            (units / "ollama.service").mkdir()
        if existing_ollama_unit is not None:
            unit = units / "ollama.service"
            # Rooted like the installer text (the harness rewrites /usr/local/bin).
            unit.write_text(existing_ollama_unit.replace("/usr/local/bin", str(prefix / "bin")), encoding="utf-8")
            os.utime(unit, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
            info = unit.stat()
            (root / "unit_before").write_text(f"{info.st_ino} {info.st_mtime_ns}\n", encoding="ascii")
        if existing_lib:
            (prefix / "lib" / "ollama").mkdir(parents=True)
            (prefix / "lib" / "ollama" / "old-runner.so").write_text("old\n", encoding="ascii")
        # Turn 4: what systemd has loaded and what the tunnel process carries.
        state = {"need": "no", "envfiles": "", "pid": "0", "environ": ""}
        state.update(loaded or {})
        (root / "sd_need").write_text(state["need"] + "\n", encoding="ascii")
        (root / "sd_envfiles").write_text(state["envfiles"] + "\n", encoding="ascii")
        (root / "sd_pid").write_text(state["pid"] + "\n", encoding="ascii")
        # Follow-up Sol N-10: properties whose `systemctl show` query fails,
        # now and after the next restart.
        (root / "sd_showfail").write_text("".join(f"{n}\n" for n in show_fail), encoding="ascii")
        (root / "sd_showfail_after_restart").write_text(
            "".join(f"{n}\n" for n in show_fail_after_restart), encoding="ascii"
        )
        proc = root / "proc"
        if state["pid"] != "0" and state["environ"] is not None:
            (proc / state["pid"]).mkdir(parents=True)
            (proc / state["pid"] / "environ").write_bytes(state["environ"].replace("\n", "\0").encode())
        try:
            ollama_stub = '#!/usr/bin/env bash\nprintf "OLLAMA_EXEC %s\\n" "$*" >> "${CALL_LOG}"\necho "ollama version is 0.33.1"\n'
            if installed:
                box.stub("ollama", ollama_stub.split("\n", 1)[1])
                digest = hashlib.sha256((box.bin / "ollama").read_bytes()).hexdigest()
            else:
                digest = hashlib.sha256(ollama_stub.encode()).hexdigest()
            real_sha = shutil.which("sha256sum") or "/usr/bin/sha256sum"
            box.stub("sha256sum", f'printf "SHA256SUM %s\\n" "$*" >> "${{CALL_LOG}}"\nexec {real_sha} "$@"\n')
            active = "active" if running else "inactive"
            new_environ = "PATH=/usr/bin\\0CORE_TOKEN=leaked\\0" if restart_keeps_secrets else "PATH=/usr/bin\\0"
            box.stub(
                "systemctl",
                'printf "SYSTEMCTL %s\\n" "$*" >> "${CALL_LOG}"\n'
                f'if [[ "$1" == is-active ]]; then echo {active}; [[ {active} == active ]]; exit $?; fi\n'
                'if [[ "$1" == show ]]; then\n'
                '  if grep -qx -- "$3" "${WORK}/sd_showfail"; then exit 1; fi\n'
                '  case "$3" in\n'
                '    NeedDaemonReload) cat "${WORK}/sd_need" ;;\n'
                '    EnvironmentFiles) cat "${WORK}/sd_envfiles" ;;\n'
                '    MainPID) cat "${WORK}/sd_pid" ;;\n'
                '  esac\n'
                '  exit 0\n'
                'fi\n'
                f'if [[ "$1" == daemon-reload ]]; then [[ {reload_rc} == 0 ]] || exit {reload_rc}; echo no > "${{WORK}}/sd_need"; : > "${{WORK}}/sd_envfiles"; exit 0; fi\n'
                f'if [[ "$1" == restart ]]; then [[ {restart_rc} == 0 ]] || exit {restart_rc}; mkdir -p "${{WORK}}/proc/200"; '
                + ("" if restart_environ_missing else f'printf "{new_environ}" > "${{WORK}}/proc/200/environ"; ')
                + 'cat "${WORK}/sd_showfail_after_restart" >> "${WORK}/sd_showfail"; echo 200 > "${WORK}/sd_pid"; exit 0; fi\n'
                "exit 0\n",
            )
            # The release archive: a plain tar; zstd is shimmed to a copy.
            import io
            import tarfile
            members = archive_members if archive_members is not None else {
                "bin/ollama": ollama_stub.encode(),
                "lib/ollama/libggml-cuda.so": b"runner\n",
            }
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as tar:
                for name, data in members.items():
                    info = tarfile.TarInfo(name)
                    if isinstance(data, tuple) and data[0] == "fifo":
                        info.type = tarfile.FIFOTYPE
                        tar.addfile(info)
                        continue
                    if isinstance(data, tuple) and data[0] == "dir":
                        info.type = tarfile.DIRTYPE
                        info.mode = int(data[1], 8)
                        tar.addfile(info)
                        continue
                    if isinstance(data, tuple):
                        info.type = tarfile.SYMTYPE
                        info.linkname = data[1]
                        tar.addfile(info)
                        continue
                    info.size = len(data)
                    info.mode = 0o777 if name.endswith(".so") and umask0 else 0o755
                    tar.addfile(info, io.BytesIO(data))
            archive = root / "release.tar"
            archive.write_bytes(buffer.getvalue())
            archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            box.stub("zstd", '[[ "$1" == -dc ]] || exit 2\nshift\n[[ "$1" == -- ]] && shift\nexec cat -- "$1"\n')
            # Follow-up N-7(b): like curl, a download larger than
            # --max-filesize is refused with exit 63 and nothing is written.
            box.stub(
                "curl",
                'printf "CURL %s\\n" "$*" >> "${CALL_LOG}"\n'
                'out=""; prev=""; max=""\n'
                'for a in "$@"; do [[ "${prev}" == -o ]] && out="$a"; [[ "${prev}" == --max-filesize ]] && max="$a"; prev="$a"; done\n'
                f'if [[ -n "${{max}}" ]] && (( $(wc -c < "{archive}") > max )); then exit 63; fi\n'
                f'cp -- "{archive}" "${{out}}"\n',
            )
            helpers = "".join(_function(source, name) for name in self.HELPERS if f"\n{name}() {{" in source)
            text = (helpers + body[:end]).replace("/usr/local/bin", str(prefix / "bin"))
            text = text.replace("/usr/local/lib", str(prefix / "lib"))
            text = text.replace("/etc/systemd/system/", str(units) + "/")
            settings = textwrap.dedent("""\
                CORE_AI_ENABLED=1
                CORE_AI_HUB_SSH_HOST=hub.invalid
                CORE_AI_HUB_SSH_USER=root
                CORE_AI_TUNNEL_KEY=/root/.ssh/k
                CORE_AI_TUNNEL_KNOWN_HOSTS=/root/.ssh/kh
                CORE_AI_MODEL=hoppy:latest
                CORE_AI_OLLAMA_PINNED_VERSION=0.33.1
                CORE_AI_OLLAMA_ARCHIVE_MAX_BYTES="${STUB_MAX_BYTES}"
                valid_dns_hostname() { :; }
                valid_absolute_path() { :; }
                choose_core_ai_base_model() { printf 'gemma4:test'; }
                persist_core_ai_env() { :; }
                id() { return 1; }
                # Follow-up N-12 fault points, selected by STUB_FAIL.
                useradd() {
                  printf 'USERADD %s\\n' "$*" >> "${CALL_LOG}"
                  if [[ "${STUB_FAIL}" == useradd_once && ! -e "${WORK}/useradd_failed" ]]; then
                    : > "${WORK}/useradd_failed"; return 9
                  fi
                }
                find() {
                  case "${STUB_FAIL}:$*" in
                    "members:. -mindepth 1") return 1 ;;
                    links:*" -type l") return 1 ;;
                    special:*"! -type f"*) return 1 ;;
                  esac
                  command find "$@"
                }
                rm() {
                  if [[ "${STUB_FAIL}" == stale_rm && "$*" == *ollama.wins-new*ollama.wins-old* ]]; then return 1; fi
                  command rm "$@"
                }
                cat() {
                  if [[ "${STUB_FAIL}" == tunnel_unit_write ]]; then return 1; fi
                  # Round 2: the first unit write hits a full disk, either as
                  # RLIMIT_FSIZE 0 (the external cat is killed, 0 bytes), as a
                  # short write (40 bytes, then an error), or as a short write
                  # that still reports success (only the content check sees it).
                  if [[ "${STUB_FAIL}" == unit_write_* && ! -e "${WORK}/unit_write_failed" ]]; then
                    : > "${WORK}/unit_write_failed"
                    if [[ "${STUB_FAIL}" == unit_write_fsize ]]; then (ulimit -f 0; command cat "$@"); return; fi
                    command head -c 40
                    [[ "${STUB_FAIL}" == unit_write_short_silent ]]; return
                  fi
                  command cat "$@"
                }
                chown() { :; }
                cp() {
                  if [[ "${STUB_FAIL_CP_A:-0}" == 1 && "$1" == -a ]]; then return 23; fi
                  command cp "$@"
                }
                mv() {
                  if [[ "${STUB_FAIL_BIN_MV:-0}" == 1 && "${@: -1}" == */bin/ollama ]]; then return 1; fi
                  command mv "$@"
                }
                install() {
                  printf 'INSTALL %s\\n' "$*" >> "${CALL_LOG}"
                  if [[ "$1" == -d ]]; then
                    [[ "${STUB_FAIL}" != install_d || "$*" != *"-o root"* ]] || return 1
                    shift; while [[ "$1" == -* ]]; do shift 2; done; command mkdir -p "$@"; return
                  fi
                  [[ "${STUB_FAIL}" != bin_install ]] || return 1
                  cp -- "${@: -2:1}" "${@: -1}" && chmod 755 "${@: -1}"
                }
                """)
            script = (
                PRELUDE
                + ("umask 000\n" if umask0 else "")
                + settings
                + f'CORE_PROC_ROOT="{proc}"\n'
                + f'CORE_AI_OLLAMA_BINARY_SHA256="{pin.replace("DIGEST", digest)}"\n'
                + f'CORE_AI_OLLAMA_ARCHIVE_SHA256="{archive_pin.replace("ARCHIVE", archive_digest)}"\n'
                + text
                + "  printf 'REACHED_RUNTIME_SETUP\\n'\n}\n"
                + "if install_local_ai_support; then echo CHECK=pass; else echo CHECK=fail; fi\n"
                + "if install_local_ai_support; then echo RERUN=pass; else echo RERUN=fail; fi\n" * (runs - 1)
            )
            env = {
                "PATH": f"{box.bin}:{prefix / 'bin'}:{BASH_DIR}:/usr/bin:/bin:/usr/sbin:/sbin",
                "STUB_FAIL_CP_A": "1" if fail_cp_a else "0",
                "STUB_FAIL_BIN_MV": "1" if fail_bin_mv else "0",
                "STUB_FAIL": fail,
                "STUB_MAX_BYTES": max_bytes,
            }
            result = box.run(script, env)
            return result, digest, box.calls(), root
        finally:
            pass

    def test_matching_pin_is_checked_before_the_binary_runs(self) -> None:
        result, _, calls, _ = self._run("DIGEST")
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertIn("REACHED_RUNTIME_SETUP", result.stdout)
        first_exec = next(i for i, c in enumerate(calls) if c.startswith("OLLAMA_EXEC"))
        digest_check = next(i for i, c in enumerate(calls) if c.startswith("SHA256SUM") and c.endswith("/ollama"))
        self.assertLess(digest_check, first_exec)

    def test_mismatching_pin_is_refused_without_executing_the_binary(self) -> None:
        result, _, calls, _ = self._run("0" * 64)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_malformed_pin_is_refused(self) -> None:
        result, _, calls, _ = self._run("DIGESTx")
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_unpinned_runtime_is_refused_but_the_core_deploy_continues(self) -> None:
        result, _, calls, _ = self._run("")
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertNotIn("REACHED_RUNTIME_SETUP", result.stdout)
        self.assertIn("CORE_AI_OLLAMA_BINARY_SHA256 is not pinned", result.stderr)
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    # ---- Turn 3 ----

    def test_unpinned_host_with_a_running_runtime_says_so(self) -> None:
        result, _, calls, _ = self._run("", running=True)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertIn("UNVERIFIED Ollama runtime is still running", result.stderr)
        self.assertIn("ollama.service=active", result.stderr)
        self.assertNotIn("hub fallback", result.stderr)
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_unpinned_host_without_a_runtime_reports_the_fallback(self) -> None:
        result, _, _, _ = self._run("", running=False)
        self.assertIn("no local AI runtime is running", result.stderr)
        self.assertIn("hub fallback", result.stderr)

    OLD_UNIT = "[Unit]\n[Service]\nEnvironmentFile=/root/wins_core.env\nExecStart=/usr/local/bin/wins-core-ai-tunnel\n"
    AICORE_LOADED = {
        "need": "yes",
        "envfiles": "/root/wins_core.env (ignore_errors=no)",
        "pid": "100",
        "environ": "PATH=/usr/bin\nCORE_TOKEN=secret-token\nCORE_INGRESS_PRIVATE_KEY=secret-key\n",
    }

    def test_unpinned_host_still_gets_the_hardened_tunnel_unit(self) -> None:
        result, _, calls, after = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.AICORE_LOADED)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        unit = (after / "units" / "wins-core-ai-tunnel.service").read_text(encoding="utf-8")
        directives = [line for line in unit.splitlines() if not line.startswith("#")]
        self.assertFalse([d for d in directives if d.startswith("EnvironmentFile")])
        self.assertIn("SYSTEMCTL daemon-reload", calls)
        self.assertIn("SYSTEMCTL restart wins-core-ai-tunnel.service", calls)
        self.assertLess(calls.index("SYSTEMCTL daemon-reload"), calls.index("SYSTEMCTL restart wins-core-ai-tunnel.service"))
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    # ---- Turn 4 (Sol CLAUDE-N-5, N-8): state-based, retried, loud ----

    def test_failed_daemon_reload_fails_loudly(self) -> None:
        result, _, calls, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.AICORE_LOADED, reload_rc=1)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("daemon-reload failed", result.stderr)
        self.assertFalse([c for c in calls if c.startswith("SYSTEMCTL restart")])

    def test_failed_restart_fails_loudly(self) -> None:
        result, _, _, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.AICORE_LOADED, restart_rc=1)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not restart wins-core-ai-tunnel.service", result.stderr)

    def test_restart_that_keeps_the_secrets_fails_loudly(self) -> None:
        result, _, _, _ = self._run(
            "", running=True, existing_unit=self.OLD_UNIT, loaded=self.AICORE_LOADED, restart_keeps_secrets=True
        )
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("still carries the Core secrets", result.stderr)

    def test_rerun_retries_when_the_file_already_matches(self) -> None:
        # A previous run wrote the hardened file but its reload or restart
        # failed: the file now matches, the loaded state does not.
        first, _, _, after = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded={"need": "no"})
        hardened = (after / "units" / "wins-core-ai-tunnel.service").read_text(encoding="utf-8")
        for loaded, expect in (
            ({"need": "no", "envfiles": "/root/wins_core.env (ignore_errors=no)"}, "SYSTEMCTL daemon-reload"),
            ({"need": "yes"}, "SYSTEMCTL daemon-reload"),
            ({"need": "no", "pid": "100", "environ": "CORE_TOKEN=secret\n"}, "SYSTEMCTL restart wins-core-ai-tunnel.service"),
        ):
            result, _, calls, _ = self._run("", running=True, existing_unit=hardened, loaded=loaded)
            self.assertIn("CHECK=pass", result.stdout, result.stderr)
            self.assertIn(expect, calls, loaded)

    def test_effective_hardened_tunnel_is_left_alone(self) -> None:
        clean = {"need": "no", "envfiles": "", "pid": "100", "environ": "PATH=/usr/bin\n"}
        result, _, calls, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=clean)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertFalse([c for c in calls if c in ("SYSTEMCTL daemon-reload",) or c.startswith("SYSTEMCTL restart")])

    def test_unpinned_host_without_a_tunnel_unit_gets_none(self) -> None:
        _, _, calls, after = self._run("")
        self.assertFalse((after / "units" / "wins-core-ai-tunnel.service").exists())
        self.assertFalse([c for c in calls if "try-restart" in c])

    def test_fresh_install_without_an_archive_pin_skips_ai_and_never_downloads(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertNotIn("REACHED_RUNTIME_SETUP", result.stdout)
        self.assertIn("CORE_AI_OLLAMA_ARCHIVE_SHA256 is not pinned", result.stderr)
        self.assertFalse([c for c in calls if c.startswith("CURL")])
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())

    def test_fresh_install_uses_the_verified_release_archive(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE")
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertIn("REACHED_RUNTIME_SETUP", result.stdout)
        curl = [c for c in calls if c.startswith("CURL")]
        self.assertEqual(1, len(curl))
        self.assertIn("releases/download/v0.33.1/ollama-linux-amd64.tar.zst", curl[0])
        self.assertNotIn("install.sh", "\n".join(calls))
        self.assertTrue((after / "usrlocal" / "bin" / "ollama").is_file())
        self.assertTrue((after / "usrlocal" / "lib" / "ollama" / "libggml-cuda.so").is_file())
        self.assertIn("ExecStart=", (after / "units" / "ollama.service").read_text(encoding="utf-8"))
        first_exec = next(i for i, c in enumerate(calls) if c.startswith("OLLAMA_EXEC"))
        archive_check = next(i for i, c in enumerate(calls) if c.startswith("SHA256SUM -c"))
        self.assertLess(archive_check, first_exec)

    def test_fresh_install_refuses_a_mismatched_archive(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="0" * 64)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_fresh_install_refuses_a_binary_that_does_not_match_its_pin(self) -> None:
        result, _, calls, after = self._run("1" * 64, installed=False, archive_pin="ARCHIVE")
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_fresh_install_refuses_unexpected_archive_members(self) -> None:
        members = {
            "bin/ollama": b'#!/usr/bin/env bash\nprintf "OLLAMA_EXEC %s\\n" "$*" >> "${CALL_LOG}"\necho "ollama version is 0.33.1"\n',
            "etc/cron.d/extra": b"* * * * * root true\n",
        }
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", archive_members=members)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("unexpected entry", result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())

    # ---- Turn 4 (Seat C N-8, Sol N-7): every install mutation is checked ----

    def test_failed_runner_library_copy_fails_and_installs_nothing(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", fail_cp_a=True)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("could not be staged", result.stderr)
        self.assertNotIn("Installed Ollama", result.stdout)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        self.assertFalse((after / "usrlocal" / "lib" / "ollama").exists())
        self.assertFalse((after / "usrlocal" / "lib" / "ollama.wins-new").exists())
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_failed_copy_keeps_the_previous_runner_tree(self) -> None:
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", fail_cp_a=True, existing_lib=True)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertEqual("old\n", (after / "usrlocal" / "lib" / "ollama" / "old-runner.so").read_text(encoding="ascii"))

    def test_failed_binary_rename_restores_the_previous_runner_tree(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", fail_bin_mv=True, existing_lib=True)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        lib = after / "usrlocal" / "lib"
        self.assertEqual(["old-runner.so"], sorted(p.name for p in (lib / "ollama").iterdir()))
        self.assertEqual(["ollama"], sorted(p.name for p in lib.iterdir()))
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        self.assertEqual([], [p.name for p in (after / "usrlocal" / "bin").iterdir()])
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_successful_install_replaces_the_previous_runner_tree(self) -> None:
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", existing_lib=True)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        lib = after / "usrlocal" / "lib"
        self.assertEqual(["libggml-cuda.so"], sorted(p.name for p in (lib / "ollama").iterdir()))
        self.assertEqual(["ollama"], sorted(p.name for p in lib.iterdir()))

    def test_fresh_install_refuses_a_fifo(self) -> None:
        stub = b'#!/usr/bin/env bash\nprintf "OLLAMA_EXEC %s\\n" "$*" >> "${CALL_LOG}"\necho "ollama version is 0.33.1"\n'
        members = {"bin/ollama": stub, "lib/ollama/pipe": ("fifo", "")}
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", archive_members=members)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("device, FIFO or socket", result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())

    def test_installed_runner_tree_is_not_group_or_world_writable(self) -> None:
        stub = b'#!/usr/bin/env bash\nprintf "OLLAMA_EXEC %s\\n" "$*" >> "${CALL_LOG}"\necho "ollama version is 0.33.1"\n'
        members = {"bin/ollama": stub, "lib/ollama/cuda_v12": ("dir", "777"), "lib/ollama/cuda_v12/libx.so": b"x\n"}
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", archive_members=members, umask0=True)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        for path in [after / "usrlocal" / "lib" / "ollama", *(after / "usrlocal" / "lib" / "ollama").rglob("*")]:
            self.assertEqual(0, path.stat().st_mode & 0o022, f"{path} is group or world writable")

    def test_fresh_install_refuses_a_symlink_that_leaves_the_tree(self) -> None:
        stub = b'#!/usr/bin/env bash\nprintf "OLLAMA_EXEC %s\\n" "$*" >> "${CALL_LOG}"\necho "ollama version is 0.33.1"\n'
        for target in ("/etc/shadow", "../../../etc/shadow"):
            members = {"bin/ollama": stub, "lib/ollama/libcuda.so": ("symlink", target)}
            result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", archive_members=members)
            self.assertIn("CHECK=fail", result.stdout, result.stderr)
            self.assertIn("symlink that leaves its tree", result.stderr)
            self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())

    # ---- Follow-up Sol N-10 / CLAUDE-N-5 / SOL-N-8: a failed query or an
    # unreadable environment is never reported as IA-CORE-16 applied ----

    CLEAN = {"need": "no", "envfiles": "", "pid": "100", "environ": "PATH=/usr/bin\n"}

    def test_failed_environment_files_query_fails_closed(self) -> None:
        result, _, _, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.CLEAN,
                                    show_fail=("EnvironmentFiles",))
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not query systemd for wins-core-ai-tunnel.service", result.stderr)
        self.assertNotIn("IA-CORE-16: wins-core-ai-tunnel.service is loaded", result.stdout)

    def test_failed_main_pid_query_fails_closed(self) -> None:
        result, _, _, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.CLEAN,
                                    show_fail=("MainPID",))
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not query systemd for wins-core-ai-tunnel.service", result.stderr)

    def test_failed_need_daemon_reload_query_fails_closed(self) -> None:
        result, _, _, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.CLEAN,
                                    show_fail=("NeedDaemonReload",))
        self.assertIn("CHECK=fail", result.stdout, result.stderr)

    def test_failed_main_pid_query_after_the_restart_fails_closed(self) -> None:
        result, _, calls, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.AICORE_LOADED,
                                        show_fail_after_restart=("MainPID",))
        self.assertIn("SYSTEMCTL restart wins-core-ai-tunnel.service", calls)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not query systemd for wins-core-ai-tunnel.service", result.stderr)

    def test_unreadable_tunnel_environment_fails_closed(self) -> None:
        loaded = {"need": "no", "envfiles": "", "pid": "100", "environ": None}
        result, _, calls, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=loaded)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not read the environment of wins-core-ai-tunnel.service", result.stderr)
        self.assertFalse([c for c in calls if c.startswith("SYSTEMCTL restart")])

    def test_unreadable_environment_after_the_restart_fails_closed(self) -> None:
        result, _, calls, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.AICORE_LOADED,
                                        restart_environ_missing=True)
        self.assertIn("SYSTEMCTL restart wins-core-ai-tunnel.service", calls)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not read the environment of wins-core-ai-tunnel.service", result.stderr)

    def test_stopped_tunnel_with_a_clean_loaded_unit_passes(self) -> None:
        loaded = {"need": "no", "envfiles": "", "pid": "0"}
        result, _, calls, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=loaded)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertFalse([c for c in calls if c.startswith("SYSTEMCTL restart")])

    def test_failed_tunnel_unit_write_fails_the_unpinned_path(self) -> None:
        # Follow-up N-12 (X11).
        result, _, _, _ = self._run("", running=True, existing_unit=self.OLD_UNIT, loaded=self.CLEAN,
                                    fail="tunnel_unit_write")
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not write wins-core-ai-tunnel.service", result.stderr)

    # ---- Follow-up Sol N-11 / Claude N-10: user and unit before the swap ----

    def test_failed_useradd_installs_nothing(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", fail="useradd_once",
                                            existing_lib=True)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("Could not create the ollama service user", result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        lib = after / "usrlocal" / "lib"
        self.assertEqual(["ollama"], sorted(p.name for p in lib.iterdir()))
        self.assertEqual(["old-runner.so"], sorted(p.name for p in (lib / "ollama").iterdir()))
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_rerun_after_a_failed_useradd_provisions_again(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", fail="useradd_once", runs=2)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("RERUN=pass", result.stdout, result.stderr)
        self.assertEqual(2, len([c for c in calls if c.startswith("USERADD")]))
        self.assertTrue((after / "usrlocal" / "bin" / "ollama").is_file())
        self.assertIn("ExecStart=", (after / "units" / "ollama.service").read_text(encoding="utf-8"))

    def test_failed_ollama_unit_write_installs_nothing(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", ollama_unit_is_dir=True)
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("ollama.service is not a regular file; refusing to replace it", result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        self.assertFalse((after / "usrlocal" / "lib" / "ollama").exists())
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    # ---- Round 2: the unit is repaired when it is wrong, written atomically ----

    @staticmethod
    def _expected_ollama_unit(after: Path | None = None) -> str:
        body = _function(_core(), "install_pinned_ollama_release")
        text = re.search(r"^  local ollama_unit_text='(.*?)'$", body, re.M | re.S).group(1) + "\n"
        return text if after is None else text.replace("/usr/local/bin", str(after / "usrlocal" / "bin"))

    def _unit_and_leftovers(self, after: Path) -> tuple[str, list[str]]:
        units = after / "units"
        leftovers = sorted(p.name for p in units.iterdir() if p.name.startswith("ollama.service."))
        return (units / "ollama.service").read_text(encoding="utf-8"), leftovers

    def test_ollama_unit_text_is_a_complete_service(self) -> None:
        # The text is a shell string, not a heredoc, so
        # validate_deployment_scripts.py no longer sees it as a unit; this is
        # its [Unit]/[Service]/ExecStart check, plus the fields this unit needs.
        lines = self._expected_ollama_unit().splitlines()
        for needed in ("[Unit]", "[Service]", "[Install]", "ExecStart=/usr/local/bin/ollama serve",
                       "User=ollama", "Group=ollama", "WantedBy=default.target"):
            self.assertIn(needed, lines)

    def test_zero_byte_unit_is_rewritten(self) -> None:
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", existing_ollama_unit="")
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertEqual((self._expected_ollama_unit(after), []), self._unit_and_leftovers(after))
        self.assertEqual(0o644, (after / "units" / "ollama.service").stat().st_mode & 0o777)

    def test_truncated_unit_is_rewritten(self) -> None:
        truncated = self._expected_ollama_unit()[:40]
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", existing_ollama_unit=truncated)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertEqual((self._expected_ollama_unit(after), []), self._unit_and_leftovers(after))

    def test_correct_unit_is_left_untouched(self) -> None:
        expected = self._expected_ollama_unit()
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", existing_ollama_unit=expected)
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        self.assertEqual((self._expected_ollama_unit(after), []), self._unit_and_leftovers(after))
        info = (after / "units" / "ollama.service").stat()
        self.assertEqual((after / "unit_before").read_text(encoding="ascii"), f"{info.st_ino} {info.st_mtime_ns}\n")

    def test_rewritten_unit_is_a_new_file(self) -> None:
        # The rename is what makes the write atomic: a repaired unit is a new
        # inode, never the old file truncated and refilled in place.
        result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", existing_ollama_unit="")
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        before_ino = (after / "unit_before").read_text(encoding="ascii").split()[0]
        self.assertNotEqual(before_ino, str((after / "units" / "ollama.service").stat().st_ino))

    def test_failed_unit_write_keeps_the_previous_file_and_the_rerun_repairs_it(self) -> None:
        old = "[Unit]\nDescription=previous unit\n"
        for fault in ("unit_write_fsize", "unit_write_short", "unit_write_short_silent"):
            result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE",
                                                existing_ollama_unit=old, fail=fault)
            self.assertIn("CHECK=fail", result.stdout, f"{fault}: {result.stderr}")
            self.assertIn("Could not write", result.stderr, fault)
            self.assertEqual((old, []), self._unit_and_leftovers(after), fault)
            self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists(), fault)
            self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")], fault)
            result, _, _, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE",
                                            existing_ollama_unit=None, fail=fault, runs=2)
            self.assertIn("CHECK=fail", result.stdout, f"{fault}: {result.stderr}")
            self.assertIn("RERUN=pass", result.stdout, f"{fault}: {result.stderr}")
            self.assertEqual((self._expected_ollama_unit(after), []), self._unit_and_leftovers(after), fault)

    # ---- Follow-up N-12: the remaining unchecked steps (X6, X7, X10, find) ----

    def test_each_failed_install_step_installs_nothing(self) -> None:
        for fault, message in (
            ("install_d", "Could not prepare "),
            ("stale_rm", "Could not clear a stale Ollama staging tree"),
            ("bin_install", "The verified Ollama binary could not be staged"),
            ("members", "Could not list the extracted Ollama release archive"),
            ("links", "Could not list the symlinks in the extracted Ollama release archive"),
            ("special", "Could not check the extracted Ollama release archive for special files"),
        ):
            result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", fail=fault)
            self.assertIn("CHECK=fail", result.stdout, f"{fault}: {result.stderr}")
            self.assertIn(message, result.stderr, fault)
            self.assertEqual([], [p.name for p in (after / "usrlocal" / "bin").iterdir()], fault)
            self.assertFalse((after / "usrlocal" / "lib" / "ollama").exists(), fault)
            self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")], fault)

    # ---- Follow-up N-7(b): bounded download ----

    def test_download_is_bounded(self) -> None:
        result, _, calls, _ = self._run("DIGEST", installed=False, archive_pin="ARCHIVE")
        self.assertIn("CHECK=pass", result.stdout, result.stderr)
        curl = [c for c in calls if c.startswith("CURL")]
        self.assertEqual(1, len(curl))
        self.assertIn("--max-filesize 4294967296 ", curl[0])

    def test_oversized_archive_is_refused_as_an_integrity_failure(self) -> None:
        result, _, calls, after = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", max_bytes="100")
        self.assertIn("CHECK=fail", result.stdout, result.stderr)
        self.assertIn("larger than CORE_AI_OLLAMA_ARCHIVE_MAX_BYTES=100", result.stderr)
        self.assertFalse((after / "usrlocal" / "bin" / "ollama").exists())
        self.assertFalse([c for c in calls if c.startswith("OLLAMA_EXEC")])

    def test_invalid_download_bound_is_refused(self) -> None:
        for bound in ("0", "", "4G"):
            result, _, calls, _ = self._run("DIGEST", installed=False, archive_pin="ARCHIVE", max_bytes=bound)
            self.assertIn("CHECK=fail", result.stdout, bound)
            self.assertIn("not a positive byte count", result.stderr, bound)
            self.assertFalse([c for c in calls if c.startswith("CURL")], bound)

    # ---- Follow-up N-12 (X12): the pinned path propagates a failed check ----

    def _run_tail(self, show_fail: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        source = _core()
        body = _function(source, "install_local_ai_support")
        tail = body[body.index("  write_core_ai_tunnel_unit || return 1\n  systemctl daemon-reload\n"):]
        box = Sandbox()
        self.addCleanup(box.close)
        units = box.root / "units"
        units.mkdir()
        (box.root / "showfail").write_text(show_fail + "\n" if show_fail else "", encoding="ascii")
        box.stub(
            "systemctl",
            'printf "SYSTEMCTL %s\\n" "$*" >> "${CALL_LOG}"\n'
            'if [[ "$1" == show ]]; then\n'
            '  if grep -qx -- "$3" "${WORK}/showfail"; then exit 1; fi\n'
            '  case "$3" in NeedDaemonReload) echo no ;; MainPID) echo 0 ;; esac\n'
            'fi\n'
            "exit 0\n",
        )
        helpers = "".join(_function(source, name) for name in (
            "write_core_ai_tunnel_unit", "core_ai_tunnel_process_holds_core_secrets", "ensure_core_ai_tunnel_unit_effective"))
        text = (helpers + "tail_under_test() {\n" + tail).replace("/etc/systemd/system/", str(units) + "/")
        script = (
            PRELUDE
            + f'CORE_PROC_ROOT="{box.root / "proc"}"\n'
            + text
            + "if tail_under_test; then echo TAIL=pass; else echo TAIL=fail; fi\n"
        )
        return box.run(script), box.calls()

    def test_pinned_path_fails_when_the_tunnel_check_fails(self) -> None:
        result, calls = self._run_tail("")
        self.assertIn("TAIL=pass", result.stdout, result.stderr)
        self.assertIn("SYSTEMCTL enable --now wins-core-ai-tunnel.service", calls)
        result, _ = self._run_tail("MainPID")
        self.assertIn("TAIL=fail", result.stdout, result.stderr)
        self.assertIn("Could not query systemd for wins-core-ai-tunnel.service", result.stderr)


# ---------------------------------------------------------------------------
# IA-CORE-16: the AI tunnel unit does not export the Core env file
# ---------------------------------------------------------------------------


class CoreAiTunnelEnvironmentTests(unittest.TestCase):
    def test_unit_has_no_environment_file_and_script_sources_it_itself(self) -> None:
        units = [b.body for b in parse_heredocs(CORE) if "wins-core-ai-tunnel.service <<" in b.header]
        self.assertEqual(1, len(units))
        directives = [line for line in units[0].splitlines() if not line.lstrip().startswith("#")]
        self.assertFalse([d for d in directives if d.startswith(("EnvironmentFile", "Environment="))])
        scripts = [b.body for b in parse_heredocs(CORE) if "/usr/local/bin/wins-core-ai-tunnel <<" in b.header]
        self.assertEqual(1, len(scripts))
        self.assertIn('source "${CORE_ENV_FILE}"', scripts[0])
        self.assertIn('CORE_TOKEN="${CORE_TOKEN:?', scripts[0])


# ---------------------------------------------------------------------------
# IA-CORE-17: the previous sync timer stops for the whole rerun
# ---------------------------------------------------------------------------


class CoreRerunSyncTimerTests(unittest.TestCase):
    """IA-CORE-17 plus Turn 2 (Sol N-1, OI-COREB-5): the old timer stops, a
    stop failure refuses the rerun, and a pass already running is drained."""

    HOLDER = textwrap.dedent("""\
        python3 - "${CORE_SYNC_LOCK_FILE}" "@HOLD@" "${CALL_LOG}" "${WORK}/holder.ready" <<'PY' &
        import fcntl, sys, time
        lock = open(sys.argv[1], "a")
        fcntl.flock(lock, fcntl.LOCK_EX)
        open(sys.argv[4], "w").close()
        time.sleep(float(sys.argv[2]))
        with open(sys.argv[3], "a") as log:
            log.write("PASS_DONE\\n")
        PY
        holder_pid=$!
        while [[ ! -e "${WORK}/holder.ready" ]]; do sleep 0.05; done
        """)

    def _run(
        self,
        withdraw_ok: bool,
        *,
        unit: bool = True,
        disable_rc: int = 0,
        hold_seconds: float = 0.0,
        drain: str = "30",
        awg_image_rc: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        box = Sandbox()
        try:
            env_file = box.root / "wins_core.env"
            env_file.write_text("CORE_TOKEN=x\n", encoding="ascii")
            box.stub(
                "systemctl",
                'printf "systemctl %s\\n" "$*" >> "${CALL_LOG}"\n'
                'case "$1" in\n'
                f"  cat) exit {0 if unit else 1} ;;\n"
                f"  disable) exit {disable_rc} ;;\n"
                "esac\n"
                "exit 0\n",
            )
            response = (
                '{"ok":true,"runtime_ready":false,"promoted":false,"pending_promotion_id":"",'
                '"active_promotion_id":"","withdrawal_id":"0123456789abcdef0123456789abcdef"}'
                if withdraw_ok
                else '{"ok":false}'
            )
            holder = self.HOLDER.replace("@HOLD@", str(hold_seconds)) if hold_seconds else ""
            settings = (
                f'CORE_ENV_FILE="{env_file}"\n'
                "CORE_TOKEN=token-for-test\n"
                "CORE_BOOTSTRAP_TOKEN=\n"
                "CORE_ID=test-core\n"
                "HUB_API_BASE=https://hub.invalid\n"
                "CORE_INSTALLER_RERUN_ACTIVE=0\n"
                f'CORE_SYNC_LOCK_FILE="{box.root}/wins-core-sync.lock"\n'
                f"CORE_SYNC_RERUN_DRAIN_SECONDS={drain}\n"
                # FLEET1 TP-C2: the withdrawal writes its body with -o and
                # reads the HTTP status from -w '%{http_code}'.
                "curl() {\n"
                '  local out="" writeout=""\n'
                '  while (($#)); do case "$1" in -o) out="$2"; shift ;; -w) writeout="$2"; shift ;; esac; shift; done\n'
                f"  if [[ -n \"$out\" ]]; then printf '%s' '{response}' > \"$out\"; else printf '%s' '{response}'; fi\n"
                '  [[ -z "$writeout" ]] || printf 200\n'
                "}\n"
                "persist_core_installer_withdrawal_state() { printf 'PERSIST\\n' >> \"${CALL_LOG}\"; }\n"
                "install_core_failure_hold_firewall() { printf 'HOLD %s\\n' \"$*\" >> \"${CALL_LOG}\"; : > \"${WORK}/hold.engaged\"; }\n"
                # The producer's docker build needs FORWARD for its DNS, and the
                # hold drops FORWARD first (aicore 2026-10-18).
                "select_awg_image() {\n"
                '  printf "AWG_ENSURE\\n" >> "${CALL_LOG}"\n'
                '  if [[ -e "${WORK}/hold.engaged" ]]; then err "DNS: transient error"; return 1; fi\n'
                # An agent pass takes this lock first (acquire_core_sync_lock), then
                # registers and runs wins-core-build-monitor, which kills an unlatched
                # wins-build.slice. The build may run only while that pass cannot start.
                '  exec 7>>"${CORE_SYNC_LOCK_FILE}"\n'
                '  if flock -n 7; then printf "AGENT_COULD_RUN\\n" >> "${CALL_LOG}"; else printf "AGENT_BLOCKED\\n" >> "${CALL_LOG}"; fi\n'
                '  exec 7>&-\n'
                f"  return {awg_image_rc}\n"
                "}\n"
            )
            script = (
                PRELUDE
                + settings
                + _function(_core(), "begin_core_deployment_withdrawal_before_mutation")
                + holder
                + 'if begin_core_deployment_withdrawal_before_mutation; then echo BEGIN_RC=0; else echo "BEGIN_RC=$?"; fi\n'
                + 'echo WITHDRAW_DONE >> "${CALL_LOG}"\n'
                + 'exec 7>>"${CORE_SYNC_LOCK_FILE}"\n'
                + 'if flock -n 7; then echo LOCK_FREE_AFTER >> "${CALL_LOG}"; else echo LOCK_HELD_AFTER >> "${CALL_LOG}"; fi\n'
                + 'exec 7>&-\n'
                + ('kill "${holder_pid}" 2>/dev/null || true\nwait "${holder_pid}" 2>/dev/null || true\n' if holder else "")
            )
            return box.run(script), box.calls()
        finally:
            box.close()

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_timer_is_disabled_after_withdrawal_and_hold(self) -> None:
        result, calls = self._run(True)
        self.assertIn("BEGIN_RC=0", result.stdout, result.stderr)
        self.assertIn("systemctl disable --now wins-core-sync.timer", calls)
        hold = next(i for i, c in enumerate(calls) if c.startswith("HOLD installer-rerun-"))
        self.assertGreater(calls.index("systemctl disable --now wins-core-sync.timer"), hold)

    def test_refused_withdrawal_changes_nothing(self) -> None:
        result, calls = self._run(False)
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertFalse([c for c in calls if c.startswith("systemctl")])

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_timer_stop_failure_refuses_the_rerun(self) -> None:
        result, _ = self._run(True, disable_rc=1)
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertIn("refusing rerun mutation", result.stderr)

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_absent_timer_unit_is_not_an_error(self) -> None:
        result, calls = self._run(True, unit=False, disable_rc=1)
        self.assertIn("BEGIN_RC=0", result.stdout, result.stderr)
        self.assertFalse([c for c in calls if c.startswith("systemctl disable")])

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_rerun_waits_for_a_pass_that_is_already_running(self) -> None:
        result, calls = self._run(True, hold_seconds=1.5)
        self.assertIn("BEGIN_RC=0", result.stdout, result.stderr)
        self.assertLess(calls.index("PASS_DONE"), calls.index("WITHDRAW_DONE"))

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_a_pass_that_does_not_finish_refuses_the_rerun(self) -> None:
        result, calls = self._run(True, hold_seconds=6, drain="1")
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertIn("did not finish", result.stderr)
        self.assertNotIn("PASS_DONE", calls[: calls.index("WITHDRAW_DONE")])

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_pinned_awg_image_is_ensured_after_the_latch_and_before_the_hold(self) -> None:
        # aicore 2026-10-18: the hold drops FORWARD first, so a rerun that had to
        # build a new pinned image lost the build container's DNS. The ensure
        # runs after the hub withdrawal and its dark-state latch, before the hold.
        result, calls = self._run(True)
        self.assertIn("BEGIN_RC=0", result.stdout, result.stderr)
        self.assertEqual(1, calls.count("AWG_ENSURE"), calls)
        hold = next(i for i, c in enumerate(calls) if c.startswith("HOLD installer-rerun-"))
        self.assertLess(calls.index("PERSIST"), calls.index("AWG_ENSURE"))
        self.assertLess(calls.index("AWG_ENSURE"), hold)
        self.assertNotIn("DNS: transient error", result.stderr)
        # R25-F2: the old agent's 3 s timer is still on here, and a pass that ran
        # during the build would call wins-core-build-monitor and kill it.
        self.assertIn("AGENT_BLOCKED", calls)
        self.assertNotIn("AGENT_COULD_RUN", calls)
        self.assertIn("LOCK_FREE_AFTER", calls, "the lock is released once the image is ensured")

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_failed_image_ensure_refuses_the_rerun_before_the_hold(self) -> None:
        result, calls = self._run(True, awg_image_rc=1)
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertIn("could not be ensured before the rerun serving hold", result.stderr)
        self.assertEqual(["PERSIST", "AWG_ENSURE"], [c for c in calls if c in ("PERSIST", "AWG_ENSURE") or c.startswith(("HOLD", "systemctl"))])

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_failed_image_ensure_leaves_the_old_agent_running_and_its_lock_free(self) -> None:
        result, calls = self._run(True, awg_image_rc=1)
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertIn("AGENT_BLOCKED", calls)
        self.assertIn("LOCK_FREE_AFTER", calls, "the agent resumes at once")
        self.assertFalse([c for c in calls if c.startswith(("HOLD", "systemctl"))], calls)

    @unittest.skipUnless(shutil.which("jq"), "the withdrawal response is parsed with jq")
    def test_a_pass_that_does_not_finish_refuses_the_rerun_before_any_build(self) -> None:
        result, calls = self._run(True, hold_seconds=6, drain="1")
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertIn("did not finish", result.stderr)
        self.assertNotIn("AWG_ENSURE", calls)
        self.assertFalse([c for c in calls if c.startswith(("HOLD", "systemctl"))], calls)

    def test_the_mechanism_that_kills_an_unlatched_build(self) -> None:
        source = _core()
        state = [b.body for b in parse_heredocs(CORE) if "/usr/local/sbin/wins-core-build-state <<" in b.header]
        self.assertEqual(1, len(state))
        self.assertIn("check-running)\n    check_state 1 1\n", state[0], "the monitor requires the maintenance latch")
        persist = _function(source, "persist_core_advertised_state", -1)
        self.assertIn("/usr/local/sbin/wins-core-build-monitor", persist, "every agent pass that registers runs it")
        agent = _staged_agent_text()
        self.assertLess(agent.index("if acquire_core_sync_lock; then"), agent.index("trap 'rc=$?; trap - EXIT; if ((rc != 0))"),
                        "a pass that does not get the lock never registers")

    def test_refused_withdrawal_builds_nothing(self) -> None:
        result, calls = self._run(False)
        self.assertNotIn("BEGIN_RC=0", result.stdout)
        self.assertNotIn("AWG_ENSURE", calls)


class CoreDeploymentLockTests(unittest.TestCase):
    """Turn 4 (Sol N-9): a deploy takes the deployment lock before any
    mutation and keeps it until it exits; a second deploy or a firewall
    recovery cannot run beside it."""

    def _acquire(self, hold_lock: bool) -> tuple[subprocess.CompletedProcess[str], Sandbox]:
        box = Sandbox()
        lock = box.root / "deployment.lock"
        holder = None
        if hold_lock:
            holder = subprocess.Popen(
                [sys.executable, "-c",
                 "import fcntl,sys,time\nf=open(sys.argv[1],'a')\nfcntl.flock(f,fcntl.LOCK_EX)\nprint('locked',flush=True)\ntime.sleep(60)",
                 str(lock)],
                stdout=subprocess.PIPE, text=True,
            )
            self.assertEqual("locked", holder.stdout.readline().strip())
        # Follow-up OI-COREB-T2-3 / SOL-N-9: the path is a literal; tests root
        # it by rewriting the literal (as the relay tests do), and an
        # environment override pointing elsewhere must be ignored.
        decoy = box.root / "override.lock"
        function = _function(_core(), "acquire_core_deployment_lock")
        script = (
            PRELUDE
            + "CORE_DEPLOYMENT_LOCK_WAIT_SECONDS=1\n"
            + function.replace("/run/lock/wins-core-deployment.lock", str(lock))
            + 'if acquire_core_deployment_lock; then echo ACQUIRE_RC=0; else echo ACQUIRE_RC=1; fi\n'
            + f'lockprobe "{lock}"\n'
            + f'if [[ -e "{decoy}" ]]; then echo DECOY_OPENED; fi\n'
        )
        try:
            return box.run(script, {"CORE_DEPLOYMENT_LOCK_FILE": str(decoy)}), box
        finally:
            if holder is not None:
                holder.kill()
                holder.wait()
                holder.stdout.close()

    def test_second_deployment_is_refused_while_the_lock_is_held(self) -> None:
        result, box = self._acquire(hold_lock=True)
        try:
            self.assertIn("ACQUIRE_RC=1", result.stdout, result.stderr)
            self.assertIn("refusing to start a second one", result.stderr)
        finally:
            box.close()

    def test_deployment_keeps_the_lock_after_acquiring_it(self) -> None:
        result, box = self._acquire(hold_lock=False)
        try:
            self.assertIn("ACQUIRE_RC=0", result.stdout, result.stderr)
            self.assertIn("LOCK_HELD", result.stdout)
        finally:
            box.close()

    def test_lock_path_ignores_an_environment_override(self) -> None:
        result, box = self._acquire(hold_lock=False)
        try:
            self.assertIn("ACQUIRE_RC=0", result.stdout, result.stderr)
            self.assertIn("LOCK_HELD", result.stdout)
            self.assertNotIn("DECOY_OPENED", result.stdout)
        finally:
            box.close()

    def test_main_locks_after_preflight_and_before_any_mutation(self) -> None:
        main = _function(_core(), "main", -1)
        lock = main.index("\n  acquire_core_deployment_lock\n")
        self.assertLess(main.index("core_print_disk_encryption_guarantee\n    return 0"), lock)
        self.assertLess(lock, main.index("\n  begin_core_deployment_withdrawal_before_mutation\n"))
        self.assertLess(lock, main.index("\n  mark_core_role\n"))


class CoreAptPackagesTests(unittest.TestCase):
    """Follow-up N-7(d): the pinned Ollama archive is .tar.zst and
    install_pinned_ollama_release skips local AI without zstd, which is not
    in every Ubuntu 24.04 image, so apt_install installs it."""

    def test_apt_install_installs_zstd(self) -> None:
        body = _function(_core(), "apt_install")
        start = body.index('apt_retry "${APT_GET[@]}" install -y \\\n')
        end = body.index("\n  ensure_zram_kept_across_kernel_upgrades", start)
        packages = body[start:end].replace("\\\n", " ").split()
        self.assertIn("zstd", packages)
        self.assertIn('command -v zstd >/dev/null 2>&1 || return 2', _function(_core(), "install_pinned_ollama_release"))


class CoreManagementTunnelSshDependencyTests(unittest.TestCase):
    """Turn 4 (DP-HIGH port, Seat C): the hub's management connector must not
    carry a dependency through which apt's ssh restart would restart it."""

    UNIT = "wins-core-management-tunnel.service"

    def _run(self, *, unit_text: str | None, deps: str = "", show_rc: int = 0, reload_rc: int = 0,
             enabled: str = "1", props: dict[str, str] | None = None
             ) -> tuple[subprocess.CompletedProcess[str], list[str], Path]:
        box = Sandbox()
        self.addCleanup(box.close)
        unit_file = box.root / self.UNIT
        if unit_text is not None:
            unit_file.write_text(unit_text, encoding="utf-8")
        (box.root / "deps").write_text(deps, encoding="utf-8")
        # Follow-up N-12 (X15): with `props`, the stub answers like systemctl,
        # one line per requested -p property in order, so a property left out
        # of the query is not seen.
        for name, value in (props or {}).items():
            (box.root / f"prop_{name}").write_text(value + "\n", encoding="utf-8")
        show = (
            'while [[ $# -gt 0 ]]; do if [[ "$1" == -p ]]; then cat "${WORK}/prop_$2" 2>/dev/null || echo; shift; fi; shift; done'
            if props is not None else 'cat "${WORK}/deps"'
        )
        box.stub(
            "systemctl",
            'printf "SYSTEMCTL %s\\n" "$*" >> "${CALL_LOG}"\n'
            f'if [[ "$1" == daemon-reload ]]; then exit {reload_rc}; fi\n'
            f'if [[ "$1" == show ]]; then [[ {show_rc} == 0 ]] || exit {show_rc}; {show}; exit 0; fi\n'
            "exit 0\n",
        )
        script = (
            PRELUDE
            + f'CORE_MANAGEMENT_TUNNEL_UNIT_FILE="{unit_file}"\n'
            + f"CORE_MANAGEMENT_TUNNEL_ENABLED={enabled}\nCORE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT=1\n"
            + _function(_core(), "core_tunnel_unit_drop_ssh_requires")
            + 'if core_tunnel_unit_drop_ssh_requires; then echo GATE=pass; else echo GATE=refused; fi\n'
        )
        return box.run(script), box.calls(), unit_file

    OLD = "[Unit]\nAfter=network-online.target ssh.service\nWants=network-online.target\nRequires=ssh.service\n[Service]\nExecStart=/x\n"

    def test_rendered_unit_has_no_dependency_that_propagates_an_ssh_restart(self) -> None:
        body = _function(_core(), "configure_core_management_tunnel")
        unit = body[body.index('cat > "${service_file}" <<EOF\n'):]
        unit = unit[: unit.index("\nEOF\n")]
        for line in unit.splitlines():
            key, _, value = line.partition("=")
            if key in ("Requires", "Requisite", "BindsTo", "PartOf"):
                self.assertFalse({"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"} & set(value.split()), line)
        self.assertIn("Wants=ssh.service", unit.splitlines())

    def test_old_unit_is_rewritten_and_reloaded_without_a_restart(self) -> None:
        result, calls, unit_file = self._run(unit_text=self.OLD, deps="\n\n\nwins-core.slice\n")
        self.assertIn("GATE=pass", result.stdout, result.stderr)
        text = unit_file.read_text(encoding="utf-8")
        self.assertIn("Wants=ssh.service", text.splitlines())
        self.assertNotIn("Requires=ssh.service", text)
        self.assertIn("SYSTEMCTL daemon-reload", calls)
        self.assertFalse([c for c in calls if " restart" in c or c.startswith("SYSTEMCTL stop")])
        self.assertFalse(list(unit_file.parent.glob(self.UNIT + ".*")))

    def test_a_loaded_ssh_dependency_refuses_the_run(self) -> None:
        for deps in ("ssh.service\n\n\n\n", "\nsshd.service\n\n\n", "\n\nssh.socket\n\n", "\n\n\nnetwork.target sshd.socket\n"):
            result, calls, _ = self._run(unit_text=self.OLD.replace("Requires=ssh.service", "Wants=ssh.service"), deps=deps)
            self.assertIn("GATE=refused", result.stdout, deps)
            self.assertIn("still Requires=, Requisite=, BindsTo= or PartOf=", result.stderr)
            self.assertEqual(1, calls.count("SYSTEMCTL daemon-reload"))
            # Follow-up Claude N-11: this gate is unconditional, so a console
            # rerun meets the same refusal; the remedy says so.
            self.assertNotIn("or re-run from the provider console", result.stderr)
            self.assertIn("Remove that dependency and rerun", result.stderr)

    def test_each_queried_dependency_type_is_checked(self) -> None:
        hardened = self.OLD.replace("Requires=ssh.service", "Wants=ssh.service")
        for name in ("Requires", "Requisite", "BindsTo", "PartOf"):
            result, _, _ = self._run(unit_text=hardened, props={name: "sshd.service"})
            self.assertIn("GATE=refused", result.stdout, name)
        result, _, _ = self._run(unit_text=hardened, props={"Wants": "ssh.service"})
        self.assertIn("GATE=pass", result.stdout, result.stderr)

    def test_an_unrelated_loaded_dependency_passes(self) -> None:
        result, _, _ = self._run(unit_text=self.OLD, deps="sshguard.service\n\n\n\n")
        self.assertIn("GATE=pass", result.stdout, result.stderr)

    def test_an_unreadable_dependency_list_refuses(self) -> None:
        result, _, _ = self._run(unit_text=self.OLD, show_rc=1)
        self.assertIn("GATE=refused", result.stdout)
        self.assertIn("Could not read the loaded dependencies", result.stderr)

    def test_a_failed_reload_refuses_even_when_the_file_already_matches(self) -> None:
        hardened = self.OLD.replace("Requires=ssh.service", "Wants=ssh.service")
        result, calls, _ = self._run(unit_text=hardened, reload_rc=1)
        self.assertIn("GATE=refused", result.stdout)
        self.assertIn("SYSTEMCTL daemon-reload", calls)

    def test_no_installed_unit_or_disabled_tunnel_is_left_alone(self) -> None:
        for kwargs in ({"unit_text": None}, {"unit_text": self.OLD, "enabled": "0"}):
            result, calls, _ = self._run(**kwargs)
            self.assertIn("GATE=pass", result.stdout, result.stderr)
            self.assertEqual([], calls)

    def test_main_runs_the_gate_before_withdrawal_and_apt(self) -> None:
        main = _function(_core(), "main", -1)
        gate = main.index("\n  core_tunnel_unit_drop_ssh_requires\n")
        self.assertLess(main.index("\n  acquire_core_deployment_lock\n"), gate)
        self.assertLess(gate, main.index("\n  begin_core_deployment_withdrawal_before_mutation\n"))
        self.assertLess(gate, main.index("\n  apt_install\n"))


# ---------------------------------------------------------------------------
# IA-CORE-19: clock sanity for the time-bounded authority rules
# ---------------------------------------------------------------------------


class CoreClockSanityTests(unittest.TestCase):
    def _preflight(self, answers: str, **env: str) -> subprocess.CompletedProcess[str]:
        box = Sandbox()
        try:
            (box.root / "answers").write_text(answers, encoding="ascii")
            box.stub("timedatectl", '''\
                line="$(head -n1 "${WORK}/answers")"
                tail -n +2 "${WORK}/answers" > "${WORK}/answers.next" || true
                [[ -s "${WORK}/answers.next" ]] && mv -f "${WORK}/answers.next" "${WORK}/answers"
                printf '%s\\n' "${line}"
                ''')
            script = PRELUDE + _function(_core(), "require_core_clock_synchronized") + (
                'if require_core_clock_synchronized; then echo CLOCK=pass; else echo CLOCK=fail; fi\n'
            )
            return box.run(script, env)
        finally:
            box.close()

    def test_unsynchronized_clock_is_refused(self) -> None:
        result = self._preflight("no\n", CORE_CLOCK_SYNC_WAIT_SECONDS="0")
        self.assertIn("CLOCK=fail", result.stdout, result.stderr)
        self.assertIn("ALLOW_UNSYNCED_CLOCK=1", result.stderr)

    def test_override_warns_and_continues(self) -> None:
        result = self._preflight("no\n", CORE_CLOCK_SYNC_WAIT_SECONDS="0", ALLOW_UNSYNCED_CLOCK="1")
        self.assertIn("CLOCK=pass", result.stdout, result.stderr)
        self.assertIn("[WARN]", result.stderr)

    def test_synchronized_clock_passes_after_a_bounded_wait(self) -> None:
        result = self._preflight("no\nyes\n", CORE_CLOCK_SYNC_WAIT_SECONDS="3")
        self.assertIn("CLOCK=pass", result.stdout, result.stderr)
        self.assertNotIn("[WARN]", result.stderr)

    def test_preflight_runs_the_check_before_declaring_success(self) -> None:
        body = _function(_core(), "preflight_core")
        self.assertLess(body.index("require_core_clock_synchronized || exit 1"), body.index('log "Preflight passed:'))

    def _authority(self, expires_offset: int) -> subprocess.CompletedProcess[str]:
        agent = _staged_agent_text()
        start = agent.index("python3 -c '\nfrom datetime import datetime, timezone")
        code_start = agent.index("'", start) + 1
        code_end = agent.index("' \"${CORE_INGRESS_CIDR}\" \"${CORE_AUTHORITY_GRACE_SECONDS}\" > \"${rules}\"", code_start)
        code = agent[code_start:code_end]
        import time
        payload = {
            "ok": True,
            "assignments": [
                {"client_ip": "10.9.0.10", "authority_expires_at_epoch": int(time.time()) + expires_offset},
                {"client_ip": "10.9.0.11", "authority_expires_at_epoch": int(time.time()) + expires_offset},
            ],
        }
        return subprocess.run(
            # Grace 60 s, the floor of CORE_AUTHORITY_GRACE_SECONDS and the
            # bound this test was written against.
            [sys.executable, "-c", code, "10.9.0.0/16", "60"],
            input=json.dumps(payload),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )

    def test_agent_names_clock_skew_when_every_authority_is_expired(self) -> None:
        result = self._authority(-600)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("class=authority_clock_skew", result.stderr)
        self.assertNotIn("-j RETURN", result.stdout)

    def test_agent_is_quiet_when_authority_is_current(self) -> None:
        result = self._authority(600)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("authority_clock_skew", result.stderr)
        self.assertEqual(2, result.stdout.count("-j RETURN"))


if __name__ == "__main__":
    unittest.main()
