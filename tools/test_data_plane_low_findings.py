#!/usr/bin/env python3
"""Lane FX-DP-LOW: executable regressions for data-plane findings IA-DP-12
through IA-DP-18 (installer audit 2026-09-29).

Every test executes the installer's own code, extracted from
server/wins_data_plane_setup_ONETOUCH.sh (or from the file named by
WINS_FX_DP_LOW_INSTALLER, which is how the mutant runner points it at a
mutated copy). Host paths are rewritten into a private temp dir, and the only
stubs are tools the test host lacks or must not touch: iptables (a stateful
model, tools/fake_netfilter.py), systemctl, systemd-analyze, suricata, `ip`,
and a GNU `stat -c` shim that reports the test user as uid 0. No network, no
host firewall, no writes outside the temp dir.

  IA-DP-12  a rebuild keeps operator rules in DOCKER-USER and its one
            WINVPN-DOCKER jump (apply_firewall and wins-vpn-firewall)
  IA-DP-13  the nginx gates file and vhost are 0640, including over a 0644 file
  IA-DP-14  the recovery-guard unit carries the installer path the guard was
            armed with, so `check` passes after `confirm` from any path
  IA-DP-15  process env > node.env > defaults file
  IA-DP-16  no TCP companion port unless COMPANION_TCP_PORT is set
  IA-DP-17  an upgrade proceeds only over a stamped host and only when the new
            installer's sha256 is in a root-owned, not group/other-writable
            approval file
  IA-DP-18  the hub key helper is add-only: its one write to authorized_keys
            is a `>>` append of the current key under flock, stale hub keys
            are reported and never removed, operator lines are never touched

Usage: python3 tools/test_data_plane_low_findings.py [-v]
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tools"))
import _toolchain  # noqa: E402
import test_data_plane_management_rollback_guard as rollback_guard  # noqa: E402

INSTALLER = pathlib.Path(
    os.environ.get("WINS_FX_DP_LOW_INSTALLER", str(ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh"))
).resolve()
FAKE_NETFILTER = ROOT / "tools" / "fake_netfilter.py"
BASH = _toolchain.bash4()
PY = sys.executable
TIMEOUT = 120


def source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def heredoc(text: str, opener: str, terminator: str) -> str:
    start = text.index(opener)
    start = text.index("\n", start) + 1
    end = text.index("\n" + terminator + "\n", start)
    return text[start:end] + "\n"


HEREDOC_OPEN = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def function(text: str, name: str) -> str:
    """The top-level definition `name() {` through its closing `}` line,
    skipping heredoc bodies (a heredoc line reading `}` is not the end)."""
    m = re.search(r"^" + re.escape(name) + r"\(\) \{\n", text, re.M)
    if not m:
        raise AssertionError(f"{name}() not found in the installer")
    lines = text[m.start():].split("\n")
    out = [lines[0]]
    terminator = None
    strip_tabs = False
    for line in lines[1:]:
        out.append(line)
        if terminator is not None:
            if (line.lstrip("\t") if strip_tabs else line) == terminator:
                terminator = None
            continue
        if line == "}":
            return "\n".join(out) + "\n"
        opened = HEREDOC_OPEN.findall(line)
        if opened:
            dash, _, word = opened[-1]
            terminator, strip_tabs = word, dash == "-"
    raise AssertionError(f"{name}() has no closing brace")


def write_exec(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


STAT_SHIM = r'''#!/usr/bin/env python3
"""GNU `stat -c FORMAT PATH...` for the tests. The test user reads as uid 0
unless the path is listed in FAKE_NONROOT (colon-separated)."""
import os, stat, sys
args = sys.argv[1:]
if len(args) < 3 or args[0] != "-c":
    os.execv("/usr/bin/stat", ["/usr/bin/stat"] + args)
fmt, paths = args[1], args[2:]
nonroot = set(filter(None, os.environ.get("FAKE_NONROOT", "").split(":")))
rc = 0
for p in paths:
    try:
        st = os.lstat(p)
    except OSError as exc:
        print(f"stat: cannot stat '{p}': {exc.strerror}", file=sys.stderr)
        rc = 1
        continue
    uid = st.st_uid
    if uid == os.getuid() and p not in nonroot:
        uid = 0
    gid = 0 if st.st_gid == os.getgid() else st.st_gid
    out = fmt.replace("%u", str(uid)).replace("%g", str(gid))
    out = out.replace("%a", format(stat.S_IMODE(st.st_mode), "o"))
    out = out.replace("%h", str(st.st_nlink)).replace("%s", str(st.st_size))
    out = out.replace("%d", str(st.st_dev)).replace("%i", str(st.st_ino))
    out = out.replace("%z", str(st.st_ctime_ns))
    print(out)
sys.exit(rc)
'''


FLOCK_STUB = r'''#!/usr/bin/env python3
"""`flock [-w SECONDS] FD` and `flock -u FD` for hosts without util-linux
(macOS). The lock is taken on the inherited open file description, exactly as
flock(1) does, so it stays held by the caller after this process exits."""
import fcntl, sys, time
args = sys.argv[1:]
wait = None
if args[:1] == ["-w"]:
    wait = float(args[1]); args = args[2:]
if args[:1] == ["-u"]:
    fcntl.flock(int(args[1]), fcntl.LOCK_UN); sys.exit(0)
fd = int(args[0])
deadline = time.time() + (wait if wait is not None else 1e9)
while True:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sys.exit(0)
    except BlockingIOError:
        if time.time() >= deadline:
            sys.exit(1)
        time.sleep(0.05)
'''

class Sandbox:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="fx-dp-low-")
        self.root = pathlib.Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "ipt.json"
        self.iptlog = self.root / "ipt.log"
        for mode in ("iptables", "iptables-save", "iptables-restore"):
            write_exec(self.bin / mode, f'#!/bin/bash\nexec "{PY}" "{FAKE_NETFILTER}" {mode} "$@"\n')
        write_exec(self.bin / "stat", STAT_SHIM.replace("/usr/bin/env python3", PY, 1))
        write_exec(self.bin / "ip", '#!/bin/bash\n[[ "$*" == *"route show default"* ]] && echo "default via 192.0.2.1 dev eth0"\nexit 0\n')
        write_exec(
            self.bin / "systemctl",
            '#!/bin/bash\nprintf "%s\\n" "$*" >> "${FAKE_SYSTEMCTL_LOG:-/dev/null}"\n'
            '[[ "${1:-}" == show ]] && echo "ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml"\nexit 0\n',
        )
        write_exec(self.bin / "systemd-analyze", "#!/bin/bash\nexit 0\n")
        # S4: winn3_prepend_shared_functions chowns the rendered guard to root:root.
        write_exec(self.bin / "chown", "#!/bin/bash\nexit 0\n")
        write_exec(self.bin / "suricata", '#!/bin/bash\necho "NFQ support: yes"\n')
        write_exec(self.bin / "netfilter-persistent", "#!/bin/bash\nexit 0\n")
        write_exec(self.bin / "nginx", "#!/bin/bash\nexit 0\n")
        write_exec(
            self.bin / "install",
            '#!/bin/bash\nargs=()\nwhile (($#)); do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done\n'
            'exec /usr/bin/install "${args[@]}"\n',
        )
        if shutil.which("sha256sum") is None:
            write_exec(self.bin / "sha256sum", '#!/bin/bash\nexec shasum -a 256 "$@"\n')
        if shutil.which("flock") is None:
            write_exec(self.bin / "flock", FLOCK_STUB.replace("/usr/bin/env python3", PY, 1))

    def close(self) -> None:
        self._tmp.cleanup()

    def env(self, **extra: str) -> dict[str, str]:
        value = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(self.root),
            "FAKE_IPT_STATE": str(self.state),
            "FAKE_IPT_LOG": str(self.iptlog),
            "FAKE_SYSTEMCTL_LOG": str(self.root / "systemctl.log"),
            "LC_ALL": "C",
        }
        value.update(extra)
        return value

    def bash(self, program: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [BASH, "-c", program],
            env=env or self.env(),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )

    # ---- fake netfilter state -------------------------------------------
    def seed(self, extra_chains: dict[str, dict[str, list[str]]]) -> None:
        state = {
            "filter": {c: {"policy": "ACCEPT", "rules": []} for c in ("INPUT", "FORWARD", "OUTPUT")},
            "nat": {c: {"policy": "ACCEPT", "rules": []} for c in ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING")},
            "mangle": {c: {"policy": "ACCEPT", "rules": []} for c in ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING")},
        }
        for table, chains in extra_chains.items():
            for chain, rules in chains.items():
                state[table].setdefault(chain, {"policy": "-", "rules": []})["rules"] = list(rules)
        self.state.write_text(json.dumps(state), encoding="utf-8")

    def chain(self, table: str, chain: str) -> list[str] | None:
        state = json.loads(self.state.read_text(encoding="utf-8"))
        entry = state[table].get(chain)
        return None if entry is None else entry["rules"]


# ---------------------------------------------------------------------------
# IA-DP-12 and IA-DP-16: the edge rebuild (apply_firewall) against a stateful
# netfilter model, driven the same way test_deployment_runtime_configs.sh's
# test_public_ingress_admission_runtime drives it.
# ---------------------------------------------------------------------------

# S4: the installer prepends these shared functions to the edge script with
# declare -f; a harness that cuts the heredoc text out supplies the same names.
S4_SHARED_GUARD_FUNCTIONS = (
    "winn3_prepend_shared_functions", "wins_late_failure_hold",
    "wins_latch_rules_inspect", "wins_latch_rules_dominate",
)
S4_EDGE_SHARED_STUBS = (
    "wins_late_failure_hold() { return 1; }\n"
    "wins_latch_rules_dominate() { return 0; }\n"
    "winn3gw_render_chains() { return 0; }\n"
)

OPERATOR_RULE = "-s 198.51.100.7/32 -j DROP"


def run_apply_firewall(box: Sandbox, admission: str = "1", **extra: str) -> subprocess.CompletedProcess[str]:
    edge = heredoc(source(), "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
    probe = S4_EDGE_SHARED_STUBS + edge[: edge.index("\napply_rps\n") + 1]
    script = box.root / "edge-probe.sh"
    script.write_text(probe, encoding="utf-8")
    queue = box.root / "queue0"
    queue.write_text("0 0 0 0 0 0 0 0 0\n", encoding="utf-8")
    test_root = box.root / "node-root"
    test_root.mkdir(exist_ok=True)
    env = box.env(
        WINSVPN_TEST_ROOT=str(test_root),
        WINN3_GATEWAY_ENV_FILE=str(box.root / "missing-winn3.env"),
        NODE_ENV_FILE=str(box.root / "missing-node.env"),
        PUBLIC_VPN_INGRESS_ADMISSION_FILE=str(box.root / "missing-admission.env"),
        PUBLIC_VPN_INGRESS_ADMISSION=admission,
        INSTALL_DATA_IDS_IPS="1",
        DATA_NFQUEUE_PROC_PATH=str(queue),
        IPTABLES_BIN=str(box.bin / "iptables"),
        IPTABLES_SAVE_BIN=str(box.bin / "iptables-save"),
        IPTABLES_RESTORE_BIN=str(box.bin / "iptables-restore"),
        NODE_MANAGEMENT_TUNNEL_ENABLED="1",
        WG_PORT="9110",
        STEALTH_ORIGIN_PORT="80",
        STEALTH_TRANSPORTS="80:none,443:tls",
        ALLOW_PUBLIC_STEALTH_HTTP="1",
        CLOUDFLARE_ONLY_STEALTH="0",
        VPN_INTERFACES="awg0",
        WINS_FIREWALL_LOCK_HELD="1",
        WINS_NFQ_STATE_DIR=str(box.root / "nfq-state"),
        WINS_NFQ_MANIFEST=str(test_root / "etc/winsvpn/nfq-queue-rules"),
        **extra,
    )
    return box.bash(f'set -Eeuo pipefail\nsource "{script}"\napply_firewall\n', env)


class DockerUserTests(unittest.TestCase):
    """IA-DP-12."""

    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def assert_docker_user(self, rules: list[str] | None, operator: bool) -> None:
        self.assertIsNotNone(rules, "DOCKER-USER does not exist after the rebuild")
        self.assertEqual("-j WINVPN-DOCKER", rules[0] if rules else None, f"jump is not first: {rules}")
        self.assertEqual(1, rules.count("-j WINVPN-DOCKER"), f"jump count: {rules}")
        if operator:
            self.assertIn(OPERATOR_RULE, rules, f"operator rule was flushed: {rules}")

    def test_rerun_keeps_operator_rule_and_jump(self) -> None:
        # A rerun: the jump is already live, so ensure_jump stages nothing.
        self.box.seed({"filter": {
            "DOCKER-USER": ["-j WINVPN-DOCKER", OPERATOR_RULE, "-j RETURN"],
            "WINVPN-DOCKER": ["-j RETURN"],
        }})
        result = run_apply_firewall(self.box)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_docker_user(self.box.chain("filter", "DOCKER-USER"), operator=True)
        self.assertIn("-j RETURN", self.box.chain("filter", "DOCKER-USER"))
        docker = self.box.chain("filter", "WINVPN-DOCKER")
        self.assertEqual("-j RETURN", docker[-1])
        self.assertTrue(any("-i awg0 -o awg0 -j REJECT" in r for r in docker), docker)

    def test_first_install_with_operator_rule_inserts_jump_first(self) -> None:
        self.box.seed({"filter": {"DOCKER-USER": [OPERATOR_RULE, "-j RETURN"]}})
        result = run_apply_firewall(self.box)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_docker_user(self.box.chain("filter", "DOCKER-USER"), operator=True)

    def test_no_docker_user_chain_yet(self) -> None:
        self.box.seed({})
        result = run_apply_firewall(self.box)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_docker_user(self.box.chain("filter", "DOCKER-USER"), operator=False)

    def test_second_rebuild_is_idempotent(self) -> None:
        self.box.seed({"filter": {"DOCKER-USER": [OPERATOR_RULE]}})
        for _ in range(2):
            result = run_apply_firewall(self.box)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_docker_user(self.box.chain("filter", "DOCKER-USER"), operator=True)

    def test_runtime_vpn_firewall_transaction_keeps_docker_user(self) -> None:
        """The 30-minute wins-vpn-firewall transaction must not flush it either."""
        text = source()
        start = text.index("write_runtime_vpn_firewall_unit() {\n")
        stop = text.index('  install -m 600 -o root -g root "${transaction_tmp}" /root/wins-forward-nat.transaction', start)
        out = self.box.root / "wins-forward-nat.transaction"
        fn = text[start:stop] + f'  cp "${{transaction_tmp}}" "{out}"; rm -f -- "${{transaction_tmp}}"\n}}\n'
        prog = "\n".join([
            "set -uo pipefail",
            "log() { :; }; warn() { :; }; err() { :; }",
            fn,
            "WAN_IF=eth0 VPN_INTERFACES='awg0 amn0' write_runtime_vpn_firewall_unit",
        ])
        result = self.box.bash(prog)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.box.seed({"filter": {
            "DOCKER-USER": ["-j WINVPN-DOCKER", OPERATOR_RULE],
            "WINVPN-DOCKER": ["-j RETURN"],
            "WINVPN-FORWARD": [],
        }, "nat": {"WINVPN-NAT-POSTROUTING": []}, "mangle": {"WINVPN-MANGLE-FORWARD": []}})
        with open(out, encoding="utf-8") as txn:
            applied = subprocess.run(
                [str(self.box.bin / "iptables-restore"), "--wait", "10", "--noflush"],
                stdin=txn, env=self.box.env(), capture_output=True, text=True, timeout=TIMEOUT,
            )
        self.assertEqual(0, applied.returncode, applied.stderr)
        self.assertEqual(["-j WINVPN-DOCKER", OPERATOR_RULE], self.box.chain("filter", "DOCKER-USER"))


class CompanionPortTests(unittest.TestCase):
    """IA-DP-16."""

    def setUp(self) -> None:
        self.box = Sandbox()
        self.box.seed({})

    def tearDown(self) -> None:
        self.box.close()

    def input_rules(self) -> list[str]:
        return self.box.chain("filter", "WINVPN-INPUT") or []

    def test_default_opens_no_companion_port(self) -> None:
        result = run_apply_firewall(self.box)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        rules = self.input_rules()
        self.assertTrue(any("--dport 80 " in r for r in rules), rules)
        self.assertFalse([r for r in rules if "--dport 8000" in r], rules)

    def test_explicit_port_is_opened_and_queued(self) -> None:
        result = run_apply_firewall(self.box, COMPANION_TCP_PORT="8000")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        rules = self.input_rules()
        self.assertIn("-p tcp --dport 8000 -j ACCEPT", rules)
        self.assertTrue(any("--dport 8000" in r and "NFQUEUE" in r for r in rules), rules)

    def test_postflight_default_matches_generator(self) -> None:
        text = source()
        generator = re.findall(r'^COMPANION_TCP_PORT="\$\{COMPANION_TCP_PORT:-(\d+)\}"$', text, re.M)
        self.assertEqual(["0"], generator)
        post = re.findall(r'\$\{COMPANION_TCP_PORT:-(\d+)\}', text)
        self.assertEqual({"0"}, set(post), "postflight must resolve the generator's default")


# ---------------------------------------------------------------------------
# IA-DP-13
# ---------------------------------------------------------------------------

class NginxModeTests(unittest.TestCase):
    TOKEN = "fx-dp-low-probe-token-0123456789abcdef"

    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def run_gates(self, conf_d: pathlib.Path) -> subprocess.CompletedProcess[str]:
        text = source()
        prog = "\n".join([
            "set -Eeuo pipefail",
            "log() { :; }; warn() { :; }; err() { echo \"$*\" >&2; }",
            function(text, "validate_health_probe_token"),
            function(text, "write_nginx_edge_gates"),
            "umask 022",
            "write_nginx_edge_gates",
        ])
        return self.box.bash(prog, self.box.env(WINS_NGINX_HTTP_CONF_D=str(conf_d), NODE_HEALTH_PROBE_TOKEN=self.TOKEN))

    def test_gates_file_is_0640_fresh_and_over_0644(self) -> None:
        conf_d = self.box.root / "conf.d"
        for pre_existing in (False, True):
            with self.subTest(pre_existing=pre_existing):
                conf_d.mkdir(exist_ok=True)
                target = conf_d / "31-wins-edge-gates.conf"
                if pre_existing:
                    target.write_text("old\n", encoding="utf-8")
                    target.chmod(0o644)
                result = self.run_gates(conf_d)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(0o640, target.stat().st_mode & 0o777)
                self.assertIn(f'"{self.TOKEN}" 1;', target.read_text(encoding="utf-8"))
                self.assertEqual(["31-wins-edge-gates.conf"], sorted(p.name for p in conf_d.iterdir()))

    def test_vhost_is_0640_fresh_and_over_0644(self) -> None:
        text = source()
        nginx_root = self.box.root / "etc-nginx"
        body = function(text, "write_nginx").replace("/etc/nginx/", f"{nginx_root}/")
        (nginx_root / "sites-available").mkdir(parents=True)
        (nginx_root / "sites-enabled").mkdir()
        node_env = self.box.root / "node.env"
        node_env.write_text("", encoding="utf-8")
        vhost = nginx_root / "sites-available" / "wins-node.conf"
        for pre_existing in (False, True):
            with self.subTest(pre_existing=pre_existing):
                if pre_existing:
                    vhost.write_text("old\n", encoding="utf-8")
                    vhost.chmod(0o644)
                prog = "\n".join([
                    "set -Eeuo pipefail",
                    "ensure_node_origin_cert() { :; }; configure_nginx_capacity() { :; }; write_nginx_edge_gates() { :; }",
                    body,
                    "umask 022",
                    "write_nginx",
                ])
                env = self.box.env(
                    NODE_ENV_FILE=str(node_env), NODE_MAX_PEERS="100", REGIONAL_GATEWAY_ALIASES="",
                    STEALTH_TRANSPORTS="80:none,443:tls", STEALTH_HOST="s.example.test", NODE_HOST="n.example.test",
                    XRAY_PATH="/fx-dp-low-path", XRAY_INBOUND_PORT="10085",
                )
                result = self.box.bash(prog, env)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(0o640, vhost.stat().st_mode & 0o777)
                self.assertIn("location = /fx-dp-low-path {", vhost.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# IA-DP-14
# ---------------------------------------------------------------------------

class RecoveryGuardUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="fx-dp-low-guard-")
        self.root = pathlib.Path(self._tmp.name)
        rollback_guard.DATA = INSTALLER
        self.node = rollback_guard.FakeNode(self.root / "node", "8.8.8.8")
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()
        self._tmp.cleanup()

    def render_unit(self, installer_path: pathlib.Path) -> str:
        text = source()
        units = self.root / "units"
        units.mkdir(exist_ok=True)
        body = function(text, "write_node_ssh_recovery_guard")
        body = body.replace("/etc/systemd/system/", f"{units}/")
        body = body.replace(
            '"${guard_tmp}" /usr/local/sbin/wins-node-ssh-recovery-guard',
            f'"${{guard_tmp}}" "{self.root}/guard-installed"',
        )
        prog = "\n".join([
            "set -Eeuo pipefail",
            "log() { :; }; warn() { :; }; err() { echo \"$*\" >&2; }",
            function(text, "data_plane_installer_path"),
            *(function(text, name) for name in S4_SHARED_GUARD_FUNCTIONS),
            f'NODE_SSH_RECOVERY_STATE_DIR_DEFAULT="{self.node.state}"',
            body,
            "write_node_ssh_recovery_guard",
        ])
        result = self.box.bash(prog, self.box.env(WINS_DATA_PLANE_INSTALLER_PATH=str(installer_path)))
        self.assertEqual(0, result.returncode, result.stderr)
        return (units / "wins-node-ssh-recovery-guard.service").read_text(encoding="utf-8")

    @staticmethod
    def unit_environment(unit: str) -> dict[str, str]:
        env: dict[str, str] = {}
        for line in unit.splitlines():
            if line.startswith("Environment="):
                key, _, value = line[len("Environment="):].partition("=")
                env[key] = value
        return env

    def test_timer_check_passes_after_confirm_from_a_non_default_path(self) -> None:
        # The installer ran from somewhere other than /root (the node's
        # installer file lives in the temp tree), armed and was confirmed.
        self.assertEqual(0, self.node.run_guard("arm").returncode)
        confirmed = self.node.run_guard("confirm")
        self.assertEqual(0, confirmed.returncode, confirmed.stdout)
        unit = self.render_unit(self.node.installer)
        env = self.node.env()
        env.pop("WINS_NODE_SSH_RECOVERY_INSTALLER_PATH")
        env.pop("WINS_NODE_SSH_RECOVERY_STATE_DIR")
        env.update(self.unit_environment(unit))
        self.assertEqual(os.path.realpath(self.node.installer),
                         os.path.realpath(env.get("WINS_NODE_SSH_RECOVERY_INSTALLER_PATH", "<absent>")))
        self.assertEqual(str(self.node.state), env.get("WINS_NODE_SSH_RECOVERY_STATE_DIR"))
        tick = subprocess.run(["bash", str(self.node.guard), "check"], env=env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT)
        self.assertEqual(0, tick.returncode, tick.stdout)

    def test_unit_refuses_a_path_systemd_would_mangle(self) -> None:
        odd = self.root / "dir with space" / "installer.sh"
        odd.parent.mkdir()
        odd.write_text("#!/bin/bash\n", encoding="utf-8")
        text = source()
        units = self.root / "units2"
        units.mkdir()
        body = function(text, "write_node_ssh_recovery_guard").replace("/etc/systemd/system/", f"{units}/")
        body = body.replace('"${guard_tmp}" /usr/local/sbin/wins-node-ssh-recovery-guard', f'"${{guard_tmp}}" "{self.root}/g2"')
        prog = "\n".join([
            "log() { :; }; warn() { :; }; err() { echo \"$*\" >&2; }",
            function(text, "data_plane_installer_path"),
            *(function(text, name) for name in S4_SHARED_GUARD_FUNCTIONS),
            f'NODE_SSH_RECOVERY_STATE_DIR_DEFAULT="{self.node.state}"',
            body,
            "write_node_ssh_recovery_guard",
        ])
        result = self.box.bash(prog, self.box.env(WINS_DATA_PLANE_INSTALLER_PATH=str(odd)))
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((units / "wins-node-ssh-recovery-guard.service").exists())


# ---------------------------------------------------------------------------
# IA-DP-15
# ---------------------------------------------------------------------------

class DefaultsPrecedenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def resolve(self, node_env: str, defaults: str, env: dict[str, str], names: list[str]) -> dict[str, str]:
        text = source()
        node_file = self.box.root / "node.env"
        node_file.write_text(node_env, encoding="utf-8")
        node_file.chmod(0o600)
        defaults_dir = self.box.root / "defaults"
        defaults_dir.mkdir(exist_ok=True)
        defaults_dir.chmod(0o700)
        defaults_file = defaults_dir / "winsvpn-defaults.env"
        defaults_file.write_text(defaults, encoding="utf-8")
        defaults_file.chmod(0o600)
        capture = "# IA-DP-15: the NAMES in the process environment"
        start = text.index(capture) if capture in text else text.index("NODE_ENV_FILE=\"${NODE_ENV_FILE:-/root/node.env}\"\n")
        block_start = text.index('WINS_DEFAULTS_FILE="${WINS_DEFAULTS_FILE:-/root/winsvpn-defaults.env}"\n')
        block_end = text.index("\nfi\n", block_start) + 4
        # Everything from the process-environment capture (or, on the
        # snapshot, node.env loading) through the defaults block, in the
        # installer's order. The trusted-file gate's ancestor walk ends at the
        # real /, which a test tree cannot make root-owned, so it is stubbed.
        segment = text[start:block_end]
        segment = segment.replace(function(text, "wins_require_trusted_env_file"),
                                  "wins_require_trusted_env_file() { :; }\n")
        printer = "; ".join(f'printf "%s=%s|%s\\n" {n} "${{{n}-<unset>}}" "$(printenv {n} || echo -)"' for n in names)
        prog = "\n".join(["set -Eeuo pipefail", "find() { :; }", segment, printer])
        run_env = self.box.env(NODE_ENV_FILE=str(node_file), WINS_DEFAULTS_FILE=str(defaults_file), **env)
        result = self.box.bash(prog, run_env)
        self.assertEqual(0, result.returncode, result.stderr)
        out = {}
        for line in result.stdout.splitlines():
            key, _, value = line.partition("=")
            out[key] = value
        return out

    def test_singapore_replay_defaults_correct_node_env(self) -> None:
        """Seat C's replay: the reviewed Singapore defaults must override the
        provider hostname and slug that node.env persisted (as the launcher's
        merge model, node.env then defaults, assumes)."""
        got = self.resolve(
            node_env='NODE_HOST="host.provider.example"\nNODE_NAME="singapore-sg1"\n'
                     'NODE_MANAGEMENT_TUNNEL_ENABLED="0"\nSURICATA_NFQUEUE_FAIL_OPEN="0"\nNODE_SLUG="singapore-sg1"\n',
            defaults='NODE_HOST="203.0.113.9"\nNODE_NAME="Singapore"\n'
                     'NODE_MANAGEMENT_TUNNEL_ENABLED=1\nSURICATA_NFQUEUE_FAIL_OPEN=1\n',
            env={},
            names=["NODE_HOST", "NODE_NAME", "NODE_MANAGEMENT_TUNNEL_ENABLED", "SURICATA_NFQUEUE_FAIL_OPEN", "NODE_SLUG"],
        )
        self.assertEqual("203.0.113.9|203.0.113.9", got["NODE_HOST"])
        self.assertEqual("Singapore|Singapore", got["NODE_NAME"])
        self.assertEqual("1|1", got["NODE_MANAGEMENT_TUNNEL_ENABLED"])
        self.assertEqual("1|1", got["SURICATA_NFQUEUE_FAIL_OPEN"])
        self.assertEqual("singapore-sg1", got["NODE_SLUG"].split("|", 1)[0], "node.env keys the defaults do not name survive")

    def test_defaults_set_a_key_node_env_holds_empty(self) -> None:
        got = self.resolve(node_env='XRAY_SNI=""\n', defaults='XRAY_SNI="edge.example"\n', env={}, names=["XRAY_SNI"])
        self.assertEqual("edge.example|edge.example", got["XRAY_SNI"])

    def test_trusted_env_gate_refuses_a_relative_path(self) -> None:
        """R1-ARGON-5 (the control plane's Muse L03 F-5): with a relative
        WINS_DEFAULTS_FILE and a root-owned, not group/other-writable working
        directory the ancestor walk reached "." and looped forever, since
        dirname "." is "."."""
        gate = function(source(), "wins_require_trusted_env_file")
        work = self.box.root / "cwd"
        work.mkdir(mode=0o700)
        defaults = work / "winsvpn-defaults.env"
        defaults.write_text("NODE_NAME=Singapore\n", encoding="utf-8")
        defaults.chmod(0o600)
        for relative in ("winsvpn-defaults.env", "./winsvpn-defaults.env"):
            prog = "\n".join([
                "set -Eeuo pipefail",
                "find() { :; }",
                gate,
                f"cd {str(work)!r}",
                f'wins_require_trusted_env_file {relative!r} "WINS_DEFAULTS_FILE"',
                "echo accepted",
            ])
            try:
                result = subprocess.run([BASH, "-c", prog], env=self.box.env(), capture_output=True,
                                        text=True, timeout=10)
            except subprocess.TimeoutExpired:
                self.fail(f"the trusted-env gate never returned for the relative path {relative}")
            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertNotIn("accepted", result.stdout)
            self.assertIn("must be an absolute path", result.stderr)

    def test_node_env_and_secrets_gates_refuse_a_relative_path(self) -> None:
        """A1-ARGON-F3: for a name with no slash, `.` searches PATH before the
        working directory while stat and find look in the working directory,
        so node.env's and the secrets file's gates passed ./NAME and then ran
        the copy on PATH. Both refuse a relative path, like the defaults gate."""
        text = source()
        start = text.index('WINS_SECRETS_FILE="${WINS_SECRETS_FILE:-/root/winsvpn-secrets.env}"\nif [[ -f')
        secrets_block = text[start:text.index("\nfi\n", start) + 4]
        work = self.box.root / "cwd"
        work.mkdir(mode=0o700)
        (work / "probe.env").write_text("SRC=checked\n", encoding="utf-8")
        (work / "probe.env").chmod(0o600)
        (self.box.bin / "probe.env").write_text("SRC=planted\n", encoding="utf-8")
        (self.box.bin / "probe.env").chmod(0o666)
        for label, snippet, extra in (
            ("load_existing_node_env", function(text, "load_existing_node_env") + 'load_existing_node_env probe.env\n', {}),
            ("WINS_SECRETS_FILE", secrets_block, {"WINS_SECRETS_FILE": "probe.env"}),
        ):
            prog = "\n".join(["set -Eeuo pipefail", "find() { :; }", f"cd {str(work)!r}", snippet,
                              'printf "SRC=%s\\n" "${SRC:-none}"'])
            result = self.box.bash(prog, self.box.env(**extra))
            self.assertNotIn("SRC=planted", result.stdout, f"{label}: the gate checked ./probe.env and sourced the PATH copy")
            self.assertNotEqual(0, result.returncode, f"{label}: {result.stdout}")
            self.assertIn("must be an absolute path", result.stderr, label)

    def test_edge_and_gateway_firewall_gates_refuse_a_relative_path(self) -> None:
        """A1-ARGON-F3 twins: wins-edge-hardening (the public-ingress admission
        state and winn3_gateway_resolve) and the winn3-gateway-firewall boot
        helper stat ./NAME and then source NAME, which `source` looks up on
        PATH first. The copy on PATH must never run."""
        text = source()
        edge = heredoc(text, "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
        start = edge.index('PUBLIC_VPN_INGRESS_ADMISSION_FILE="${PUBLIC_VPN_INGRESS_ADMISSION_FILE:-')
        admission = edge[start:edge.index("\nfi\n", start) + 4]
        helper = self.box.root / "winn3-gateway-firewall"
        helper.write_text(heredoc(text, "cat <<'EOF' # the boot helper: /usr/local/sbin/winn3-gateway-firewall", "EOF"),
                          encoding="utf-8")
        work = self.box.root / "cwd"
        work.mkdir(mode=0o700)
        marker = self.box.root / "planted-ran"
        (work / "probe.env").write_text("WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n", encoding="utf-8")
        (work / "probe.env").chmod(0o600)
        (self.box.bin / "probe.env").write_text(
            f"WINN3_GATEWAY_LISTEN=0.0.0.0:4444\nprintf ran > {str(marker)!r}\n", encoding="utf-8")
        (self.box.bin / "probe.env").chmod(0o666)
        for label, snippet, variable in (
            ("PUBLIC_VPN_INGRESS_ADMISSION_FILE",
             "WINS_EDGE_QUEUES_ONLY=0\nPUBLIC_VPN_INGRESS_ADMISSION_REQUESTED_SET=\n" + admission,
             "PUBLIC_VPN_INGRESS_ADMISSION_FILE"),
            ("winn3_gateway_resolve", function(edge, "winn3_gateway_resolve") + "winn3_gateway_resolve || exit 1\n",
             "WINN3_GATEWAY_ENV_FILE"),
            ("winn3-gateway-firewall", f"exec {BASH} {str(helper)!r}\n", "WINN3_GATEWAY_ENV_FILE"),
        ):
            with self.subTest(label):
                marker.unlink(missing_ok=True)
                prog = "\n".join(["set -Eeuo pipefail", f"cd {str(work)!r}", snippet])
                result = self.box.bash(prog, self.box.env(**{variable: "probe.env"}))
                self.assertFalse(marker.exists(), f"{label}: the gate checked ./probe.env and sourced the PATH copy")
                self.assertNotEqual(0, result.returncode, f"{label}: {result.stdout}")
                self.assertIn("must be an absolute path", result.stderr, label)

    def test_environment_beats_defaults_and_node_env(self) -> None:
        got = self.resolve(
            node_env='NODE_HOST="host.provider.example"\nNODE_MAX_PEERS="4096"\n',
            defaults='NODE_HOST="203.0.113.9"\nNODE_MAX_PEERS=500\nNEW_ONLY_DEFAULT=first\n'
                     'NEW_ONLY_DEFAULT=second\nexport EXPORTED_DEFAULT=yes\n',
            env={"NODE_HOST": "198.51.100.20", "RUN_YABS": "0"},
            names=["NODE_HOST", "NODE_MAX_PEERS", "NEW_ONLY_DEFAULT", "EXPORTED_DEFAULT", "RUN_YABS"],
        )
        self.assertEqual("198.51.100.20|198.51.100.20", got["NODE_HOST"], "process env must beat both files")
        self.assertEqual("500|500", got["NODE_MAX_PEERS"], "defaults must beat node.env")
        self.assertEqual("second|second", got["NEW_ONLY_DEFAULT"], "last line in the defaults file wins")
        self.assertEqual("yes|yes", got["EXPORTED_DEFAULT"])
        self.assertEqual("0|0", got["RUN_YABS"])

    def test_environment_beats_defaults_without_node_env_key(self) -> None:
        got = self.resolve(node_env="", defaults="RUN_YABS=1\nNODE_MAX_PEERS=500\n",
                           env={"RUN_YABS": "0"}, names=["RUN_YABS", "NODE_MAX_PEERS"])
        self.assertEqual("0|0", got["RUN_YABS"])
        self.assertEqual("500|500", got["NODE_MAX_PEERS"])

    def test_empty_env_value_is_an_explicit_choice(self) -> None:
        got = self.resolve(node_env="", defaults="HUB_API_BASE=https://defaults.example.test\n",
                           env={"HUB_API_BASE": ""}, names=["HUB_API_BASE"])
        self.assertEqual("|", got["HUB_API_BASE"])


# ---------------------------------------------------------------------------
# IA-DP-17
# ---------------------------------------------------------------------------

class ApprovedInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = Sandbox()
        self.installer = self.box.root / "installer.sh"
        self.installer.write_text("#!/bin/bash\necho new release\n", encoding="utf-8")
        self.sha = hashlib.sha256(self.installer.read_bytes()).hexdigest()
        self.etc = self.box.root / "etc-winsvpn"
        self.etc.mkdir()
        self.etc.chmod(0o755)
        self.stamp = self.etc / ".data_plane_installer.sha256"
        self.approved = self.etc / "approved-installer-sha256"
        self.awg = self.box.root / "awg0.conf"
        self.awg.write_text("[Interface]\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.box.close()

    def guard(self, **extra: str) -> subprocess.CompletedProcess[str]:
        text = source()
        helpers = [function(text, "data_plane_installer_path"), function(text, "data_plane_already_installed")]
        if "data_plane_installer_approved() {" in text:
            helpers.append(function(text, "data_plane_installer_approved"))
            # The approval path is pinned in the installer; the test points
            # the pinning function at its own tree (after the real one).
            helpers.append(function(text, "data_plane_approved_installers_file"))
            helpers.append(f"data_plane_approved_installers_file() {{ printf '%s' '{self.approved}'; }}")
        prog = "\n".join([
            "set -Eeuo pipefail",
            'log() { echo "LOG $*"; }; warn() { echo "WARN $*"; }; err() { echo "ERR $*"; }',
            "docker() { return 1; }",
            *helpers,
            function(text, "guard_data_plane_code_drift"),
            "guard_data_plane_code_drift",
            "echo PROCEEDED",
        ])
        env = self.box.env(
            WINS_DATA_PLANE_INSTALLER_PATH=str(self.installer),
            DATA_PLANE_CODE_STAMP=str(self.stamp),
            AWG_CONF_PATH=str(self.awg),
            **extra,
        )
        return self.box.bash(prog, env)

    def write_stamp(self, sha: str) -> None:
        self.stamp.write_text(f"{sha}\ninstall_mode=main\n", encoding="utf-8")

    def approve(self, *lines: str, mode: int = 0o644) -> None:
        self.approved.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
        self.approved.chmod(mode)

    def assert_proceeds(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PROCEEDED", result.stdout)

    def assert_refuses(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("PROCEEDED", result.stdout)
        self.assertIn("REFUSING TO REINSTALL", result.stdout)

    def test_matching_stamp_still_proceeds(self) -> None:
        self.write_stamp(self.sha)
        self.assert_proceeds(self.guard())

    def test_listed_upgrade_over_a_stamped_host_proceeds(self) -> None:
        self.write_stamp("a" * 64)
        self.approve("# release 2026-09-29", "b" * 64, f"{self.sha}  wins_data_plane_setup_ONETOUCH.sh")
        result = self.guard()
        self.assert_proceeds(result)
        self.assertIn("approved release", result.stdout)

    def test_unlisted_upgrade_is_refused(self) -> None:
        self.write_stamp("a" * 64)
        self.approve("b" * 64)
        self.assert_refuses(self.guard())

    def test_approval_never_covers_an_unstamped_host(self) -> None:
        self.approve(self.sha)
        self.assert_refuses(self.guard())

    def test_unsafe_approval_files_are_ignored(self) -> None:
        self.write_stamp("a" * 64)
        cases = {
            "group-writable file": lambda: self.approve(self.sha, mode=0o664),
            "world-writable dir": lambda: (self.approve(self.sha), self.etc.chmod(0o777)),
            "non-root file": lambda: self.approve(self.sha),
        }
        for name, prepare in cases.items():
            with self.subTest(name):
                self.etc.chmod(0o755)
                prepare()
                extra = {"FAKE_NONROOT": str(self.approved)} if name == "non-root file" else {}
                self.assert_refuses(self.guard(**extra))
        with self.subTest("symlink"):
            self.etc.chmod(0o755)
            real = self.box.root / "elsewhere"
            real.write_text(self.sha + "\n", encoding="utf-8")
            self.approved.unlink()
            self.approved.symlink_to(real)
            self.assert_refuses(self.guard())

    def test_prefix_of_sha_is_not_approval(self) -> None:
        self.write_stamp("a" * 64)
        self.approve(self.sha[:63], self.sha + "0")
        self.assert_refuses(self.guard())

    def test_explicit_overwrite_still_works(self) -> None:
        self.assert_proceeds(self.guard(ALLOW_DATA_PLANE_OVERWRITE="1"))

    def test_approval_path_is_pinned(self) -> None:
        """Neither the environment nor a sourced node.env/defaults assignment
        can redirect the approval file."""
        text = source()
        pinned = function(text, "data_plane_approved_installers_file")
        prog = "\n".join([
            "set -Eeuo pipefail",
            f"DATA_PLANE_APPROVED_INSTALLERS_FILE='{self.approved}'",
            f"WINS_DATA_PLANE_APPROVED_INSTALLERS_FILE='{self.approved}'",
            pinned,
            "data_plane_approved_installers_file",
        ])
        result = self.box.bash(prog, self.box.env(DATA_PLANE_APPROVED_INSTALLERS_FILE=str(self.approved)))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("/etc/winsvpn/approved-installer-sha256", result.stdout)
        approved_fn = function(text, "data_plane_installer_approved")
        self.assertIn('file="$(data_plane_approved_installers_file)"', approved_fn)


# ---------------------------------------------------------------------------
# IA-DP-18: the add-only hub key helper (Fable ruling 2026-10-01)
# ---------------------------------------------------------------------------

HUB_OLD = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD root@hub"
HUB_NEW = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWNEWN root@hub"
HUB_THIRD = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITHIRDTHIRDTHIRDTHIRDTHIRDTHIRDTHIRDTHIRDTHI root@hub"
OPERATOR = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPERATOROPERATOROPERATOROPERATOROPERATOROPE ops@laptop"
OPERATOR_TWO = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPTWOOPTWOOPTWOOPTWOOPTWOOPTWOOPTWOOPTWOOPT ops@two"
MARKER = "wins-hub-managed"


def managed(key: str) -> str:
    """The one line the helper appends for a hub key: type, blob, marker."""
    return " ".join(key.split()[:2]) + " " + MARKER


# Commands the helper must never run. `install -d` (a directory) and
# `chmod 600 -- FILE` are the only other executables that name a path.
REMOVING_COMMANDS = ("mv", "cp", "rm", "perl", "python", "sed", "awk", "truncate", "tee", "dd", "ln",
                     "rename", "ed", "ex", "vi", "vim", "cat", "shred", "rsync", "sort", "uniq", "grep")

# Every line of the helper that mentions the authorized_keys path, exactly.
# The write is the `>>` line; the rest read, test or chmod it.
FILE_LINES = (
    'local file="$1" pubkey="$2" marker="wins-hub-managed" wanted dir lock_fd',
    'echo "wins-hub-key: flock (util-linux) is required and was not found; ${file} left unchanged" >&2',
    'dir="$(dirname "${file}")"',
    'echo "wins-hub-key: could not take the lock on ${dir}; ${file} left unchanged" >&2',
    """if [[ -f "${file}" && "$(stat -c '%a' "${file}" 2>/dev/null)" != 600 ]]; then""",
    'chmod 600 "${file}" || exit 1',
    'if [[ -e "${file}" ]]; then',
    'done < "${file}"',
    """if [[ -s "${file}" && -n "$(tail -c 1 -- "${file}" | tr -d '\\n')" ]]; then""",
    # F-DPLOW-1/2 follow-up: the stale report names the file (stderr only).
    '"${lineno}" "${file}" "${lineno}" "${ktype}" "${kend}" >&2',
    '"${nstale}" "${file}" >&2',
    """printf '%s\\n' "${pre}${wanted}" >> "${file}" || exit 1""",
)
APPEND_LINE = FILE_LINES[-1]


def code_lines(helper: str) -> list[str]:
    """The helper's lines without comments or leading space."""
    return [ln.strip() for ln in helper.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def write_redirections(helper: str) -> list[tuple[str, str]]:
    """(operator, target) for every output redirection in the helper's code.
    Dups (`>&2`, `2>&1`), single-quoted text and arithmetic are not
    redirections."""
    found = []
    for ln in code_lines(helper):
        ln = re.sub(r"'[^']*'", "''", ln)
        ln = re.sub(r"\(\([^\n]*?\)\)", "", ln)
        for m in re.finditer(r'(&>>|&>|>>|>\||<>|>)(?!&)\s*("(?:[^"\\]|\\.)*"|\S+)', ln):
            found.append((m.group(1), m.group(2)))
    return found


def stale_line(path: pathlib.Path, n: int, key: str) -> str:
    """The helper's per-line audit report (OI-DPLOW-4 follow-up)."""
    ktype, blob = key.split()[:2]
    end = f"ending ...{blob[-16:]}" if len(blob) > 32 else "<short>"
    return (f"wins-hub-key: stale hub key at line {n} stays authorized; remove it by hand (OI-DPLOW-4): "
            f"{path} line {n}, {ktype} key {end}\n")


def stale_summary(path: pathlib.Path, count: int) -> str:
    return (f"wins-hub-key: {count} stale hub key line(s) listed above stay authorized in {path}. "
            "Add-only never removes a hub key line, so every hub-managed line that is not the current hub key "
            "stays, including the HUB_SSH_PUBKEY the installer was given when it differs from the key the API serves "
            "(OI-DPLOW-14); the owner audit removes them by hand (OI-DPLOW-4)\n")


class HubKeyTests(unittest.TestCase):
    """Both writers: the installer's fetch_hub_pubkey and wins-node-register's
    sync_hub_ssh_pubkey, each executed with the hub response stubbed, and the
    helper itself (both byte-identical copies) driven directly."""

    COPIES = ("installer", "register")

    def setUp(self) -> None:
        self.box = Sandbox()
        self.ssh = self.box.root / "dot-ssh"
        self.keys = self.ssh / "authorized_keys"

    def tearDown(self) -> None:
        self.box.close()

    # ---- drivers ---------------------------------------------------------
    def run_installer_site(self, pubkey: str, **extra: str) -> subprocess.CompletedProcess[str]:
        text = source()
        helper = []
        if "wins_install_hub_authorized_key() {" in text[: text.index("fetch_hub_pubkey() {")]:
            helper.append(function(text, "wins_install_hub_authorized_key"))
        prog = "\n".join([
            "set -Eeuo pipefail",
            "log() { :; }; warn() { :; }; err() { echo \"$*\" >&2; }",
            f'SSH_DIR="{self.ssh}"', f'SSH_TRUST_FILE="{self.keys}"',
            *helper,
            function(text, "fetch_hub_pubkey"),
            "fetch_hub_pubkey",
        ])
        return self.box.bash(prog, self.box.env(HUB_SSH_PUBKEY=pubkey, **extra))

    def run_register_site(self, pubkey: str, **extra: str) -> subprocess.CompletedProcess[str]:
        register = heredoc(source(), "cat > /usr/local/bin/wins-node-register <<'EOF'", "EOF")
        helper = []
        if "wins_install_hub_authorized_key() {" in register:
            helper.append(function(register, "wins_install_hub_authorized_key"))
        body = function(register, "sync_hub_ssh_pubkey").replace("/root/.ssh", str(self.ssh))
        response = self.box.root / "pubkey.json"
        response.write_text(json.dumps({"pubkey": pubkey}), encoding="utf-8")
        write_exec(self.box.bin / "curl", f'#!/bin/bash\ncat > /dev/null\ncat "{response}"\n')
        prog = "\n".join([
            "set -Eeuo pipefail",
            *helper,
            body,
            "sync_hub_ssh_pubkey || true",
        ])
        env = self.box.env(NODE_TOKEN="t", NODE_SLUG="lab", HUB_API_BASE="https://hub.example.test", **extra)
        return self.box.bash(prog, env)

    def sites(self):
        return (("installer", self.run_installer_site), ("register", self.run_register_site))

    def helper_text(self, copy: str) -> str:
        text = source()
        if copy == "register":
            text = heredoc(text, "cat > /usr/local/bin/wins-node-register <<'EOF'", "EOF")
        return function(text, "wins_install_hub_authorized_key")

    def run_helper(self, copy: str, pubkey: str, helper: str | None = None, **env: str) -> subprocess.CompletedProcess[str]:
        helper = helper if helper is not None else self.helper_text(copy)
        prog = "\n".join(["set -Eeuo pipefail", helper,
                          f'wins_install_hub_authorized_key "{self.keys}" "{pubkey}"'])
        return self.box.bash(prog, self.box.env(**env))

    def fresh(self, content: str | bytes | None = OPERATOR + "\n", mode: int = 0o600) -> None:
        shutil.rmtree(self.ssh, ignore_errors=True)
        self.ssh.mkdir(mode=0o700)
        if content is not None:
            if isinstance(content, str):
                content = content.encode("utf-8")
            self.keys.write_bytes(content)
            self.keys.chmod(mode)

    def lines(self) -> list[str]:
        return self.keys.read_text(encoding="utf-8").splitlines()

    def authorized(self, key: str) -> bool:
        material = " ".join(key.split()[:2])
        return any(" ".join(line.split()[:2]) == material for line in self.lines())

    def state(self) -> tuple[bytes, int, int, int]:
        st = self.keys.stat()
        return (self.keys.read_bytes(), st.st_ino, st.st_mtime_ns, st.st_ctime_ns)

    def hold_lock(self) -> subprocess.Popen:
        """Another process holding flock on the directory, as flock(1) would."""
        holder = subprocess.Popen(
            [PY, "-c", "import fcntl,os,sys; f=os.open(sys.argv[1], os.O_RDONLY); fcntl.flock(f, fcntl.LOCK_EX); "
                       "print('held', flush=True); sys.stdin.read()", str(self.ssh)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual("held", holder.stdout.readline().strip())
        return holder

    @staticmethod
    def release(holder: subprocess.Popen) -> None:
        holder.stdin.close()
        holder.wait(timeout=30)

    # ---- add, exactly once, idempotent ------------------------------------
    def test_first_sync_appends_one_marked_line_and_keeps_the_rest(self) -> None:
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh(OPERATOR + "\n# operator comment\n")
                result = run(HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([OPERATOR, "# operator comment", managed(HUB_NEW)], self.lines())
                self.assertEqual(0o600, self.keys.stat().st_mode & 0o777)
                self.assertEqual("", result.stderr, "a clean first sync must report nothing")

    def test_a_missing_file_is_created_0600_with_the_one_line(self) -> None:
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh(None)
                self.assertEqual(0, run(HUB_NEW).returncode)
                self.assertEqual([managed(HUB_NEW)], self.lines())
                self.assertEqual(0o600, self.keys.stat().st_mode & 0o777)

    def test_second_sync_is_a_byte_inode_mtime_and_ctime_noop(self) -> None:
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh()
                self.assertEqual(0, run(HUB_NEW).returncode)
                before = self.state()
                result = run(HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(before, self.state(), "an unchanged hub key touched authorized_keys")
                self.assertEqual("", result.stderr)
                self.assertEqual(1, self.lines().count(managed(HUB_NEW)))

    def test_legacy_unmarked_copy_of_the_current_key_counts_as_present(self) -> None:
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh(OPERATOR + "\n" + HUB_NEW + "\n")
                before = self.state()
                result = run(HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(before, self.state(), "a present legacy copy must be left as it is")
                self.assertEqual("", result.stderr)

    def test_present_means_type_and_blob_of_a_non_comment_line(self) -> None:
        """A commented-out copy does not count; a copy with another comment
        does; a copy behind an options prefix does not (it is restricted, so
        it is not the unrestricted hub line)."""
        commented = "# " + HUB_NEW
        optioned = 'from="198.51.100.7" ' + HUB_NEW
        other_comment = " ".join(HUB_NEW.split()[:2]) + " somebody else's label"
        for name, run in self.sites():
            with self.subTest(site=name, case="comment"):
                self.fresh(commented + "\n")
                self.assertEqual(0, run(HUB_NEW).returncode)
                self.assertEqual([commented, managed(HUB_NEW)], self.lines())
            with self.subTest(site=name, case="other comment"):
                self.fresh(other_comment + "\n")
                before = self.state()
                self.assertEqual(0, run(HUB_NEW).returncode)
                self.assertEqual(before, self.state())
            with self.subTest(site=name, case="options prefix"):
                self.fresh(optioned + "\n")
                self.assertEqual(0, run(HUB_NEW).returncode)
                self.assertEqual([optioned, managed(HUB_NEW)], self.lines())

    def test_commented_out_lines_are_neither_present_nor_reported(self) -> None:
        """A hub line the operator commented out is inert: it does not make
        the current key present and it is not listed as a stale live key."""
        commented_old = "# " + managed(HUB_OLD)
        commented_new = "#" + managed(HUB_NEW)
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(OPERATOR + "\n" + commented_old + "\n" + commented_new + "\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("", result.stderr)
                self.assertEqual([OPERATOR, commented_old, commented_new, managed(HUB_NEW)], self.lines())

    def test_unterminated_last_line_is_not_glued(self) -> None:
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(OPERATOR)
                self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                self.assertEqual([OPERATOR, managed(HUB_NEW)], self.lines())

    def test_a_torn_tail_is_kept_apart_and_the_next_sync_adds_a_complete_line(self) -> None:
        """A power loss can leave a prefix of the line with no newline. sshd
        rejects it; the next sync appends a complete line after it."""
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                torn = managed(HUB_NEW)[:40]
                self.fresh(OPERATOR + "\n" + torn)
                self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                self.assertEqual([OPERATOR, torn, managed(HUB_NEW)], self.lines())
                before = self.state()
                self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                self.assertEqual(before, self.state())

    # ---- rotation: add, keep, report ---------------------------------------
    def test_rotation_appends_the_new_key_and_keeps_and_reports_the_old(self) -> None:
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh()
                self.assertEqual(0, self.run_helper(copy, HUB_OLD).returncode)
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([OPERATOR, managed(HUB_OLD), managed(HUB_NEW)], self.lines())
                self.assertEqual(stale_line(self.keys, 2, HUB_OLD) + stale_summary(self.keys, 1), result.stderr)
                self.assertNotIn(HUB_OLD.split()[1], result.stderr, "key material must not be printed")

    def test_stale_lines_are_reported_every_sync_and_never_removed(self) -> None:
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(OPERATOR + "\n" + managed(HUB_OLD) + "\n" + managed(HUB_NEW) + "\n"
                           + OPERATOR_TWO + "\n" + managed(HUB_THIRD) + "\n")
                before = self.state()
                for _ in range(3):
                    result = self.run_helper(copy, HUB_NEW)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(
                        stale_line(self.keys, 2, HUB_OLD) + stale_line(self.keys, 5, HUB_THIRD)
                        + stale_summary(self.keys, 2),
                        result.stderr)
                    self.assertEqual(before, self.state(), "a sync with only stale lines changed the file")

    def test_an_operator_line_carrying_the_marker_is_kept_and_reported(self) -> None:
        operator_marked = OPERATOR + " " + MARKER
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(operator_marked + "\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([operator_marked, managed(HUB_NEW)], self.lines())
                self.assertIn("stale hub key at line 1 stays authorized", result.stderr)
                again = self.run_helper(copy, HUB_NEW)
                self.assertEqual([operator_marked, managed(HUB_NEW)], self.lines())
                self.assertIn("stale hub key at line 1 stays authorized", again.stderr)

    def test_the_current_key_is_never_reported_as_stale(self) -> None:
        optioned_marked = 'command="/bin/true" ' + HUB_NEW + " " + MARKER
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(optioned_marked + "\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("", result.stderr)

    def test_install_time_key_that_differs_from_the_api_key_stays_and_is_reported(self) -> None:
        """OI-DPLOW-14: the installer's HUB_SSH_PUBKEY line and the key the
        API serves are both authorized; the non-current one is listed."""
        self.fresh()
        self.assertEqual(0, self.run_installer_site(HUB_OLD).returncode)
        result = self.run_register_site(HUB_NEW)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(self.authorized(HUB_OLD) and self.authorized(HUB_NEW))
        self.assertIn("WARN: 1 stale hub key line(s) stay authorized", result.stderr)

    def test_stale_report_names_file_line_type_and_key_end_for_the_audit(self) -> None:
        """OI-DPLOW-4 follow-up: each stale line is named by file, line, key
        type and the end of its key blob, so the owner can find it after
        earlier lines moved; the summary says why it is still there
        (OI-DPLOW-14). An operator line with options ahead of the key and the
        marker last is identified by its key, not by the options."""
        optioned = 'from="198.51.100.1" ' + HUB_OLD + " " + MARKER
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(OPERATOR + "\n" + optioned + "\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(stale_line(self.keys, 2, HUB_OLD) + stale_summary(self.keys, 1), result.stderr)
                self.assertIn(f"{self.keys} line 2, ssh-ed25519 key ending ...{HUB_OLD.split()[1][-16:]}", result.stderr)
                self.assertIn("the HUB_SSH_PUBKEY the installer was given when it differs from the key the API serves (OI-DPLOW-14)",
                              result.stderr)

    def test_only_the_key_blob_decides_staleness_not_comments_or_options(self) -> None:
        """Round 2 (Sol, FU-DPLOW4; seat C N-3): a stale key whose comment or
        option text holds the current blob, or a key-like word, is still
        reported, and it is named by its own key."""
        old_type, old_blob = HUB_OLD.split()[:2]
        new_blob = HUB_NEW.split()[1]
        comment_hides = f"{old_type} {old_blob} {new_blob} {MARKER}"
        option_hides = f'command="echo ssh-rsa {new_blob} \\"x y\\"" {old_type} {old_blob} note {MARKER}'
        current_after_options = f'from="198.51.100.9" {HUB_NEW} {MARKER}'
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(OPERATOR + "\n" + comment_hides + "\n" + option_hides + "\n" + current_after_options + "\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(stale_line(self.keys, 2, HUB_OLD) + stale_line(self.keys, 3, HUB_OLD)
                                 + stale_summary(self.keys, 2), result.stderr)

    def test_leading_blanks_are_skipped_as_sshd_does(self) -> None:
        """Round 3 (Sol, FU-DPLOW4): sshd skips leading spaces and tabs. A
        current key behind indented options is not stale; an indented stale
        key is reported by its own key; indented blank and comment lines are
        ignored."""
        old_type, old_blob = HUB_OLD.split()[:2]
        lines = [
            OPERATOR,
            f'  from="198.51.100.9" {HUB_NEW} {MARKER}',
            f'\t \tcommand="echo {HUB_NEW.split()[1]}" {old_type} {old_blob} {MARKER}',
            f"   {HUB_OLD} {MARKER}",
            "   ",
            f"\t# {old_type} {old_blob} {MARKER}",
        ]
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh("\n".join(lines) + "\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(stale_line(self.keys, 3, HUB_OLD) + stale_line(self.keys, 4, HUB_OLD)
                                 + stale_summary(self.keys, 2), result.stderr)

    def test_a_short_blob_is_never_printed(self) -> None:
        """Round 2 (Sol N-1): a blob of 32 characters or fewer prints as
        <short>; only longer blobs show their last 16 characters."""
        thirty = "AAAAC3NzaC1lZDI1NTE5AAAAIShort1"
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh(f"ssh-ed25519 AAAA {MARKER}\nssh-ed25519 {thirty} {MARKER}\n{MARKER}\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn(f"{self.keys} line 1, ssh-ed25519 key <short>\n", result.stderr)
                self.assertIn(f"{self.keys} line 2, ssh-ed25519 key <short>\n", result.stderr)
                self.assertIn(f"{self.keys} line 3, unparsed key <short>\n", result.stderr)
                self.assertNotIn(" AAAA", result.stderr)
                self.assertNotIn(thirty[-8:], result.stderr)
                self.assertNotIn("ending", result.stderr)
        # Round 3 (seat C E1): the boundary. 32 characters is short, 33 shows
        # its last 16.
        b32 = "AAAAC3NzaC1lZDI1NTE5AAAAIBound32"
        b33 = "AAAAC3NzaC1lZDI1NTE5AAAAIBound033"
        self.assertEqual((32, 33), (len(b32), len(b33)))
        for copy in self.COPIES:
            with self.subTest(copy=copy, boundary=True):
                self.fresh(f"ssh-ed25519 {b32} {MARKER}\nssh-ed25519 {b33} {MARKER}\n")
                result = self.run_helper(copy, HUB_NEW)
                self.assertIn(f"{self.keys} line 1, ssh-ed25519 key <short>\n", result.stderr)
                self.assertIn(f"{self.keys} line 2, ssh-ed25519 key ending ...{b33[-16:]}\n", result.stderr)

    def test_installer_site_lists_the_install_time_key_it_keeps(self) -> None:
        """OI-DPLOW-14: the install-time key that differs from the API key is
        named in the installer's own log when the other key is installed."""
        self.fresh()
        self.assertEqual(0, self.run_installer_site(HUB_OLD).returncode)
        result = self.run_installer_site(HUB_NEW)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(stale_line(self.keys, 2, HUB_OLD), result.stderr)
        self.assertIn("(OI-DPLOW-14)", result.stderr)

    def test_register_warn_lists_every_stale_line_for_the_owner_audit(self) -> None:
        """OI-DPLOW-4 follow-up: the register's one WARN per sync says why the
        lines stay (OI-DPLOW-14) and is followed by every per-line report, so
        the journal alone is enough for the owner audit."""
        self.fresh()
        self.assertEqual(0, self.run_register_site(HUB_OLD).returncode)
        self.assertEqual(0, self.run_register_site(HUB_NEW).returncode)
        result = self.run_register_site(HUB_THIRD)
        self.assertEqual(0, result.returncode, result.stderr)
        lines = result.stderr.splitlines()
        warns = [ln for ln in lines if "WARN" in ln]
        self.assertEqual(1, len(warns), result.stderr)
        self.assertIn("(OI-DPLOW-14)", warns[0])
        self.assertIn(stale_line(self.keys, 2, HUB_OLD).rstrip("\n"), lines)
        self.assertIn(stale_line(self.keys, 3, HUB_NEW).rstrip("\n"), lines)
        self.assertLess(lines.index(warns[0]), lines.index(stale_line(self.keys, 2, HUB_OLD).rstrip("\n")))

    def test_register_warns_once_per_sync_while_stale_lines_exist(self) -> None:
        self.fresh()
        self.assertEqual(0, self.run_register_site(HUB_OLD).returncode)
        clean = self.run_register_site(HUB_OLD)
        self.assertEqual("", clean.stderr, "no stale line, no warning")
        self.assertTrue(self.run_register_site(HUB_NEW).returncode == 0)
        for _ in range(2):
            result = self.run_register_site(HUB_NEW)
            self.assertEqual(0, result.returncode, result.stderr)
            warns = [ln for ln in result.stderr.splitlines() if "WARN" in ln]
            self.assertEqual(1, len(warns), result.stderr)
            self.assertIn("1 stale hub key line(s) stay authorized", warns[0])
            self.assertIn("OI-DPLOW-4", warns[0])
        self.assertEqual([OPERATOR, managed(HUB_OLD), managed(HUB_NEW)], self.lines())
        # two stale lines still make ONE warning, carrying the count
        result = self.run_register_site(HUB_THIRD)
        warns = [ln for ln in result.stderr.splitlines() if "WARN" in ln]
        self.assertEqual(1, len(warns), result.stderr)
        self.assertIn("2 stale hub key line(s) stay authorized", warns[0])
        self.assertEqual([OPERATOR, managed(HUB_OLD), managed(HUB_NEW), managed(HUB_THIRD)], self.lines())

    def test_register_warns_when_the_sync_cannot_run(self) -> None:
        self.fresh()
        holder = self.hold_lock()
        try:
            result = self.run_register_site(HUB_NEW, WINS_HUB_KEY_LOCK_WAIT="1")
        finally:
            self.release(holder)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("WARN: hub SSH key sync left", result.stderr)
        self.assertIn("unchanged", result.stderr)
        self.assertEqual([OPERATOR], self.lines())

    # ---- refusals leave the file alone --------------------------------------
    def test_multi_line_key_is_refused_without_touching_the_file(self) -> None:
        injected = HUB_NEW + "\n" + 'command="/bin/sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ attacker'
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh()
                run(injected)
                self.assertEqual([OPERATOR], self.lines())

    def test_malformed_single_line_key_is_refused(self) -> None:
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh()
                run("ssh-ed25519 not*base64 root@hub")
                self.assertEqual([OPERATOR], self.lines())

    def test_a_held_lock_blocks_the_writer(self) -> None:
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh()
                before = self.state()
                holder = self.hold_lock()
                try:
                    result = self.run_helper(copy, HUB_NEW, WINS_HUB_KEY_LOCK_WAIT="1")
                finally:
                    self.release(holder)
                self.assertEqual(1, result.returncode, "the helper wrote while another writer held the lock")
                self.assertIn("could not take the lock", result.stderr)
                self.assertEqual(before, self.state())
                self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                self.assertEqual([OPERATOR, managed(HUB_NEW)], self.lines())

    def test_missing_flock_exits_1_names_the_tool_and_changes_nothing(self) -> None:
        hide = 'command() { if [[ "${1:-}" == -v && "${2:-}" == flock ]]; then return 1; fi; builtin command "$@"; }'
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                self.fresh()
                before = self.state()
                prog = "\n".join([hide, "set -uo pipefail", self.helper_text(copy),
                                  f'wins_install_hub_authorized_key "{self.keys}" "{HUB_NEW}"; echo "rc=$?"'])
                result = self.box.bash(prog)
                self.assertIn("rc=1", result.stdout)
                self.assertIn("flock", result.stderr)
                self.assertEqual(before, self.state())

    # ---- operator lines are never touched -----------------------------------
    def operator_edit(self, how: str) -> None:
        """Another tool edits authorized_keys the way operators do."""
        if how == "sed -i":
            subprocess.run(["sed", "-i.orig", "-e", "s/ops@laptop/ops@laptop-renamed/", str(self.keys)], check=True)
            (self.ssh / "authorized_keys.orig").unlink()
        elif how == "rename":
            tmp = self.ssh / ".operator-edit"
            tmp.write_bytes(self.keys.read_bytes() + (OPERATOR_TWO + "\n").encode())
            tmp.chmod(0o600)
            os.replace(tmp, self.keys)
        elif how == "identical rewrite":
            data = self.keys.read_bytes()
            with open(self.keys, "r+b") as fh:
                fh.write(data)
                fh.truncate()
        elif how == "identical rewrite by rename":
            tmp = self.ssh / ".operator-edit"
            tmp.write_bytes(self.keys.read_bytes())
            tmp.chmod(0o600)
            os.replace(tmp, self.keys)
        else:
            raise AssertionError(how)

    def test_operator_lines_survive_every_kind_of_edit_between_syncs(self) -> None:
        for copy in self.COPIES:
            for how in ("sed -i", "rename", "identical rewrite", "identical rewrite by rename"):
                with self.subTest(copy=copy, edit=how):
                    self.fresh()
                    self.assertEqual(0, self.run_helper(copy, HUB_OLD).returncode)
                    self.operator_edit(how)
                    edited = self.keys.read_bytes()
                    result = self.run_helper(copy, HUB_NEW)
                    self.assertEqual(0, result.returncode, result.stderr)
                    after = self.keys.read_bytes()
                    self.assertTrue(after.startswith(edited), f"{how}: the helper changed bytes the operator left")
                    self.assertEqual((managed(HUB_NEW) + "\n").encode(), after[len(edited):])
                    for line in edited.decode().splitlines():
                        self.assertEqual(1, after.decode().splitlines().count(line), line)
                    self.assertTrue(self.authorized(HUB_OLD) and self.authorized(HUB_NEW))
                    # and an identical-bytes sync afterwards is a no-op again
                    before = self.state()
                    self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                    self.assertEqual(before, self.state())

    def test_symlinked_file_is_appended_through_the_link_and_stays_a_link(self) -> None:
        for name, run in self.sites():
            with self.subTest(site=name):
                self.fresh(None)
                target = self.box.root / f"managed-keys-{name}"
                target.write_text(OPERATOR + "\n", encoding="utf-8")
                target.chmod(0o600)
                self.keys.symlink_to(target)
                self.assertEqual(0, run(HUB_NEW).returncode)
                self.assertTrue(self.keys.is_symlink(), "the symlink was replaced by a regular file")
                self.assertEqual(str(target), os.readlink(self.keys))
                self.assertEqual([OPERATOR, managed(HUB_NEW)], target.read_text(encoding="utf-8").splitlines())
                before = target.read_bytes()
                self.assertEqual(0, run(HUB_NEW).returncode)
                self.assertEqual(before, target.read_bytes())

    def test_mode_is_normalised_to_0600_only_when_it_differs(self) -> None:
        for copy in self.COPIES:
            for mode in (0o644, 0o640, 0o400, 0o666):
                with self.subTest(copy=copy, mode=oct(mode)):
                    self.fresh(OPERATOR + "\n", mode=mode)
                    self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                    self.assertEqual(0o600, self.keys.stat().st_mode & 0o777)
                    self.assertEqual([OPERATOR, managed(HUB_NEW)], self.lines())

    # ---- crash safety --------------------------------------------------------
    def test_sigkill_before_or_after_the_append_leaves_old_or_old_plus_one_line(self) -> None:
        for copy in self.COPIES:
            helper = self.helper_text(copy)
            self.assertEqual(1, helper.count("    " + APPEND_LINE + "\n"), "append anchor")
            kill = '    kill -9 "${BASHPID}"\n'
            for when in ("before", "after"):
                with self.subTest(copy=copy, kill=when):
                    self.fresh()
                    old = self.keys.read_bytes()
                    anchor = "    " + APPEND_LINE + "\n"
                    mutated = helper.replace(anchor, kill + anchor if when == "before" else anchor + kill)
                    prog = "\n".join([mutated, f'wins_install_hub_authorized_key "{self.keys}" "{HUB_NEW}"; echo "rc=$?"'])
                    result = self.box.bash(prog)
                    self.assertIn("rc=137", result.stdout)
                    expect = old if when == "before" else old + (managed(HUB_NEW) + "\n").encode()
                    self.assertEqual(expect, self.keys.read_bytes())
                    # the next sync converges on exactly one line, never two
                    self.assertEqual(0, self.run_helper(copy, HUB_NEW).returncode)
                    self.assertEqual(old + (managed(HUB_NEW) + "\n").encode(), self.keys.read_bytes())

    # ---- concurrency ---------------------------------------------------------
    def test_concurrent_syncs_never_duplicate_or_lose_lines(self) -> None:
        helper = self.helper_text("installer")
        keys = (HUB_OLD, HUB_NEW, HUB_THIRD)
        appended = [f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP{j:060d} op{j}" for j in range(60)]
        self.fresh()
        arr = " ".join(f'"{k}"' for k in keys)
        prog = "\n".join([
            "set -uo pipefail", helper,
            f'K="{self.keys}"', f"KEYS=({arr})",
            'worker() { local i; for ((i = 0; i < 9; i++)); do '
            'wins_install_hub_authorized_key "$K" "${KEYS[$(( (i + $1) % 3 ))]}" 2>/dev/null; done; }',
            'appender() { local j; for ((j = 0; j < 60; j++)); do '
            'printf "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP%060d op%d\\n" "$j" "$j" >> "$K"; done; }',
            'for w in 0 1 2 3 4 5; do worker "$w" & done',
            "appender &", "wait",
        ])
        result = self.box.bash(prog)
        self.assertEqual(0, result.returncode, result.stderr)
        lines = self.lines()
        for key in keys:
            self.assertEqual(1, lines.count(managed(key)), f"hub line count for {key.split()[1][:20]}: {lines}")
        for line in [OPERATOR, *appended]:
            self.assertEqual(1, lines.count(line), f"operator line lost or duplicated: {line[-8:]}")
        self.assertEqual(1 + 60 + 3, len(lines))

    # ---- the write invariant: the only write is one `>>` append -------------
    def test_helper_copies_are_byte_identical(self) -> None:
        self.assertEqual(self.helper_text("installer"), self.helper_text("register"))

    def test_static_the_only_write_to_authorized_keys_is_one_append(self) -> None:
        for copy in self.COPIES:
            helper = self.helper_text(copy)
            with self.subTest(copy=copy):
                code = code_lines(helper)
                redirections = write_redirections(helper)
                to_file = [(op, tgt) for op, tgt in redirections if "file" in tgt or tgt in ("$1", '"$1"')]
                self.assertEqual([(">>", '"${file}"')], to_file)
                others = [(op, tgt) for op, tgt in redirections if (op, tgt) not in to_file]
                for op, tgt in others:
                    self.assertTrue(op == ">" and re.match(r"/dev/null\)?\"?$", tgt) is not None, f"unexpected redirection {op} {tgt}")
                self.assertEqual(1, sum(1 for ln in code if ">> " in ln or ln.endswith(">>")))
                self.assertNotIn("<>", "\n".join(code))
                # every line that names the path is on the exact allow list
                for ln in code:
                    if "${file}" in ln or '"$1"' in ln or "$@" in ln or "$*" in ln:
                        self.assertIn(ln, FILE_LINES, f"unreviewed use of the authorized_keys path: {ln}")
                # no other name can alias it
                self.assertEqual(1, sum(1 for ln in code if re.search(r"\bfile=", ln)))
                self.assertEqual(1, sum(1 for ln in code if '"$1"' in ln))
                # nothing that rewrites, replaces or removes a file is run
                joined = "\n".join(re.sub(r"'[^']*'", "''", re.sub(r'"[^"]*"', '""', ln)) for ln in code)
                for word in REMOVING_COMMANDS:
                    self.assertIsNone(re.search(rf"(^|[\s;|&(`]){word}(\s|$)", joined), f"{word} in the helper")
                self.assertNotIn("sed -i", joined)
                self.assertNotIn("eval", joined)
                for ln in code:
                    if re.search(r"\binstall\b", ln):
                        self.assertEqual('install -d -m 700 "${dir}" || exit 1', ln)
                    if re.search(r"\bchmod\b", ln):
                        self.assertEqual('chmod 600 "${file}" || exit 1', ln)
                    if re.search(r"\bexec\b", ln):
                        self.assertEqual('exec {lock_fd}< "${dir}" || exit 1', ln)

    def test_the_helper_no_longer_needs_perl_or_keeps_any_record(self) -> None:
        text = source()
        for copy in self.COPIES:
            helper = self.helper_text(copy)
            for gone in ("perl", "receipt", "ctime", "pending", "intent", "record", "revoke", ".wins-hub-managed-key"):
                self.assertNotIn(gone, "\n".join(code_lines(helper)), f"{gone} survives in the {copy} helper")
        self.assertNotIn(".wins-hub-managed-key", text)
        self.assertNotIn("WINS_HUB_KEY_RECORD", text)

    def test_dynamic_no_rewriting_command_runs_and_every_sync_only_appends(self) -> None:
        """Stubs for every command that could rewrite, rename, truncate or
        remove a file log their argv; the file's inode never changes and each
        sync's bytes are the previous bytes plus nothing or exactly one line."""
        log = self.box.root / "audit.log"
        audit_dir = self.box.root / "audit-bin"
        audit_dir.mkdir()
        outer = self.box.env()["PATH"]
        for name in (*REMOVING_COMMANDS, "install", "chmod", "mktemp", "touch", "mkdir", "rmdir", "mkfifo"):
            real = shutil.which(name, path=outer)
            if real is None:
                continue
            write_exec(audit_dir / name, f'#!/bin/bash\nprintf "%s" "{name}" >> "{log}"; '
                                         f'for a in "$@"; do printf " [%s]" "$a" >> "{log}"; done; echo >> "{log}"\n'
                                         f'exec "{real}" "$@"\n')
        env = self.box.env()
        env["PATH"] = f"{audit_dir}:{env['PATH']}"
        for copy in self.COPIES:
            with self.subTest(copy=copy):
                log.write_text("", encoding="utf-8")
                self.fresh(OPERATOR + "\n", mode=0o644)
                inode = self.keys.stat().st_ino
                previous = self.keys.read_bytes()
                for key in (HUB_OLD, HUB_OLD, HUB_NEW, HUB_NEW, HUB_THIRD, HUB_OLD):
                    prog = "\n".join(["set -Eeuo pipefail", self.helper_text(copy),
                                      f'wins_install_hub_authorized_key "{self.keys}" "{key}"'])
                    result = self.box.bash(prog, env)
                    self.assertEqual(0, result.returncode, result.stderr)
                    now = self.keys.read_bytes()
                    self.assertEqual(inode, self.keys.stat().st_ino, "authorized_keys was replaced")
                    self.assertTrue(now.startswith(previous), "bytes the file already held were changed")
                    suffix = now[len(previous):]
                    self.assertIn(suffix, (b"", (managed(key) + "\n").encode()))
                    previous = now
                calls = [ln for ln in log.read_text(encoding="utf-8").splitlines()]
                path = str(self.keys)
                for ln in calls:
                    cmd = ln.split(" ", 1)[0]
                    self.assertNotIn(cmd, REMOVING_COMMANDS, f"the helper ran {ln}")
                    if cmd == "install":
                        self.assertEqual(f"install [-d] [-m] [700] [{self.ssh}]", ln)
                    elif cmd == "chmod":
                        self.assertEqual(f"chmod [600] [{path}]", ln)
                    else:
                        self.fail(f"unexpected command in the audit log: {ln}")
                self.assertEqual(1, sum(1 for ln in calls if ln.startswith("chmod")), "mode normalised once (0644 only)")
                self.assertEqual([OPERATOR, managed(HUB_OLD), managed(HUB_NEW), managed(HUB_THIRD)], self.lines())


if __name__ == "__main__":
    unittest.main(verbosity=2)
