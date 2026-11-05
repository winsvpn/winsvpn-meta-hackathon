#!/usr/bin/env python3
"""Offline regression tests for the Double VPN Core path (lane L44, 2026-09-25).

Each test pins one defect found in the Core installer, its embedded sync agent,
or the Core-facing hub endpoints:

* the Core rendered MTU 1440 on core0/coreexit0/corex while the fleet and every
  client use 1280, so a residential PPPoE/DS-Lite uplink fragmented the
  Core-to-exit hop;
* (the Suricata MemoryHigh change is gated on Round SU and tested separately in
  tools/test_core_suricata_memory_high.py, shipped with diff 05);
* the outbound management connector Required the CPU-isolation oneshot, so an
  isolation failure at boot stranded the home Core;
* the sync oneshot had no start timeout, so one wedged docker exec stopped the
  heartbeat forever while every unit looked healthy;
* the sync agent asked two third-party IP services on every 3-second tick and
  never re-derived a residential endpoint after the address changed (modes 0,
  auto and 1, nonpublic answers and bounded staleness are tested here);
* the hub probed management over SSH on every tick;
* the hub site-AI key endpoint deleted every authorized_keys line that merely
  CONTAINED the submitted blob, and accepted non-keys (the repository port of
  the Round HK certified exact-line ownership fix is tested here);
* a bootstrap-only Core row was created 'online' and stayed that way forever.

Everything runs against the real shipped text: installer functions are sliced
and executed with bash, the sync agent is staged exactly as the installer emits
it, and hub handlers are exec'd from the embedded main.py.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.stage_core_sync_agent import stage
from tools.validate_deployment_scripts import parse_heredocs

CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"
CONTROL = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"


def _core() -> str:
    return CORE.read_text(encoding="utf-8")


def _bash_major() -> int:
    return int(
        subprocess.run(
            ["bash", "-c", 'printf %s "${BASH_VERSINFO[0]}"'],
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
    )


def _heredoc(target_suffix: str) -> str:
    bodies = [
        block.body
        for block in parse_heredocs(CORE)
        if block.header.strip().endswith(target_suffix)
    ]
    if len(bodies) != 1:
        raise AssertionError(f"expected one heredoc ending {target_suffix!r}, found {len(bodies)}")
    return bodies[0]


def _staged_agent(directory: Path) -> Path:
    output = directory / "stage"
    stage(CORE, output)
    agent = directory / "wins-core-sync-no-main"
    agent.write_text(
        (output / "wins-core-sync").read_text(encoding="utf-8").replace('\nmain "$@"\n', "\n"),
        encoding="utf-8",
    )
    return agent


def _run_harness(body: str, *args: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as value:
        root = Path(value)
        agent = _staged_agent(root)
        harness = root / "harness.sh"
        harness.write_text(
            "#!/usr/bin/env bash\nset -Eeuo pipefail\nagent=\"$1\"\nwork=\"$2\"\nshift 2\n"
            "CORE_ENV_FILE=/dev/null\n# shellcheck disable=SC1090\nsource \"${agent}\"\n"
            + body,
            encoding="utf-8",
        )
        return subprocess.run(
            ["bash", str(harness), str(agent), str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )



class CoreMtuTests(unittest.TestCase):
    def test_core_hops_render_the_fleet_standard_mtu(self):
        source = _core()
        self.assertIn('CORE_AWG_MTU="${CORE_AWG_MTU:-1280}"', source)
        self.assertNotRegex(source, r"(?m)^MTU = 1440$")
        rendered = re.findall(r"(?m)^MTU = (.+)$", source)
        self.assertEqual(rendered, ["${CORE_AWG_MTU}"] * 3, rendered)
        with tempfile.TemporaryDirectory() as value:
            agent = _staged_agent(Path(value)).read_text(encoding="utf-8")
        self.assertIn('CORE_AWG_MTU="${CORE_AWG_MTU:-1280}"', agent)
        self.assertIn("MTU = ${CORE_AWG_MTU}", agent)
        self.assertIn("printf 'CORE_AWG_MTU=%q\\n'", source)

    def test_mtu_bound_and_mss_clamp_follow_the_mtu(self):
        source = _core()
        start = source.index("core_awg_mtu_is_valid() {")
        end = source.index("\nvalid_iface_name() {", start)
        functions = source[start:end]
        script = functions + r'''
for good in 1280 1340 1420; do core_awg_mtu_is_valid "$good" || { echo "rejected $good"; exit 1; }; done
for bad in 1279 1421 1440 1500 abc "" 01280; do
  if core_awg_mtu_is_valid "$bad"; then echo "accepted $bad"; exit 1; fi
done
[[ "$(core_tcp_mss_for_mtu 1280)" == 1240 ]] || { echo "mss"; exit 1; }
'''
        result = subprocess.run(["bash", "-c", script], text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("--set-mss 1400", source)
        self.assertIn('-j TCPMSS --set-mss "${core_tcp_mss}"', source)


class CoreServiceContractTests(unittest.TestCase):
    def test_management_connector_survives_an_isolation_failure(self):
        source = _core()
        dropin = _heredoc(
            "/etc/systemd/system/wins-core-management-tunnel.service.d/50-wins-core-isolation.conf <<'EOF'"
        )
        self.assertIn("Wants=wins-core-isolation.service", dropin)
        self.assertNotIn("Requires=", dropin)
        self.assertIn("Slice=wins-core.slice", dropin)
        start = source.index("  for unit in nginx xray wins-core-sync")
        loop_header = source[start:source.index("; do", start)]
        self.assertNotIn("wins-core-management-tunnel", loop_header)
        # The data path still fails closed on isolation.
        self.assertIn("wins-core-xray-exit@", loop_header)
        self.assertIn(
            "[Unit]\nRequires=wins-core-isolation.service\nAfter=wins-core-isolation.service\n\n[Service]\nSlice=wins-core.slice",
            source,
        )

    def test_sync_oneshot_has_a_bounded_start_timeout(self):
        service = _heredoc("cat > /etc/systemd/system/wins-core-sync.service <<'EOF'")
        match = re.search(r"(?m)^TimeoutStartSec=([0-9]+)$", service)
        self.assertIsNotNone(match, service)
        # Longer than the slowest legitimate pass, far shorter than forever.
        self.assertGreaterEqual(int(match.group(1)), 180)
        self.assertLessEqual(int(match.group(1)), 600)


class SyncAgentBehaviourTests(unittest.TestCase):
    """Public-endpoint modes 0/auto/1, public-address validation, bounded
    staleness, and the management-probe cache. Stubs run inside command
    substitutions (subshells), so call counts are kept in files."""

    PRELUDE = r"""
: > "${work}/curl-calls"
printf '%s\n' 1.0.0.1 > "${work}/answer"
curl() { printf 'x\n' >> "${work}/curl-calls"; cat "${work}/answer"; }
count() { wc -l < "${work}/curl-calls" | tr -d '[:space:]'; }
# The empty-endpoint LAN fallback calls `ip`; answer with a private address.
ip() { printf '2: eth0    inet 192.168.4.36/24 brd 192.168.4.255 scope global eth0\n'; }
CORE_PUBLIC_IP_CACHE_FILE="${work}/public-ip"
CORE_PUBLIC_IP_REFRESH_SECONDS=300
CORE_PUBLIC_IP_RETRY_SECONDS=60
CORE_PUBLIC_IP_MAX_STALE_SECONDS=3600
CORE_TOKEN=test-token
CORE_INGRESS_PUBLIC_KEY=k1 CORE_EXIT_PUBLIC_KEY=k2 CORE_EXIT_PRIVATE_KEY=k3
reset() {
  rm -f "${CORE_PUBLIC_IP_CACHE_FILE}" "${CORE_PUBLIC_IP_CACHE_FILE}.attempt"
  : > "${work}/curl-calls"
  CORE_PUBLIC_INGRESS_ENDPOINT="$1"
  CORE_PUBLIC_STEALTH_ENDPOINT="$2"
}
expect() { [[ "${CORE_PUBLIC_INGRESS_ENDPOINT} ${CORE_PUBLIC_STEALTH_ENDPOINT} $(count)" == "$1" ]] || { echo "want [$1] got [${CORE_PUBLIC_INGRESS_ENDPOINT} ${CORE_PUBLIC_STEALTH_ENDPOINT} $(count)] at $2"; exit 1; }; }
"""

    def setUp(self):
        if _bash_major() < 4:
            self.skipTest("The Core sync agent requires Bash 4.")

    def _ok(self, body: str) -> subprocess.CompletedProcess[str]:
        result = _run_harness(self.PRELUDE + body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_mode_auto_follows_literal_endpoints_keeps_dns_and_caches(self):
        self._ok(r"""
CORE_PUBLIC_ENDPOINT_AUTODETECT=auto
reset 9.9.9.9:9210 9.9.9.9:80
require_ready
expect "1.0.0.1:9210 1.0.0.1:80 1" "auto literal"
printf '%s\n' 149.112.112.112 > "${work}/answer"
for _ in 1 2 3 4 5; do require_ready; done
expect "1.0.0.1:9210 1.0.0.1:80 1" "auto cache reuse"
reset core.example.net:9210 cdn.example.net:443
require_ready
expect "core.example.net:9210 cdn.example.net:443 0" "auto dns kept, no lookup"
reset core.example.net:9210 9.9.9.9:80
require_ready
expect "core.example.net:9210 149.112.112.112:80 1" "auto mixed"
""")

    def test_mode_one_replaces_dns_ingress_only_and_mode_zero_pins(self):
        self._ok(r"""
CORE_PUBLIC_ENDPOINT_AUTODETECT=1
reset core.example.net:9210 cdn.example.net:443
require_ready
expect "1.0.0.1:9210 cdn.example.net:443 1" "mode 1 replaces the dns AWG ingress, never a dns stealth host"
CORE_PUBLIC_ENDPOINT_AUTODETECT=0
reset 9.9.9.9:9210 9.9.9.9:80
require_ready
expect "9.9.9.9:9210 9.9.9.9:80 0" "mode 0 pins literals"
reset core.example.net:9210 cdn.example.net:443
require_ready
expect "core.example.net:9210 cdn.example.net:443 0" "mode 0 pins dns"
CORE_PUBLIC_ENDPOINT_AUTODETECT=bogus
if (require_ready) 2>/dev/null; then echo "invalid mode accepted"; exit 1; fi
""")

    def test_no_mode_produces_a_stealth_endpoint_the_hub_tls_rule_rejects(self):
        """Seat S AI-2: every mode x transport x endpoint combination is run
        through the agent, and each result is checked with the hub's own
        xray_tls_dns_candidate_available (exec'd from the embedded main.py)."""
        cases = []
        for mode in ("0", "auto", "1"):
            for transports in ("80:none", "443:tls", "80:none,443:tls"):
                for stealth in ("cdn.example.net:443", "9.9.9.9:443", ""):
                    cases.append((mode, transports, stealth))
        body = "\n".join(
            'CORE_PUBLIC_ENDPOINT_AUTODETECT=%s; CORE_STEALTH_TRANSPORTS=%s; reset 9.9.9.9:9210 "%s"; require_ready; '
            'printf "RESULT|%s|%s|%s|%%s\\n" "${CORE_PUBLIC_STEALTH_ENDPOINT}"' % (m, t, st, m, t, st)
            for m, t, st in cases
        )
        result = self._ok(body)
        namespace: dict[str, Any] = {"re": re, "Any": Any}
        import ipaddress
        namespace["ipaddress"] = ipaddress
        _load({"xray_tls_dns_candidate_available", "split_host_port", "parse_aliases", "normalize_hostname"}, namespace)
        dns_ok = namespace["xray_tls_dns_candidate_available"]
        rows = [line.split("|") for line in result.stdout.splitlines() if line.startswith("RESULT|")]
        self.assertEqual(len(rows), len(cases), result.stdout)
        for _, mode, transports, before, after in rows:
            if before and not before.startswith("9.9.9.9"):
                self.assertEqual(after, before, f"mode {mode} {transports}: a DNS stealth host was replaced")
            if "tls" in transports and not before:
                self.assertEqual(after, "", f"mode {mode} {transports}: empty stealth filled with {after!r} under TLS")
            if "tls" in transports and after:
                accepted_before = dns_ok(before, "[]", 443) if before else True
                self.assertEqual(
                    dns_ok(after, "[]", 443), accepted_before,
                    f"mode {mode} {transports}: stealth {before!r} -> {after!r} changes the hub TLS verdict",
                )
                if before != after:
                    self.fail(f"mode {mode} {transports}: stealth rewritten while a TLS transport is configured")

    def test_nonpublic_answers_are_never_advertised_or_cached(self):
        result = self._ok(r"""
CORE_PUBLIC_ENDPOINT_AUTODETECT=1
for bad in 100.64.1.2 192.168.4.36 10.0.0.9 127.0.0.1 169.254.1.1 203.0.113.10 224.0.0.1 0.0.0.0; do
  reset 9.9.9.9:9210 9.9.9.9:80
  printf '%s\n' "${bad}" > "${work}/answer"
  require_ready
  expect "9.9.9.9:9210 9.9.9.9:80 2" "nonpublic ${bad}"
  [[ ! -e "${CORE_PUBLIC_IP_CACHE_FILE}" ]] || { echo "nonpublic ${bad} cached"; exit 1; }
done
""")
        self.assertIn("class=public_ip_nonpublic", result.stderr)

    def test_empty_endpoint_never_falls_back_to_a_lan_address_or_an_empty_host(self):
        """IA-E2E R-1: with no usable public answer, an empty endpoint used to
        take the first interface address unchecked (a NATed Core advertised
        its LAN address) or, with none, became ":9210", which the hub refuses.
        Only a globally routable interface address may fill it now."""
        result = self._ok(r"""
CORE_PUBLIC_ENDPOINT_AUTODETECT=auto
printf '%s\n' 192.168.4.36 > "${work}/answer"
reset "" ""
require_ready
expect "  2" "LAN interface address refused"
ip() { :; }
reset "" ""
require_ready
expect "  2" "no interface address leaves the endpoint empty, never :9210"
ip() { printf '%s\n' '2: eth0    inet 192.168.4.36/24 brd 192.168.4.255 scope global eth0' \
  '3: eth1    inet 9.9.9.9/24 brd 9.9.9.255 scope global eth1'; }
reset "" ""
require_ready
expect "9.9.9.9:9210 9.9.9.9:80 2" "first public interface address used"
CORE_STEALTH_TRANSPORTS=443:tls
reset "" ""
require_ready
expect "9.9.9.9:9210  2" "no IP-literal stealth endpoint under TLS"
""")
        self.assertIn("class=public_ip_unavailable", result.stderr)

    def test_refresh_failure_serves_cache_only_until_max_stale_then_keeps_persisted(self):
        result = self._ok(r"""
CORE_PUBLIC_ENDPOINT_AUTODETECT=auto
now="$(date +%s)"
# Cache older than the refresh interval but inside max-stale: lookup fails,
# the last public answer is still used.
reset 9.9.9.9:9210 9.9.9.9:80
printf '%s %s\n' 1.0.0.1 "$((now - 1000))" > "${CORE_PUBLIC_IP_CACHE_FILE}"
: > "${work}/answer"
require_ready
expect "1.0.0.1:9210 1.0.0.1:80 2" "stale-but-bounded cache"
# Retry backoff: a second pass inside CORE_PUBLIC_IP_RETRY_SECONDS makes no lookup.
: > "${work}/curl-calls"
require_ready
expect "1.0.0.1:9210 1.0.0.1:80 0" "retry backoff"
# Cache beyond max-stale: nothing usable, persisted endpoints are kept.
reset 9.9.9.9:9210 9.9.9.9:80
printf '%s %s\n' 1.0.0.1 "$((now - 7200))" > "${CORE_PUBLIC_IP_CACHE_FILE}"
require_ready
expect "9.9.9.9:9210 9.9.9.9:80 2" "expired cache keeps persisted"
# A cache entry claiming a nonpublic address is ignored.
reset 9.9.9.9:9210 9.9.9.9:80
printf '%s %s\n' 192.168.4.36 "${now}" > "${CORE_PUBLIC_IP_CACHE_FILE}"
require_ready
expect "9.9.9.9:9210 9.9.9.9:80 2" "tampered cache ignored"
""")
        self.assertIn("class=public_ip_refresh_failed", result.stderr)

    def test_management_probe_success_is_reused_inside_the_hub_window(self):
        self._ok(r"""
: > "${work}/probes"
printf '%s' '{"ok":true,"management_status":"ok"}' > "${work}/reply"
hub_curl() { printf 'x\n' >> "${work}/probes"; cat "${work}/reply"; }
probes() { wc -l < "${work}/probes" | tr -d '[:space:]'; }
CORE_MANAGEMENT_TUNNEL_ENABLED=1
CORE_MANAGEMENT_VERIFY_STAMP_FILE="${work}/mgmt-stamp"
CORE_MANAGEMENT_VERIFY_CACHE_SECONDS=60
verify_management_runtime
verify_management_runtime
[[ "$(probes)" == 1 ]] || { echo "probes=$(probes)"; exit 1; }
# The tunnel fails INSIDE the cached interval: by design the Core does not
# notice until the stamp expires (at most CORE_MANAGEMENT_VERIFY_CACHE_SECONDS,
# bounded to 120 s, inside the hub's 180 s window).
printf '%s' '{"ok":false,"management_status":"failed"}' > "${work}/reply"
verify_management_runtime
[[ "$(probes)" == 1 ]] || { echo "cached pass probed: $(probes)"; exit 1; }
# First pass after expiry detects the failure and clears the stamp.
printf '%s\n' "$(( $(date +%s) - 61 ))" > "${CORE_MANAGEMENT_VERIFY_STAMP_FILE}"
if verify_management_runtime; then echo "failed probe passed"; exit 1; fi
[[ ! -e "${CORE_MANAGEMENT_VERIFY_STAMP_FILE}" ]] || { echo "stamp kept after failure"; exit 1; }
[[ "$(probes)" == 2 ]] || { echo "probes=$(probes)"; exit 1; }
if verify_management_runtime; then echo "failure was cached"; exit 1; fi
[[ "$(probes)" == 3 ]] || { echo "probes=$(probes)"; exit 1; }
printf '%s' '{"ok":true,"management_status":"ok"}' > "${work}/reply"
CORE_MANAGEMENT_VERIFY_CACHE_SECONDS=0
verify_management_runtime; verify_management_runtime
[[ "$(probes)" == 5 ]] || { echo "probes=$(probes)"; exit 1; }
""")



# --------------------------------------------------------------------------
# Hub handlers, exec'd from the embedded main.py.


class HTTPException(Exception):
    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _embedded_main() -> str:
    installer = CONTROL.read_text(encoding="utf-8")
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index("\n", installer.index(marker)) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def _load(
    names: set[str],
    namespace: dict[str, Any],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Exec the named top-level functions and assignments of the embedded
    main.py. Route decorators (@app.*) are stripped; other decorators such as
    @contextmanager are kept. Names in `optional` may be absent (so a test can
    run the unpatched handler and fail on behaviour, not on import)."""
    tree = ast.parse(_embedded_main())
    nodes = []
    found: set[str] = set()
    wanted = set(names) | set(optional)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted:
            node.decorator_list = [
                d for d in node.decorator_list
                if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                        and isinstance(d.func.value, ast.Name) and d.func.value.id == "app")
            ]
            nodes.append(node)
            found.add(node.name)
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in wanted
        ):
            nodes.append(node)
            found.add(node.targets[0].id)
    if not set(names) <= found:
        raise AssertionError(f"missing embedded names: {sorted(set(names) - found)}")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "embedded-l44", "exec"), namespace)
    return namespace


def _ed25519_line(comment: str) -> tuple[str, str]:
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + secrets.token_bytes(32)
    encoded = base64.b64encode(blob).decode("ascii")
    return encoded, f"ssh-ed25519 {encoded} {comment}"


SITE_AI_HELPERS = frozenset({
    "_SSH_KEY_TYPES_FOR_BLOB", "_SITE_AI_TUNNEL_PREFIX", "_SITE_AI_TUNNEL_LOCK",
    "_site_ai_ownership_path", "_site_ai_ownership_flock", "_site_ai_owned_lines",
    "_site_ai_save_owned_lines", "_site_ai_key_blob_valid", "_authorized_key_line_blob",
    "_is_site_ai_tunnel_line", "_site_ai_authorized_keys_path", "SITE_AI_TUNNEL_SSH_USER",
})


def _ed_blob(seed: bytes) -> str:
    return base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + seed).decode("ascii")


class SiteAiTunnelKeyTests(unittest.TestCase):
    """Repository lineage of the Round HK certified fix: the endpoint removes
    only the exact lines recorded in its own ownership file, and refuses (409)
    a key present in any line it does not own. Cases mirror HK's
    test_sitekey.py, plus Seat S's two Round AI counterexamples."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "root" / ".ssh").mkdir(parents=True)
        (self.root / "etc" / "ssh").mkdir(parents=True)
        (self.root / "etc" / "ssh" / "ssh_host_ed25519_key.pub").write_text(
            "ssh-ed25519 " + _ed_blob(secrets.token_bytes(32)) + " host\n", encoding="ascii"
        )
        self.ownership = self.root / "site_ai_tunnel_owned.json"
        self.previous_env = os.environ.get("SITE_AI_TUNNEL_OWNERSHIP_FILE")
        os.environ["SITE_AI_TUNNEL_OWNERSHIP_FILE"] = str(self.ownership)
        # H0 (D3): the endpoint writes the non-root forwarding account's keys
        # file, not root's; operator lines in that file are what it must keep.
        self.authorized = self.root / "var" / "lib" / "wins-site-ai-tunnel" / "authorized_keys"
        self.authorized.parent.mkdir(parents=True)
        self.previous_keys_env = os.environ.get("SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE")
        os.environ["SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE"] = str(self.authorized)
        real_path = Path
        root = self.root

        def fake_path(value: str) -> Path:
            text = str(value)
            if text.startswith("/root/") or text.startswith("/etc/ssh"):
                return real_path(str(root) + text)
            return real_path(text)

        @contextmanager
        def fake_db():
            yield None

        import fcntl
        import json
        import threading

        namespace: dict[str, Any] = {
            "Path": fake_path, "HTTPException": HTTPException, "re": re, "os": os,
            "base64": base64, "json": json, "fcntl": fcntl, "threading": threading,
            "contextmanager": contextmanager, "get_db": fake_db,
            "ensure_schema": lambda conn: None,
            "require_core_token": lambda *args, **kwargs: None,
            "DOUBLE_VPN_CORE_ID": "north-america-core",
            "SiteAiTunnelKeyRequest": object, "Request": object,
            "Header": lambda *args, **kwargs: None,
            # The handler binds the tunnel to the port of the hub's own site-AI
            # endpoint (audit hub-b F-3); main.py imports urllib at module top.
            "urllib": urllib, "SITE_AI_LOCAL_ENDPOINT": "http://127.0.0.1:11435",
        }
        _load({"register_site_ai_tunnel_key"}, namespace, optional=SITE_AI_HELPERS)
        self.handler = namespace["register_site_ai_tunnel_key"]
        self.op1 = "ssh-ed25519 " + _ed_blob(secrets.token_bytes(32)) + " operator-one"
        self.op2 = 'from="10.0.0.0/8" ssh-ed25519 ' + _ed_blob(secrets.token_bytes(32)) + " operator-two"
        self.op3 = "ssh-rsa " + base64.b64encode(
            struct.pack(">I", 7) + b"ssh-rsa" + secrets.token_bytes(300)
        ).decode("ascii") + " operator-rsa"
        # Seat S counterexample 1: an operator line with the SAME options the
        # endpoint writes.
        self.opfwd = ('restrict,port-forwarding,permitlisten="127.0.0.1:2222" ssh-ed25519 '
                      + _ed_blob(secrets.token_bytes(32)) + " operator-forward")
        self.operators = [self.op1, self.op2, self.op3, self.opfwd]
        self.authorized.write_text("\n".join(self.operators) + "\n", encoding="ascii")

    def tearDown(self):
        if self.previous_env is None:
            os.environ.pop("SITE_AI_TUNNEL_OWNERSHIP_FILE", None)
        else:
            os.environ["SITE_AI_TUNNEL_OWNERSHIP_FILE"] = self.previous_env
        if self.previous_keys_env is None:
            os.environ.pop("SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE", None)
        else:
            os.environ["SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE"] = self.previous_keys_env
        self.tmp.cleanup()

    def post(self, key: str, port: int = 11435) -> int:
        payload = SimpleNamespace(core_id="north-america-core", public_key=key, listen_port=port, label="")
        try:
            self.handler(payload, object(), "core-token")
        except HTTPException as exc:
            return exc.status_code
        return 200

    def lines(self) -> list[str]:
        return self.authorized.read_text(encoding="ascii").splitlines()

    def test_non_keys_are_refused_and_operator_lines_survive(self):
        self.assertEqual(self.post("ssh-ed25519 A"), 400)
        self.assertEqual(self.post("ssh-ed25519 " + self.op1.split()[1][4:20]), 400)
        wrong_type = base64.b64encode(struct.pack(">I", 7) + b"ssh-rsa" + b"x" * 40).decode("ascii")
        self.assertEqual(self.post("ssh-ed25519 " + wrong_type), 400)
        self.assertEqual(self.post("ssh-ed25519 " + _ed_blob(b"x" * 10)), 400)
        self.assertEqual(self.post("ssh-ed25519 !!!!"), 400)
        self.assertEqual(self.lines(), self.operators)

    def test_same_option_operator_line_survives_registration_and_rotation(self):
        first = "ssh-ed25519 " + _ed_blob(secrets.token_bytes(32))
        self.assertEqual(self.post(first), 200)
        after = self.lines()
        self.assertEqual(after[:4], self.operators)
        self.assertEqual(len(after), 5)
        self.assertTrue(after[4].startswith('restrict,port-forwarding,permitlisten="127.0.0.1:11435" ssh-ed25519 '))
        second = "ssh-ed25519 " + _ed_blob(secrets.token_bytes(32))
        self.assertEqual(self.post(second), 200)
        rotated = self.lines()
        self.assertEqual(rotated[:4], self.operators)
        self.assertEqual(len(rotated), 5)
        self.assertIn(second.split()[1], rotated[4])
        self.assertNotIn(first.split()[1], "\n".join(rotated))
        self.assertEqual(self.post(second), 200)
        self.assertEqual(sum(second.split()[1] in line for line in self.lines()), 1)
        self.assertEqual(oct(self.ownership.stat().st_mode & 0o777), "0o600")

    def test_exact_operator_blob_is_refused_409_and_survives(self):
        # Seat S counterexample 2: a submitted blob EXACTLY equal to an
        # operator key. Each must be refused and the file stay byte-identical.
        before = self.lines()
        codes = [self.post(line.split()[-3] + " " + line.split()[-2]) for line in (self.op1, self.op2, self.op3)]
        codes.append(self.post("ssh-ed25519 " + self.opfwd.split()[-2]))
        self.assertEqual(codes, [409, 409, 409, 409])
        self.assertEqual(self.lines(), before)

    def test_operator_line_reusing_the_current_site_ai_blob_survives_rotation(self):
        current = "ssh-ed25519 " + _ed_blob(secrets.token_bytes(32))
        self.assertEqual(self.post(current), 200)
        shared = ('restrict,port-forwarding,permitlisten="127.0.0.1:3333" ssh-ed25519 '
                  + current.split()[1] + " operator-shared")
        with self.authorized.open("a", encoding="ascii") as handle:
            handle.write(shared + "\n")
        self.assertEqual(self.post("ssh-ed25519 " + _ed_blob(secrets.token_bytes(32))), 200)
        after = self.lines()
        self.assertIn(shared, after)
        self.assertEqual(after[:4], self.operators)
        self.assertFalse(any("11435" in line and current.split()[1] in line for line in after))

    def test_corrupt_or_tampered_ownership_record_removes_nothing(self):
        self.ownership.write_text("{not json", encoding="ascii")
        self.assertEqual(self.post("ssh-ed25519 " + _ed_blob(secrets.token_bytes(32))), 200)
        self.assertEqual(self.lines()[:4], self.operators)
        self.ownership.write_text('{"lines": [%s]}' % json.dumps(self.op1), encoding="ascii")
        self.assertEqual(self.post("ssh-ed25519 " + _ed_blob(secrets.token_bytes(32))), 200)
        self.assertIn(self.op1, self.lines())


class BootstrapRowStatusTests(unittest.TestCase):
    def _bootstrap(self, conn: sqlite3.Connection):
        @contextmanager
        def fake_db():
            yield conn

        namespace: dict[str, Any] = {
            "re": re,
            "secrets": secrets,
            "HTTPException": HTTPException,
            "get_db": fake_db,
            "ensure_schema": lambda c: None,
            "consume_bootstrap_grant": lambda c, token, role, subject: True,
            "token_digest": lambda token: hashlib.sha256(token.encode()).hexdigest(),
            "security_alert": lambda *args, **kwargs: None,
            "DOUBLE_VPN_CORE_ID": "north-america-core",
            "CoreBootstrapRequest": object,
            "Request": object,
            "sqlite3": sqlite3,
        }
        _load({"bootstrap_core", "create_core_servers_table"}, namespace)
        namespace["create_core_servers_table"](conn)
        conn.execute("ALTER TABLE core_servers ADD COLUMN core_token_hash TEXT")
        return namespace["bootstrap_core"]

    def test_bootstrap_only_row_is_not_advertised_online(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        bootstrap = self._bootstrap(conn)
        result = bootstrap(SimpleNamespace(core_id="aicore-core0", bootstrap_token="g"), object())
        self.assertTrue(result["ok"])
        row = conn.execute("SELECT status, last_heartbeat FROM core_servers WHERE core_id='aicore-core0'").fetchone()
        self.assertEqual(row["status"], "maintenance")
        self.assertIsNone(row["last_heartbeat"])

    def _management_bootstrap(self, conn: sqlite3.Connection):
        @contextmanager
        def fake_db():
            yield conn

        namespace: dict[str, Any] = {
            "re": re, "HTTPException": HTTPException, "get_db": fake_db,
            "ensure_schema": lambda c: None,
            "require_admin_token": lambda *args, **kwargs: None,
            "normalized_management_ssh_host_keys": lambda keys: list(keys or []),
            "ensure_core_management_tunnel": lambda core_id: {"ssh_host": f"core-{core_id}.example.net", "tunnel_id": "t"},
            "install_management_known_hosts": lambda host, keys: None,
            "security_alert": lambda *args, **kwargs: None,
            "CoreManagementTunnelBootstrap": object, "Request": object, "Optional": Optional,
            "Header": lambda *args, **kwargs: None,
        }
        _load({"bootstrap_core_management_tunnel"}, namespace)
        return namespace["bootstrap_core_management_tunnel"]

    def test_management_bootstrap_only_row_is_not_advertised_online(self):
        # Seat S AI-3: the other Core-creating insert.
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self._bootstrap(conn)  # creates the table
        bootstrap = self._management_bootstrap(conn)
        payload = SimpleNamespace(core_id="aicore-core0", ssh_user="aicore", ssh_host_keys=["ssh-ed25519 AAAA"])
        self.assertTrue(bootstrap(payload, object(), "admin")["ok"])
        row = conn.execute("SELECT status, management_status FROM core_servers WHERE core_id='aicore-core0'").fetchone()
        self.assertEqual(row["status"], "maintenance")
        self.assertEqual(row["management_status"], "unknown")
        # An existing, registered row keeps its status.
        conn.execute("INSERT INTO core_servers (core_id, status) VALUES ('north-america-core', 'online')")
        bootstrap(SimpleNamespace(core_id="north-america-core", ssh_user="aicore", ssh_host_keys=[]), object(), "admin")
        row = conn.execute("SELECT status FROM core_servers WHERE core_id='north-america-core'").fetchone()
        self.assertEqual(row["status"], "online")

    def test_rebootstrap_keeps_a_registered_row_status(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        bootstrap = self._bootstrap(conn)
        conn.execute(
            "INSERT INTO core_servers (core_id, status, core_token_hash) VALUES ('north-america-core', 'online', 'old')"
        )
        bootstrap(SimpleNamespace(core_id="north-america-core", bootstrap_token="g"), object())
        row = conn.execute("SELECT status, core_token_hash FROM core_servers WHERE core_id='north-america-core'").fetchone()
        self.assertEqual(row["status"], "online")
        self.assertNotEqual(row["core_token_hash"], "old")


if __name__ == "__main__":
    unittest.main()
