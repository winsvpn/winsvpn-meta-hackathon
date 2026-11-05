#!/usr/bin/env python3
"""configure_appcloud_tunnel_connector in wins_control_plane_setup_ONETOUCH.sh.

Runs the REAL function text, extracted from the installer, in bash with every
system-changing command stubbed (install, systemctl, systemd-analyze,
cloudflared, curl, mktemp, useradd, install_cloudflared_package) and every
path it writes redirected into a private temporary root. Fake credentials
only.

The unit file must be byte-identical to wins-appcloud-tunnel.service as
installed on the live hub on 2026-09-26 (sha256 pinned below; the unit holds
no secret). The config and credentials files must match the exact rendering
that live connector uses, checked here against literal expected text.

Run:  python3 server/test_appcloud_tunnel_connector.py [path/to/installer]
"""
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
    else os.path.join(HERE, "wins_control_plane_setup_ONETOUCH.sh")
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    del sys.argv[1]
BASH = shutil.which("bash")

LIVE_UNIT_SHA256 = "ec0ac29257084f90295bd87f7da56877f2906184c17e2dee81680466dad83f5e"
ZONE = "app-cloud-sync.net"
FAKE_TID = "0123abcd-4567-89ef-0123-456789abcdef"
FAKE_SECRET = "L65FAKETUNNELSECRETnotarealvalue0000000000=="
FAKE_ACCOUNT = "f00dfeedf00dfeedf00dfeedf00dfeed"
FAKE_CRED = {"AccountTag": FAKE_ACCOUNT, "TunnelSecret": FAKE_SECRET, "TunnelID": FAKE_TID,
             "Endpoint": ""}
FRONTS = [f"{c}.{ZONE}" for c in "abcdefghijklmnopqrstuvwxyz"]

with open(INSTALLER, encoding="utf-8") as fh:
    SOURCE = fh.read()


def extract_function(name):
    m = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}\n", SOURCE, re.S | re.M)
    return m.group(0) if m else None


FUNC = extract_function("configure_appcloud_tunnel_connector")

STUBS = r'''
set -Eeuo pipefail
log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
err()  { printf '[ERR] %s\n' "$*"; }
rec()  { printf '%s\n' "$*" >> "${ROOT}/calls"; }
install_cloudflared_package() { rec "install_cloudflared_package"; }
id() { return 0; }
useradd() { rec "useradd $*"; }
mktemp() {
  [[ "$*" == "-d /run/wins-appcloud.XXXXXX" ]] || { echo "unexpected mktemp $*" >&2; return 1; }
  mkdir -p "${ROOT}/run"; command mktemp -d "${ROOT}/run/wins-appcloud.XXXXXX"
}
install() {
  local owner="" group="" mode="" dir=0 a=()
  while (($#)); do
    case "$1" in -o) owner=$2; shift 2 ;; -g) group=$2; shift 2 ;; -m) mode=$2; shift 2 ;; -d) dir=1; shift ;; *) a+=("$1"); shift ;; esac
  done
  if ((dir)); then local d; for d in "${a[@]}"; do mkdir -p "${ROOT}${d}"; rec "install-d ${d} ${owner}:${group} ${mode}"; done; return 0; fi
  [[ "${a[1]}" == /* ]] || return 1
  mkdir -p "$(dirname "${ROOT}${a[1]}")"
  command cp "${a[0]}" "${ROOT}${a[1]}"
  rec "install ${a[1]} ${owner}:${group} ${mode}"
}
cloudflared() {
  rec "cloudflared $*"
  [[ -n "${CF_REJECT:-}" ]] && return 1
  local cfg="$3" host
  [[ "$1 $2" == "tunnel --config" && -f "${cfg}" ]] || return 1
  grep -q '^credentials-file: .*/run/wins-appcloud\.' "${cfg}" || return 1
  case "$4 $5" in
    "ingress validate") return 0 ;;
    "ingress rule")
      host="${6#https://}"; host="${host%%/*}"
      if grep -qx "  - hostname: ${host}" "${cfg}"; then printf 'Matched rule #0\n\tservice: %s\n' "$(sed -n 's/^    service: //p' "${cfg}" | head -n 1)"; else printf 'Matched rule #1\n\tservice: http_status:404\n'; fi ;;
    *) return 1 ;;
  esac
}
systemd-analyze() { rec "systemd-analyze $*"; }
systemctl() { rec "systemctl $*"; }
curl() { rec "curl"; printf '%s' "${READY_CODE:-200}"; }
sleep() { :; }
'''


def run(env_extra):
    root = tempfile.mkdtemp(prefix="appcloud-test-")
    script = os.path.join(root, "harness.sh")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(STUBS + FUNC + "\nconfigure_appcloud_tunnel_connector\n")
    env = {"PATH": os.environ.get("PATH", ""), "ROOT": root, "LC_ALL": "C",
           "CLOUDFLARE_APPCLOUD_ZONE_NAME_DEFAULT": ZONE}
    env.update(env_extra)
    p = subprocess.run([BASH, script], env=env, capture_output=True, text=True, timeout=60)
    calls = []
    if os.path.exists(os.path.join(root, "calls")):
        with open(os.path.join(root, "calls"), encoding="utf-8") as fh:
            calls = fh.read().splitlines()
    files = {}
    for sub in ("etc/cloudflared/appcloud.yml", "etc/cloudflared/appcloud-credentials.json",
                "etc/systemd/system/wins-appcloud-tunnel.service"):
        path = os.path.join(root, sub)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                files["/" + sub] = fh.read()
    leftover = os.listdir(os.path.join(root, "run")) if os.path.isdir(os.path.join(root, "run")) else []
    shutil.rmtree(root, ignore_errors=True)
    return p.returncode, p.stdout + p.stderr, calls, files, leftover


def full_env(**over):
    hosts = FRONTS[:]
    random.Random(7).shuffle(hosts)
    raw_hosts = ", ".join(h.upper() if i % 3 == 0 else h for i, h in enumerate(hosts)) + "\n" + hosts[0]
    env = {"APPCLOUD_TUNNEL_ID": FAKE_TID.upper(), "APPCLOUD_TUNNEL_CREDENTIALS": json.dumps(FAKE_CRED),
           "APPCLOUD_TUNNEL_HOSTS": raw_hosts}
    env.update(over)
    return env


def expected_yml():
    lines = [f"tunnel: {FAKE_TID}", "credentials-file: /etc/cloudflared/appcloud-credentials.json",
             "metrics: 127.0.0.1:20251", "no-autoupdate: true", "originRequest:", "  connectTimeout: 10s",
             "ingress:"]
    for h in FRONTS:
        lines += [f"  - hostname: {h}", "    service: http://127.0.0.1:80"]
    lines += ["  - service: http_status:404", ""]
    return "\n".join(lines).encode()


class AppcloudConnector(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(FUNC, "configure_appcloud_tunnel_connector() not found in the installer")

    def assertNoSecret(self, out):
        for value in (FAKE_SECRET, FAKE_ACCOUNT, FAKE_TID, FAKE_TID.upper()):
            self.assertNotIn(value, out)

    def test_absent_secrets_skip_cleanly(self):
        rc, out, calls, files, left = run({})
        self.assertEqual(rc, 0, out)
        self.assertIn("not set", out)
        self.assertEqual((calls, files, left), ([], {}, []))

    def test_partial_secrets_fail_closed(self):
        for present in (("APPCLOUD_TUNNEL_ID",), ("APPCLOUD_TUNNEL_ID", "APPCLOUD_TUNNEL_CREDENTIALS"),
                        ("APPCLOUD_TUNNEL_HOSTS",)):
            env = {k: v for k, v in full_env().items() if k in present}
            rc, out, calls, files, left = run(env)
            self.assertEqual(rc, 1, (present, out))
            self.assertEqual((calls, files, left), ([], {}, []), present)
            self.assertNoSecret(out)

    def test_full_secrets_install_the_live_connector_bytes(self):
        rc, out, calls, files, left = run(full_env())
        self.assertEqual(rc, 0, out)
        self.assertEqual(hashlib.sha256(files["/etc/systemd/system/wins-appcloud-tunnel.service"]).hexdigest(),
                         LIVE_UNIT_SHA256)
        self.assertEqual(files["/etc/cloudflared/appcloud.yml"], expected_yml())
        self.assertEqual(files["/etc/cloudflared/appcloud-credentials.json"], json.dumps(FAKE_CRED).encode())
        installs = [c for c in calls if c.startswith(("install ", "install-d "))]
        self.assertEqual(installs, [
            "install-d /etc/cloudflared root:cloudflared 750",
            "install /etc/cloudflared/appcloud-credentials.json root:cloudflared 0640",
            "install /etc/cloudflared/appcloud.yml root:cloudflared 0640",
            "install /etc/systemd/system/wins-appcloud-tunnel.service root:root 0644",
        ])
        tail = [c for c in calls if c.startswith(("systemd-analyze", "systemctl"))]
        self.assertEqual(tail, [
            "systemd-analyze verify /etc/systemd/system/wins-appcloud-tunnel.service",
            "systemctl daemon-reload",
            "systemctl enable --now wins-appcloud-tunnel.service",
            "systemctl restart wins-appcloud-tunnel.service",
        ])
        self.assertEqual(calls[0], "install_cloudflared_package")
        self.assertTrue(any(c.endswith("ingress validate") for c in calls))
        self.assertIn("ready", out)
        self.assertEqual(left, [], "staging directory left behind")
        self.assertNoSecret(out)

    def test_invalid_inputs_install_nothing(self):
        other = dict(FAKE_CRED, TunnelID="ffffffff-4567-89ef-0123-456789abcdef")
        cases = {
            "credentials for another tunnel": full_env(APPCLOUD_TUNNEL_CREDENTIALS=json.dumps(other)),
            "credentials not JSON": full_env(APPCLOUD_TUNNEL_CREDENTIALS="not-json " + FAKE_SECRET),
            "credentials missing TunnelSecret": full_env(APPCLOUD_TUNNEL_CREDENTIALS=json.dumps(
                {k: v for k, v in FAKE_CRED.items() if k != "TunnelSecret"})),
            "id not a UUID": full_env(APPCLOUD_TUNNEL_ID="not-a-uuid"),
            "host outside the app zone": full_env(APPCLOUD_TUNNEL_HOSTS="a.app-cloud-sync.net evil.example.com"),
            "host label invalid": full_env(APPCLOUD_TUNNEL_HOSTS="-a.app-cloud-sync.net"),
            "hosts only separators": full_env(APPCLOUD_TUNNEL_HOSTS=" , "),
        }
        for label, env in cases.items():
            rc, out, calls, files, left = run(env)
            self.assertEqual(rc, 1, (label, out))
            self.assertEqual(files, {}, label)
            self.assertFalse([c for c in calls if c.startswith(("install ", "systemctl"))], label)
            self.assertEqual(left, [], label)
            self.assertNoSecret(out)

    def test_cloudflared_rejecting_ingress_installs_nothing(self):
        rc, out, calls, files, left = run(full_env(CF_REJECT="1"))
        self.assertEqual(rc, 1, out)
        self.assertEqual((files, left), ({}, []))
        self.assertFalse([c for c in calls if c.startswith(("install ", "systemctl"))])

    def test_connector_not_ready_fails_the_deploy(self):
        # CP-7: a connector that never reports ready leaves every app front on
        # Cloudflare 1033, so the deploy stops instead of passing.
        rc, out, calls, files, left = run(full_env(READY_CODE="503"))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("[ERR]", out)
        self.assertIn("not ready after 60 s (metrics /ready=503)", out)
        self.assertEqual(len(files), 3)

    def test_main_runs_it_right_after_the_control_tunnel(self):
        main = extract_function("main")
        self.assertIsNotNone(main)
        self.assertIn("\n  configure_control_origin_tunnel\n  configure_appcloud_tunnel_connector\n", main)
        self.assertEqual(len(re.findall(r"^\s*configure_appcloud_tunnel_connector\s*$", SOURCE, re.M)), 1)

    def test_credentials_are_in_the_secret_permission_floor(self):
        specs = extract_function("control_secret_path_specs")
        self.assertIsNotNone(specs)
        self.assertIn('"${cf_dir}/appcloud-credentials.json|007|', specs)


if __name__ == "__main__":
    unittest.main()
