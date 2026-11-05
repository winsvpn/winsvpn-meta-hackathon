#!/usr/bin/env python3
"""Hub installer LOW findings IA-CP-08 through IA-CP-18 (lane FX-CP-B, 2026-09-29).

Every test runs the REAL text extracted from wins_control_plane_setup_ONETOUCH.sh
(a shell function, a generated script heredoc, or the embedded main.py), with
system-changing commands stubbed and every absolute path it writes redirected
into a private temporary root. No network, no host, no real credential: every
token, key and address below is a fake or an RFC 5737 / example.test value.

  IA-CP-08  write_nginx: a config `nginx -t` rejects is rolled back; an
            unchanged rerun restarts neither nginx nor the control tunnel.
  IA-CP-09  the Access service-token writer replaces runtime env lines.
  IA-CP-10  direct-origin nginx trusts Cloudflare's ranges for CF-Connecting-IP.
  IA-CP-11  hub ssh children get a narrowed environment.
  IA-CP-12  /ref/ and /referral/ reach the hub instead of the static site.
  IA-CP-13  Suricata rule updates are staged, reviewed, health-checked and
            rolled back; the weekly run uses the same path.
  IA-CP-14  the Litestream replica directory reaches the pruner, which never
            deletes the whole history.
  IA-CP-15  DNS upsert never PUTs over a record of another type.
  IA-CP-16  the secrets file passes the same trusted-env gate as defaults.
  IA-CP-17  the RPO-0 claim names what the barrier does not cover.
  IA-CP-18  the hub backup cannot silently drop a present or critical member.

Run:  python3 server/test_control_plane_installer_low_fixes.py
      WINS_CP_INSTALLER=/path/to/installer python3 server/test_...py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.environ.get("WINS_CP_INSTALLER") or os.path.join(
    HERE, "wins_control_plane_setup_ONETOUCH.sh")
BASH = _toolchain.bash4()
GTAR = shutil.which("gtar") or shutil.which("tar")

with open(INSTALLER, encoding="utf-8") as fh:
    SOURCE = fh.read()

FAKE_ACCOUNT = "f00dfeedf00dfeedf00dfeedf00dfeed"
FAKE_UUID = "0123abcd-4567-89ef-0123-456789abcdef"
FAKE_SECRET = "FXCPBFAKEsecretNOTREAL0000000000000000000000"
CF_RANGES = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
             "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
             "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13"]


_FUNCTIONS = {}


def extract_function(name):
    """The function's full text: from `name() {` to the first column-0 `}`
    at which the text is complete bash (a `}` inside a heredoc body, such as
    an nginx server block, is not the end). Missing: a stub that fails."""
    if name in _FUNCTIONS:
        return _FUNCTIONS[name]
    m = re.search(rf"^{re.escape(name)}\(\) \{{\n", SOURCE, re.M)
    text = f"{name}() {{ echo 'MISSING FUNCTION {name}' >&2; return 97; }}\n"
    if m:
        for end in re.finditer(r"^\}\n", SOURCE[m.start():], re.M):
            candidate = SOURCE[m.start():m.start() + end.end()]
            check = subprocess.run([BASH, "-n"], input=candidate, capture_output=True, text=True)
            if check.returncode == 0 and "warning" not in check.stderr:
                text = candidate
                break
    _FUNCTIONS[name] = text
    return text


def extract_heredoc(target):
    head = f"cat > {target} <<'EOF'\n"
    start = SOURCE.index(head) + len(head)
    return SOURCE[start:SOURCE.index("\nEOF\n", start) + 1]


def main_py_source():
    head = "cat > \"${APP_DIR}/main.py\" <<'PYEOF'\n"
    start = SOURCE.index(head) + len(head)
    return SOURCE[start:SOURCE.index("\nPYEOF\n", start) + 1]


def rooted(text, prefixes=("/etc/nginx", "/etc/systemd", "/etc/winsvpn", "/etc/cloudflared",
                           "/var/www", "/root/.config")):
    """Redirect absolute paths into ${ROOT}. The nginx include regex keeps its
    literal /etc path (it matches file content, not a path it opens)."""
    keep = "'^[[:space:]]*include[[:space:]]+/etc/nginx/conf"
    text = text.replace(keep, "'^[[:space:]]*include[[:space:]]+/XKEEPX/nginx/conf")
    for prefix in prefixes:
        text = text.replace(prefix, "${ROOT}" + prefix)
    return text.replace("/XKEEPX/nginx/conf", "/etc/nginx/conf")


COMMON = r'''
set -Eeuo pipefail
log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err()  { printf '[ERR] %s\n' "$*" >&2; }
rec()  { printf '%s\n' "$*" >> "${ROOT}/calls"; }
# GNU `stat -c` on macOS. Ownership is reported as root (the installer runs as
# root on a hub) unless the path is NONROOT_PATH; the mode is the real one.
stat() {
  if [[ "${1:-}" != "-c" ]]; then command stat "$@"; return; fi
  local fmt="$2" path="$3" mode uid=0
  mode="$(command stat -f '%Lp' "${path}")" || return 1
  [[ -n "${NONROOT_PATH:-}" && "${path}" == "${NONROOT_PATH}" ]] && uid=1000
  fmt="${fmt//%u/${uid}}"; fmt="${fmt//%g/0}"; fmt="${fmt//%a/${mode}}"
  printf '%s\n' "${fmt}"
}
'''


def run_bash(script, env_extra, root):
    env = {"PATH": os.environ.get("PATH", ""), "ROOT": root, "LC_ALL": "C", "HOME": root}
    env.update({k: str(v) for k, v in env_extra.items()})
    path = os.path.join(root, "harness.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
    p = subprocess.run([BASH, path], env=env, capture_output=True, text=True, timeout=120)
    calls_path = os.path.join(root, "calls")
    calls = []
    if os.path.exists(calls_path):
        with open(calls_path, encoding="utf-8") as fh:
            calls = fh.read().splitlines()
        os.remove(calls_path)
    return p.returncode, p.stdout + p.stderr, calls


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)


class TempRoot(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fxcpb-")

    def tearDown(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in dirnames + filenames:
                try:
                    os.chmod(os.path.join(dirpath, name), 0o700, follow_symlinks=False)
                except (OSError, NotImplementedError):
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def p(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))


# ============================ IA-CP-08 / 10 / 12 ===========================

NGINX_FUNCS = ["wins_files_digest", "wins_restart_if_changed", "wins_nginx_rendered_paths", "wins_nginx_config_digest",
               "wins_nginx_snapshot", "wins_nginx_restore", "write_nginx"]
NGINX_STUBS = r'''
ensure_hub_origin_cert() { :; }
nginx() { rec "nginx $*"; return "${NGINX_T_RC:-0}"; }
systemctl() {
  rec "systemctl $*"
  if [[ "$1" == "restart" ]]; then return "${RESTART_RC:-0}"; fi
}
cloudflare_origin_ipv4_ranges() {
  [[ -z "${CF_FAIL:-}" ]] || return 1
  printf '%s\n' ${CF_RANGES}
}
HUB_DOMAIN=hub.example.test
SYNC_DOMAINS=(sync.example.test)
WEBSITE_TLS_DOMAINS=(www.example.test)
IONOS_HUB_IP=198.51.100.1
HIDE_CONTROL_ORIGIN_DEFAULT=1
CONTROL_DIRECT_CLOUDFLARE_ONLY_DEFAULT=1
'''
NGINX_CONF = ("user www-data;\nworker_processes 2;\nevents {\n    worker_connections 768;\n}\n"
              "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")


class WriteNginxTests(TempRoot):
    def setUp(self):
        super().setUp()
        for d in ("etc/nginx/conf.d", "etc/nginx/sites-available", "etc/nginx/sites-enabled",
                  "etc/winsvpn/tls"):
            os.makedirs(self.p(d), exist_ok=True)
        write(self.p("etc/nginx/nginx.conf"), NGINX_CONF)
        write(self.p("etc/nginx/sites-enabled/default"), "server { listen 80; }\n")
        write(self.p("etc/winsvpn/tls/hub-origin.crt"), "CERT-A\n")
        write(self.p("etc/winsvpn/tls/hub-origin.key"), "KEY-A\n", 0o600)

    def run_nginx(self, **env):
        funcs = "".join(rooted(extract_function(n)) for n in NGINX_FUNCS)
        script = COMMON + NGINX_STUBS + funcs + "\nwrite_nginx\n"
        base = {"NGINX_SITE": self.p("etc/nginx/sites-available/wins-hub.conf"),
                "WINS_NGINX_MAIN_CONFIG": self.p("etc/nginx/nginx.conf"),
                "WEBSITE_TLS_CERT": self.p("etc/winsvpn/tls/website.crt"),
                "WEBSITE_TLS_KEY": self.p("etc/winsvpn/tls/website.key"),
                "HIDE_CONTROL_ORIGIN": "1", "CF_RANGES": " ".join(CF_RANGES),
                "WINSVPN_DEPLOY_STATE_DIR": self.p("var/lib/winsvpn-deployment")}
        base.update(env)
        return run_bash(script, base, self.root)

    def rendered(self):
        out = {}
        for rel in ("etc/nginx/nginx.conf", "etc/nginx/snippets/wins-hub-locations.conf",
                    "etc/nginx/snippets/wins-hub-proxy-common.conf",
                    "etc/nginx/conf.d/wins-realip.conf", "etc/nginx/conf.d/wins-edge-ratelimit.conf",
                    "etc/nginx/sites-available/wins-hub.conf",
                    "etc/systemd/system/nginx.service.d/30-wins-performance.conf"):
            path = self.p(rel)
            out[rel] = read(path) if os.path.exists(path) else None
        out["sites-enabled/default"] = os.path.lexists(self.p("etc/nginx/sites-enabled/default"))
        link = self.p("etc/nginx/sites-enabled/wins-hub.conf")
        out["sites-enabled/wins-hub.conf"] = os.readlink(link) if os.path.islink(link) else None
        return out

    # --- IA-CP-08 ---------------------------------------------------------
    def test_first_run_restarts_and_an_identical_rerun_does_not(self):
        rc, out, calls = self.run_nginx()
        self.assertEqual(rc, 0, out)
        self.assertIn("systemctl restart nginx", calls)
        rc, out, calls = self.run_nginx()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("systemctl restart nginx", calls, "unchanged rerun restarted nginx")
        self.assertIn("systemctl enable --now nginx", calls, "nginx must still be enabled/started")

    def test_a_changed_setting_restarts(self):
        self.assertEqual(self.run_nginx()[0], 0)
        rc, out, calls = self.run_nginx(NGINX_WORKER_CONNECTIONS="4096")
        self.assertEqual(rc, 0, out)
        self.assertIn("systemctl restart nginx", calls)

    def test_a_rotated_origin_certificate_restarts(self):
        self.assertEqual(self.run_nginx()[0], 0)
        write(self.p("etc/winsvpn/tls/hub-origin.crt"), "CERT-B\n")
        rc, out, calls = self.run_nginx()
        self.assertEqual(rc, 0, out)
        self.assertIn("systemctl restart nginx", calls)

    def test_a_restart_that_failed_is_retried_on_the_next_run(self):
        rc, _, calls = self.run_nginx(RESTART_RC="1")
        self.assertNotEqual(rc, 0)
        self.assertIn("systemctl restart nginx", calls)
        rc, out, calls = self.run_nginx()
        self.assertEqual(rc, 0, out)
        self.assertIn("systemctl restart nginx", calls, "a failed restart was recorded as applied")

    def test_a_rejected_config_is_rolled_back_and_nginx_is_not_restarted(self):
        self.assertEqual(self.run_nginx()[0], 0)
        good = self.rendered()
        rc, out, calls = self.run_nginx(NGINX_T_RC="1", NGINX_WORKER_CONNECTIONS="4096",
                                        HIDE_CONTROL_ORIGIN="0")
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.rendered(), good, "rejected configuration left on disk")
        self.assertFalse([c for c in calls if c.startswith("systemctl")], calls)

    def test_a_rejected_first_install_leaves_the_host_as_it_was(self):
        rc, out, calls = self.run_nginx(NGINX_T_RC="1")
        self.assertNotEqual(rc, 0, out)
        state = self.rendered()
        self.assertEqual(state["etc/nginx/nginx.conf"], NGINX_CONF)
        for rel in ("etc/nginx/snippets/wins-hub-locations.conf", "etc/nginx/conf.d/wins-realip.conf",
                    "etc/nginx/sites-available/wins-hub.conf"):
            self.assertIsNone(state[rel], f"{rel} survived a rejected install")
        self.assertTrue(state["sites-enabled/default"], "default site was not restored")
        self.assertIsNone(state["sites-enabled/wins-hub.conf"])

    # --- IA-CP-10 ---------------------------------------------------------
    def realip_sources(self):
        return re.findall(r"^set_real_ip_from (\S+);$", read(self.p("etc/nginx/conf.d/wins-realip.conf")), re.M)

    def test_direct_origin_trusts_the_cloudflare_ranges(self):
        rc, out, _ = self.run_nginx(HIDE_CONTROL_ORIGIN="0")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.realip_sources(), ["127.0.0.1/32", "::1/128"] + CF_RANGES)
        self.assertIn("real_ip_header CF-Connecting-IP;", read(self.p("etc/nginx/conf.d/wins-realip.conf")))

    def test_hidden_origin_trusts_loopback_only(self):
        rc, out, _ = self.run_nginx(HIDE_CONTROL_ORIGIN="1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.realip_sources(), ["127.0.0.1/32", "::1/128"])

    def test_cloudflare_only_direct_origin_refuses_without_the_ranges(self):
        rc, out, _ = self.run_nginx(HIDE_CONTROL_ORIGIN="0", CF_FAIL="1",
                                    CONTROL_DIRECT_CLOUDFLARE_ONLY="1")
        self.assertNotEqual(rc, 0, out)
        self.assertFalse(os.path.exists(self.p("etc/nginx/conf.d/wins-realip.conf")))
        self.assertEqual(read(self.p("etc/nginx/nginx.conf")), NGINX_CONF)

    def test_open_direct_origin_falls_back_to_loopback_when_the_fetch_fails(self):
        rc, out, _ = self.run_nginx(HIDE_CONTROL_ORIGIN="0", CF_FAIL="1",
                                    CONTROL_DIRECT_CLOUDFLARE_ONLY="0")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.realip_sources(), ["127.0.0.1/32", "::1/128"])

    # --- IA-CP-12 ---------------------------------------------------------
    def test_referral_routes_are_proxied_to_the_hub(self):
        self.assertEqual(self.run_nginx()[0], 0)
        locations = read(self.p("etc/nginx/snippets/wins-hub-locations.conf"))
        catch_all = locations.index("location / {")
        for prefix in ("/ref/", "/referral/"):
            m = re.search(r"^location " + re.escape(prefix) + r" \{\n(.*?)\n\}$", locations, re.S | re.M)
            self.assertIsNotNone(m, f"no nginx location for {prefix}")
            self.assertIn("proxy_pass http://127.0.0.1:8000;", m.group(1))
            self.assertIn("wins-hub-proxy-common.conf", m.group(1))
            self.assertLess(m.start(), catch_all)
        hub = main_py_source()
        self.assertIn('@app.get("/ref/{referral_code}")', hub)
        self.assertIn('@app.get("/referral/{referral_code}")', hub)


# ============================== IA-CP-08 tunnel =============================

TUNNEL_STUBS = r'''
valid_dns_hostname() { return 0; }
install_cloudflared_package() { :; }
id() { return 0; }
useradd() { :; }
chown() { :; }
install() {
  while (($#)); do
    case "$1" in -o|-g|-m) shift 2 ;; -d) shift ;; *) mkdir -p "$1"; shift ;; esac
  done
}
systemd-analyze() { :; }
systemctl() { rec "systemctl $*"; }
curl_bearer() {
  local args="$*"
  case "${args}" in
    *"/configurations"*) printf '{"success":true}' ;;
    *"/token"*) printf '{"success":true,"result":"%s"}' "${FAKE_TUNNEL_TOKEN}" ;;
    *) printf '{"success":true,"result":[{"id":"%s","name":"%s","deleted_at":null}]}' "${FAKE_TUNNEL_ID}" "${CONTROL_TUNNEL_NAME_DEFAULT}" ;;
  esac
}
'''


class ControlTunnelRestartTests(TempRoot):
    def run_tunnel(self, token):
        funcs = "".join(rooted(extract_function(n)) for n in (
            "wins_files_digest", "wins_restart_if_changed", "configure_control_origin_tunnel"))
        script = COMMON + TUNNEL_STUBS + funcs + "\nconfigure_control_origin_tunnel\n"
        os.makedirs(self.p("etc/systemd/system"), exist_ok=True)
        return run_bash(script, {
            "HIDE_CONTROL_ORIGIN": "1", "CLOUDFLARE_TUNNEL_ACCOUNT_ID": FAKE_ACCOUNT,
            "CLOUDFLARE_TUNNEL_API_TOKEN": "fake-api-token", "CONTROL_TUNNEL_NAME_DEFAULT": "wins-ctl-test",
            "CLOUDFLARE_APPCLOUD_RECORDS_DEFAULT": "", "CLOUDFLARE_WINS_RECORDS_DEFAULT": "hub.example.test",
            "CLOUDFLARE_WINS_COM_RECORDS_DEFAULT": "", "CONTROL_TUNNEL_ID_FILE": self.p("etc/winsvpn/control-tunnel-id"),
            "FAKE_TUNNEL_ID": FAKE_UUID, "FAKE_TUNNEL_TOKEN": token,
            "WINSVPN_DEPLOY_STATE_DIR": self.p("var/lib/winsvpn-deployment"),
        }, self.root)

    def test_the_connector_restarts_only_when_its_token_or_unit_changes(self):
        token_a, token_b = "A" * 120, "B" * 120
        rc, out, calls = self.run_tunnel(token_a)
        self.assertEqual(rc, 0, out)
        self.assertIn("systemctl restart wins-control-tunnel.service", calls)
        rc, out, calls = self.run_tunnel(token_a)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("systemctl restart wins-control-tunnel.service", calls)
        self.assertIn("systemctl enable --now wins-control-tunnel.service", calls)
        rc, out, calls = self.run_tunnel(token_b)
        self.assertEqual(rc, 0, out)
        self.assertIn("systemctl restart wins-control-tunnel.service", calls)


# ================================= IA-CP-09 =================================

ACCESS_STUBS = r'''
cloudflare_access_shell_json() {
  rec "cf $1 $2"
  case "$1 $2" in
    GET*) printf '{"success":true,"result":[{"id":"%s","client_id":"%s","name":"n"}]}' "${FAKE_UUID}" "${TUNNEL_SERVICE_TOKEN_ID}" ;;
    *) printf '{"success":true,"result":{}}' ;;
  esac
}
'''


class AccessTokenEnvTests(TempRoot):
    def test_the_access_token_writer_leaves_one_line_per_key(self):
        env_file, legacy = self.p("root/vpn_auth.env"), self.p("root/vpn_auth/.env")
        base = ("# runtime\nADMIN_TOKEN='x'\nCLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID='%s'\n"
                "TUNNEL_SERVICE_TOKEN_ID='abc.access'\nTUNNEL_SERVICE_TOKEN_SECRET='%s'\nTAIL='y'\n"
                % (FAKE_UUID, FAKE_SECRET))
        write(env_file, base, 0o600)
        write(legacy, base, 0o600)
        funcs = "".join(extract_function(n) for n in (
            "atomic_replace_file", "append_runtime_env_kv", "replace_runtime_env_kv",
            "ensure_cloudflare_access_service_token"))
        script = COMMON + ACCESS_STUBS + funcs + "\nensure_cloudflare_access_service_token\n"
        for _run in range(2):
            rc, out, _ = run_bash(script, {
                "CLOUDFLARE_ACCESS_SERVICE_TOKEN_NAME_DEFAULT": "wins-test",
                "CLOUDFLARE_ACCESS_SERVICE_TOKEN_DURATION_DEFAULT": "8760h",
                "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID_DEFAULT": "", "TUNNEL_SERVICE_TOKEN_ID_DEFAULT": "",
                "TUNNEL_SERVICE_TOKEN_SECRET_DEFAULT": "", "CLOUDFLARE_TUNNEL_ACCOUNT_ID_DEFAULT": "",
                "HIDE_CONTROL_ORIGIN_DEFAULT": "1", "REQUIRE_CLOUDFLARE_ACCESS_DEFAULT": "1",
                "ENV_FILE": env_file, "LEGACY_ENV_FILE": legacy, "HIDE_CONTROL_ORIGIN": "1",
                "REQUIRE_CLOUDFLARE_ACCESS": "1", "CLOUDFLARE_TUNNEL_ACCOUNT_ID": FAKE_ACCOUNT,
                "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID": FAKE_UUID, "FAKE_UUID": FAKE_UUID,
                "TUNNEL_SERVICE_TOKEN_ID": "abc.access", "TUNNEL_SERVICE_TOKEN_SECRET": FAKE_SECRET,
            }, self.root)
            self.assertEqual(rc, 0, out)
        for path in (env_file, legacy):
            text = read(path)
            for key in ("CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID", "TUNNEL_SERVICE_TOKEN_ID",
                        "TUNNEL_SERVICE_TOKEN_SECRET"):
                self.assertEqual(len(re.findall(rf"^{key}=", text, re.M)), 1, f"{key} duplicated in {path}")
            self.assertIn("ADMIN_TOKEN='x'", text)
            self.assertIn("TAIL='y'", text)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_no_deploy_path_appends_to_the_runtime_env(self):
        body = SOURCE.replace(extract_function("append_runtime_env_kv"), "")
        callers = [line for line in body.splitlines()
                   if re.search(r"\bappend_runtime_env_kv\b", line) and not line.lstrip().startswith("#")]
        self.assertEqual(callers, [], "a deploy path still appends duplicate runtime env lines")


# ================================= IA-CP-11 =================================

class HubSshEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(main_py_source())

    def test_every_management_ssh_spawn_passes_a_narrowed_env(self):
        sites, missing = 0, []
        for node in ast.walk(self.tree):
            # A direct subprocess spawn, or the bounded management runner
            # (run_management_ssh_bounded passes env through to subprocess.run).
            spawn = isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Attribute)
                 and node.func.attr in {"run", "Popen", "check_output", "call"}
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess")
                or (isinstance(node.func, ast.Name) and node.func.id == "run_management_ssh_bounded"))
            if not (spawn
                    and node.args and isinstance(node.args[0], ast.Call)
                    and isinstance(node.args[0].func, ast.Name)
                    and node.args[0].func.id in {"node_ssh_command", "core_ssh_command"}):
                continue
            sites += 1
            env = [k for k in node.keywords if k.arg == "env"]
            ok = (env and isinstance(env[0].value, ast.Call) and isinstance(env[0].value.func, ast.Name)
                  and env[0].value.func.id == "management_ssh_env")
            if not ok:
                missing.append(node.lineno)
        self.assertGreaterEqual(sites, 6, "fewer ssh spawn sites than audited; re-audit this test")
        self.assertEqual(missing, [], f"main.py lines spawn ssh with the full hub environment: {missing}")

    def test_the_narrowed_env_keeps_the_access_token_and_drops_hub_secrets(self):
        wanted = [n for n in self.tree.body
                  if (isinstance(n, ast.FunctionDef) and n.name == "management_ssh_env")
                  or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MANAGEMENT_SSH_ENV_KEYS"
                                                        for t in n.targets))]
        self.assertEqual(len(wanted), 2, "management_ssh_env / MANAGEMENT_SSH_ENV_KEYS missing")
        module = ast.Module(body=[ast.parse("import os").body[0]] + wanted, type_ignores=[])
        namespace = {}
        exec(compile(module, "main.py", "exec"), namespace)
        saved = dict(os.environ)
        try:
            os.environ.update({"ADMIN_TOKEN": "admin-secret", "PAYPAL_CLIENT_SECRET": "pp-secret",
                               "REDEMPTION_KEYS": "v1:" + "c" * 64, "TUNNEL_SERVICE_TOKEN_ID": "abc.access",
                               "TUNNEL_SERVICE_TOKEN_SECRET": FAKE_SECRET})
            env = namespace["management_ssh_env"]()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        for leaked in ("ADMIN_TOKEN", "PAYPAL_CLIENT_SECRET", "REDEMPTION_KEYS"):
            self.assertNotIn(leaked, env)
        self.assertEqual(env["TUNNEL_SERVICE_TOKEN_ID"], "abc.access")
        self.assertEqual(env["TUNNEL_SERVICE_TOKEN_SECRET"], FAKE_SECRET)
        self.assertTrue(env.get("PATH"))


# ================================= IA-CP-13 =================================

OLD_RULES = 'alert tcp any any -> any 80 (msg:"old"; sid:1000001; rev:1;)\n'
NEW_RULES = 'alert tcp any any -> any 80 (msg:"new"; sid:1000002; rev:1;)\n'
BAD_RULES = 'drop tcp any any -> any 80 (msg:"bad"; sid:1000003; rev:1;)\n'


class SuricataUpdateTests(TempRoot):
    def setUp(self):
        super().setUp()
        self.rules = self.p("var/lib/suricata/rules")
        os.makedirs(self.rules)
        write(os.path.join(self.rules, "suricata.rules"), OLD_RULES)
        self.bin = self.p("bin")
        os.makedirs(self.bin)
        stubs = {
            "flock": "exit 0",
            "suricata-update": r'''out="${WINS_SURICATA_RULES_DIR}"
while (($#)); do [[ "$1" == "--output" || "$1" == "-o" ]] && { out="$2"; shift; }; shift; done
[[ "${SU_RC:-0}" == 0 ]] || exit "${SU_RC}"
printf '%s' "${FAKE_RULES}" > "${out}/suricata.rules"''',
            "suricata": 'echo "suricata $*" >> "${ROOT}/calls"; exit "${SURICATA_T_RC:-0}"',
            "systemctl": 'echo "systemctl $*" >> "${ROOT}/calls"; exit 0',
            "suricatasc": 'echo "suricatasc $*" >> "${ROOT}/calls"; exit 0',
            "curl": 'echo "curl" >> "${ROOT}/calls"; exit "${HEALTH_RC:-0}"',
            "policy": 'exit "${POLICY_RC:-0}"',
            "sleep": "exit 0",
        }
        for name, body in stubs.items():
            write(os.path.join(self.bin, name), "#!/usr/bin/env bash\n" + body + "\n", 0o755)
        script = extract_heredoc("/usr/local/bin/wins-suricata-update")
        script = script.replace("/run/lock/wins-suricata-update.lock", "${ROOT}/update.lock")
        script = script.replace("/var/lib/suricata/rules", "${WINS_SURICATA_RULES_DIR}")
        self.script = self.p("wins-suricata-update")
        write(self.script, script, 0o700)

    def update(self, rules, **env):
        base = {"PATH": self.bin + os.pathsep + os.environ["PATH"], "ROOT": self.root, "LC_ALL": "C",
                "WINS_SURICATA_RULES_DIR": self.rules, "FAKE_RULES": rules,
                "WINS_SURICATA_ACTION_POLICY_BIN": os.path.join(self.bin, "policy"),
                "WINS_SURICATA_HEALTH_SECONDS": "3"}
        base.update(env)
        p = subprocess.run([BASH, self.script], env=base, capture_output=True, text=True, timeout=60)
        calls = read(self.p("calls")).splitlines() if os.path.exists(self.p("calls")) else []
        if calls:
            os.remove(self.p("calls"))
        return p.returncode, p.stdout + p.stderr, calls

    def active(self):
        return read(os.path.join(self.rules, "suricata.rules"))

    def leftovers(self):
        return [n for n in os.listdir(self.rules) if n.startswith(".wins-staging")]

    def test_a_good_update_is_swapped_in_reloaded_and_the_old_set_kept(self):
        rc, out, calls = self.update(NEW_RULES)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.active(), NEW_RULES)
        self.assertEqual(read(os.path.join(self.rules, "suricata.rules.last-good")), OLD_RULES)
        self.assertIn("suricatasc -c reload-rules", calls)
        self.assertIn("curl", calls, "no health check through nginx after the reload")
        self.assertEqual(self.leftovers(), [])

    def test_a_blocking_action_never_touches_the_active_ruleset(self):
        rc, out, calls = self.update(BAD_RULES)
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.active(), OLD_RULES)
        self.assertNotIn("suricatasc -c reload-rules", calls)
        self.assertEqual(self.leftovers(), [])

    def test_a_failed_download_never_touches_the_active_ruleset(self):
        rc, out, _ = self.update(NEW_RULES, SU_RC="3")
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.active(), OLD_RULES)

    def test_a_config_test_failure_restores_the_last_good_ruleset(self):
        rc, out, _ = self.update(NEW_RULES, SURICATA_T_RC="1")
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.active(), OLD_RULES)

    def test_a_policy_failure_restores_the_last_good_ruleset(self):
        rc, out, _ = self.update(NEW_RULES, POLICY_RC="1")
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.active(), OLD_RULES)

    def test_a_hub_that_stops_answering_after_the_reload_is_rolled_back(self):
        rc, out, calls = self.update(NEW_RULES, HEALTH_RC="7")
        self.assertNotEqual(rc, 0, out)
        self.assertEqual(self.active(), OLD_RULES)
        self.assertGreaterEqual(calls.count("suricatasc -c reload-rules"), 2, "restore was not reloaded")

    def test_an_unchanged_download_does_not_reload(self):
        rc, out, calls = self.update(OLD_RULES)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("suricatasc -c reload-rules", calls)

    def test_the_weekly_maintenance_uses_the_staged_path(self):
        weekly = extract_heredoc("/usr/local/bin/wins-weekly-maintenance")
        self.assertIn("run_step \"Suricata rule update\" /usr/local/bin/wins-suricata-update", weekly)
        self.assertIsNone(re.search(r"^\s*[^#\n]*\bsuricata-update --", weekly, re.M),
                          "weekly maintenance still downloads over the active ruleset")


# ================================= IA-CP-14 =================================

RCLONE_STUBS = r'''
validate_backup_retention_contract() { :; }
validate_backup_encryption_contract() { :; }
backup_encryption_live_check() { :; }
resolve_backup_host_id() { RESOLVED_BACKUP_HOST_ID=hub-test; }
install() { local a; for a in "$@"; do :; done; mkdir -p "${a}"; }
RCLONE_REMOTE_DEFAULT=GoogleDrive_secured
REQUIRE_REMOTE_BACKUP_DEFAULT=0
BACKUP_RETENTION_DAYS_DEFAULT=30
BACKUP_MANIFEST_RETENTION_DAYS_DEFAULT=365
BACKUP_PRUNE_DRY_RUN_DEFAULT=0
REQUIRE_BACKUP_PRUNING_DEFAULT=1
BACKUP_AGE_RECIPIENTS_FILE_DEFAULT=/etc/winsvpn/backup-recipients.age
REQUIRE_BACKUP_ENCRYPTION_DEFAULT=1
LITESTREAM_REPLICA_URL_DEFAULT=''
'''


class LitestreamPruneTests(TempRoot):
    def backup_env_for(self, url):
        script = COMMON + RCLONE_STUBS + rooted(extract_function("configure_rclone_credentials")) \
            + "\nconfigure_rclone_credentials\n"
        env = {"LITESTREAM_REPLICA_URL": url} if url is not None else {}
        rc, out, _ = run_bash(script, env, self.root)
        path = self.p("etc/winsvpn/backup.env")
        return rc, out, (read(path) if os.path.exists(path) else "")

    def test_the_local_replica_directory_reaches_backup_env(self):
        # LSR (2026-10-02): the default is now empty (an off-host sftp://
        # replica must be named), and a remote sftp:// replica, like the
        # retired gs:// one, leaves the local stage-2 directory empty.
        for url, want in ((None, ""),
                          ("file:///srv/litestream/hub", "/srv/litestream/hub"),
                          ("sftp://wins-replica@127.0.0.1:2232/srv/wins-replica/data/hub", "")):
            rc, out, env = self.backup_env_for(url)
            self.assertEqual(rc, 0, out)
            self.assertIn(f"\nWINS_LITESTREAM_REPLICA_DIR={want}\n", "\n" + env)
            os.remove(self.p("etc/winsvpn/backup.env"))

    def test_an_unsafe_local_replica_path_is_refused(self):
        rc, out, _ = self.backup_env_for("/var/backups/lite stream")
        self.assertNotEqual(rc, 0, out)

    def prune(self, files):
        replica = self.p("replica")
        os.makedirs(os.path.join(replica, "ltx", "0"), exist_ok=True)
        import time
        for name, age_days in files.items():
            path = os.path.join(replica, "ltx", "0", name)
            write(path, "ltx")
            stamp = time.time() - age_days * 86400
            os.utime(path, (stamp, stamp))
        write(self.p("backup.env"), f"REQUIRE_REMOTE_BACKUP=0\nBACKUP_RETENTION_DAYS=30\n"
                                    f"WINS_LITESTREAM_REPLICA_DIR={replica}\n", 0o600)
        script = self.p("prune.sh")
        write(script, extract_heredoc("/usr/local/bin/wins-hub-backup-prune"), 0o700)
        env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "WINS_BACKUP_ENV": self.p("backup.env"),
               "WINS_LOCAL_BACKUP_DIR": self.p("local"), "WINS_BACKUP_MANIFEST_DIR": self.p("manifests"),
               "WINS_RCLONE_CONFIG": self.p("no-rclone.conf")}
        p = subprocess.run([BASH, script], env=env, capture_output=True, text=True, timeout=60)
        remaining = sorted(os.listdir(os.path.join(replica, "ltx", "0")))
        return p.returncode, p.stdout + p.stderr, remaining

    def test_the_pruner_reads_the_directory_from_backup_env(self):
        rc, out, remaining = self.prune({"old.ltx": 45, "fresh.ltx": 1})
        self.assertEqual(rc, 0, out)
        self.assertEqual(remaining, ["fresh.ltx"])

    def test_the_pruner_never_deletes_the_whole_history(self):
        rc, out, remaining = self.prune({"old-a.ltx": 45, "old-b.ltx": 60})
        self.assertEqual(rc, 0, out)
        self.assertEqual(remaining, ["old-a.ltx", "old-b.ltx"], out)


# ================================= IA-CP-15 =================================

DNS_STUBS = r'''
curl_bearer() {
  local args="$*"
  case "${args}" in
    *"-X PUT"*) rec "PUT ${args##* -X PUT }"; printf '{"success":true}' ;;
    *"-X POST"*) rec "POST"; printf '{"success":true}' ;;
    *) cat "${FAKE_LIST}" ;;
  esac
}
'''


class DnsUpsertTests(TempRoot):
    def upsert(self, records, record_type):
        listing = self.p("list.json")
        import json
        write(listing, json.dumps({"success": True, "result": records}))
        script = COMMON + DNS_STUBS + extract_function("cloudflare_upsert_dns_record") + \
            f'\ncloudflare_upsert_dns_record tok zone {record_type} hub.example.test target.example.test true\n'
        rc, out, calls = run_bash(script, {"FAKE_LIST": listing}, self.root)
        self.assertEqual(rc, 0, out)
        writes = [c for c in calls if c.startswith(("PUT", "POST"))]
        self.assertEqual(len(writes), 1, calls)
        return writes[0]

    def test_a_same_type_record_is_updated_even_when_it_is_not_first(self):
        call = self.upsert([{"id": "txt1", "type": "TXT"}, {"id": "a1", "type": "A"}], "A")
        self.assertTrue(call.startswith("PUT") and "/a1 " in call + " ", call)

    def test_a_record_of_another_type_is_never_overwritten(self):
        self.assertEqual(self.upsert([{"id": "txt1", "type": "TXT"}], "CNAME"), "POST")
        self.assertEqual(self.upsert([{"id": "txt1", "type": "TXT"}, {"id": "a1", "type": "A"}], "CNAME"), "POST")

    def test_the_a_to_cname_migration_still_updates_in_place(self):
        call = self.upsert([{"id": "a1", "type": "A"}], "CNAME")
        self.assertTrue(call.startswith("PUT") and "/a1 " in call + " ", call)

    def test_no_record_creates(self):
        self.assertEqual(self.upsert([], "A"), "POST")


# ================================= IA-CP-16 =================================

GATE_STUBS = r'''
# BSD find understands -perm /mode. Ancestors outside the private root are the
# test machine's own directories and are treated as clean.
find() {
  # Emulates exactly the two GNU forms the gate uses:
  #   find PATH -maxdepth 0 -perm /MASK -print -quit
  #   find PATH -prune -perm /MASK -print -quit
  local path="$1" mask="" mode
  while (($#)); do [[ "$1" == "-perm" ]] && mask="${2#/}"; shift; done
  [[ "${path}" == "${ROOT}"* && -n "${mask}" ]] || return 0
  mode="$(command stat -f '%Lp' "${path}")"
  (( (8#${mode} & 8#${mask}) != 0 )) && printf '%s\n' "${path}"
  return 0
}
WINS_SECRETS_LOADED=""
'''


class SecretsFileGateTests(TempRoot):
    def overlay(self, path, **env):
        script = COMMON + GATE_STUBS + extract_function("wins_require_trusted_env_file") + \
            extract_function("overlay_wins_secrets_file") + \
            '\nif overlay_wins_secrets_file; then echo "rc=0 loaded=${WINS_SECRETS_LOADED}"; else echo "rc=1 loaded=${WINS_SECRETS_LOADED}"; fi\n'
        env = dict(env, WINS_SECRETS_FILE=path)
        rc, out, _ = run_bash(script, env, self.root)
        m = re.search(r"rc=(\d) loaded=(\S*)", out)
        self.assertIsNotNone(m, out)
        return m.group(1) == "0", m.group(2) == "yes", out

    def secret(self, rel="secure/winsvpn-secrets.env", mode=0o600, dir_mode=0o700):
        path = self.p(rel)
        write(path, "WINS_SECRETS_LOADED=yes\n", mode)
        os.chmod(os.path.dirname(path), dir_mode)
        return path

    def test_a_root_only_file_in_a_private_directory_loads(self):
        ok, loaded, out = self.overlay(self.secret())
        self.assertTrue(ok and loaded, out)

    def test_an_absent_file_is_a_no_op(self):
        ok, loaded, out = self.overlay(self.p("secure/none.env"))
        self.assertTrue(ok, out)
        self.assertFalse(loaded)

    def test_a_symlink_is_refused(self):
        real = self.secret()
        link = self.p("secure/link.env")
        os.symlink(real, link)
        ok, loaded, out = self.overlay(link)
        self.assertFalse(ok, out)
        self.assertFalse(loaded, "secrets were sourced through a symlink")

    def test_a_file_in_a_group_writable_directory_is_refused(self):
        ok, loaded, out = self.overlay(self.secret(dir_mode=0o775))
        self.assertFalse(ok, out)
        self.assertFalse(loaded, "secrets were sourced from a replaceable directory")

    def test_a_loose_mode_or_foreign_owner_is_still_refused(self):
        ok, loaded, out = self.overlay(self.secret(mode=0o644))
        self.assertFalse(ok or loaded, out)
        path = self.secret(rel="secure2/s.env")
        ok, loaded, out = self.overlay(path, NONROOT_PATH=path)
        self.assertFalse(ok or loaded, out)


# ================================= IA-CP-17 =================================

class DurabilityClaimTests(unittest.TestCase):
    def test_the_rpo_zero_claim_names_what_the_barrier_does_not_cover(self):
        block = SOURCE.split("# --- Litestream durability barrier (HANDOFF 3j)", 1)[1].split(
            "LITESTREAM_VERSION_DEFAULT=", 1)[0]
        self.assertNotIn("RPO 0 for acknowledged money/entitlement/identity writes", block)
        for named in ("PayPal", "BTCPay", "Monero", "/verify"):
            self.assertIn(named, block, f"the RPO claim does not say {named} is outside the barrier")
        # Every require_durability_barrier context the claim lists exists in main.py.
        hub = main_py_source()
        for context in ("api-redeem", "api-redeem-ack", "admin-redemption-batch", "admin-redemption-revoke"):
            self.assertIn(f'require_durability_barrier(request, "{context}"', hub)


# ================================= IA-CP-18 =================================

BACKUP_PRE = r'''
set -Eeuo pipefail
umask 077
root_path() { printf '%s/%s' "${SOURCE_ROOT%/}" "$1"; }
PAYLOAD_DIR="${ROOT}/work/payload"
UPLOAD_DIR="${ROOT}/work/upload"
ARCHIVE_TAR="${ROOT}/work/wins-hub-backup.tar"
ARCHIVE="${UPLOAD_DIR}/wins-hub-backup-test.tar.gz"
DB_SOURCE="${SOURCE_ROOT}/root/vpn_auth/vpn_users.db"
DB_SNAPSHOT="${PAYLOAD_DIR}/root/vpn_auth/vpn_users.db"
PREPARED_DB_SNAPSHOT="${ROOT}/none"
LEDGER_SOURCE="${SOURCE_ROOT}/root/vpn_auth/winn3_authority_ledger.db"
LEDGER_SNAPSHOT="${PAYLOAD_DIR}/root/vpn_auth/winn3_authority_ledger.db"
PREPARED_LEDGER_SNAPSHOT="${ROOT}/none-ledger"
install_id=00000000-0000-4000-8000-000000000000
install_epoch=1
BACKUP_EPOCH=2
install -d -m 700 "${PAYLOAD_DIR}" "${UPLOAD_DIR}"
'''

BACKUP_TREE = ["root/vpn_auth/main.py", "root/vpn_auth.env", "etc/nginx/nginx.conf",
               "etc/systemd/system/wins-hub.service", "etc/systemd/system/wins-gateway-canary.service",
               "etc/systemd/system/wins-gateway-canary.timer",
               "etc/systemd/system/wins-security-alert-monitor.service",
               "etc/systemd/system/wins-security-alert-monitor.timer",
               "etc/systemd/system/wins-paypal-sync.service", "etc/systemd/system/wins-paypal-sync.timer",
               "etc/iptables/rules.v4"]


@unittest.skipUnless(GTAR and "GNU" in subprocess.run([GTAR, "--version"], capture_output=True,
                                                     text=True).stdout, "GNU tar is required")
class BackupMembershipTests(TempRoot):
    def setUp(self):
        super().setUp()
        self.src = self.p("src")
        for rel in BACKUP_TREE:
            write(os.path.join(self.src, rel), f"content of {rel}\n", 0o600)
        self.shim = self.p("shim")
        os.makedirs(self.shim)
        os.symlink(GTAR, os.path.join(self.shim, "tar"))

    def backup(self):
        body = extract_heredoc("/usr/local/bin/wins-hub-backup")
        start = body.index("\nsources=(\n") + 1
        end = body.index('tar -tzf "${ARCHIVE}" >/dev/null\n') + len('tar -tzf "${ARCHIVE}" >/dev/null\n')
        # LSR R5: the membership section calls the script's path_kind and
        # kind_or_fail helpers, defined earlier in the script.
        helpers = ""
        if "\nkind_or_fail() {\n" in body:
            k = body.index("\nkind_or_fail() {\n")
            helpers = body[body.index("\npath_kind() {\n") + 1:body.index("\n}\n", k) + 3]
        script = COMMON.replace("set -Eeuo pipefail", "") + BACKUP_PRE + helpers + body[start:end]
        env = {"PATH": self.shim + os.pathsep + os.environ["PATH"], "SOURCE_ROOT": self.src}
        rc, out, _ = run_bash(script, env, self.root)
        members = []
        archive = self.p("work/upload/wins-hub-backup-test.tar.gz")
        if rc == 0 and os.path.exists(archive):
            members = subprocess.run([GTAR, "-tzf", archive], capture_output=True, text=True).stdout.split()
        return rc, out, members

    def test_a_complete_host_archives_every_present_member(self):
        rc, out, members = self.backup()
        self.assertEqual(rc, 0, out)
        for rel in BACKUP_TREE:
            self.assertIn("./" + rel, members)
        self.assertIn("wins-control-tunnel.service", out, "an absent listed source was skipped silently")

    def test_a_missing_restore_critical_member_fails_the_backup(self):
        os.remove(os.path.join(self.src, "root/vpn_auth.env"))
        rc, out, _ = self.backup()
        self.assertNotEqual(rc, 0, "backup succeeded without the runtime env file")
        self.assertIn("root/vpn_auth.env", out)

    def test_a_present_member_tar_could_not_read_fails_the_backup(self):
        if os.geteuid() == 0:
            self.skipTest("root reads mode-000 files")
        os.chmod(os.path.join(self.src, "etc/systemd/system/wins-paypal-sync.timer"), 0)
        rc, out, _ = self.backup()
        self.assertNotEqual(rc, 0, "--ignore-failed-read hid an unreadable member")
        self.assertIn("wins-paypal-sync.timer", out)


# ================================= R1-GLM-2 =================================

class HubReservedPortsTests(TempRoot):
    """R1-GLM-2 (the data plane's Mythos L04 F-1): setup_control_sysctl widens
    the ephemeral range to 1024-65535, so the hub's fixed listeners (the API on
    8000, the site-AI endpoint port, the app-zone tunnel metrics on 20251) are
    reserved in the file systemd-sysctl applies at boot, before this run's own
    `sysctl --system`."""

    RESERVED = "net.ipv4.ip_local_reserved_ports="

    def render(self, **env):
        os.makedirs(self.p("etc/sysctl.d"), exist_ok=True)
        default = re.search(r'^SITE_AI_LOCAL_ENDPOINT_DEFAULT=.*$', SOURCE, re.M).group(0)
        stubs = r'''
sysctl() {
  if [[ "${1:-}" == "--system" ]]; then
    if grep -q '^net.ipv4.ip_local_reserved_ports=' "${ROOT}/etc/sysctl.d/99-winsvpn-hub.conf"; then
      rec "sysctl --system with-reservation"
    else
      rec "sysctl --system without-reservation"
    fi
    return 0
  fi
  rec "sysctl $*"
}
'''
        script = (COMMON + stubs + default + "\n"
                  + rooted(extract_function("setup_control_sysctl"), prefixes=("/etc/sysctl.d",))
                  + "\nsetup_control_sysctl\nsetup_control_sysctl\n")
        rc, out, calls = run_bash(script, env, self.root)
        self.assertEqual(rc, 0, out)
        lines = read(self.p("etc/sysctl.d/99-winsvpn-hub.conf")).splitlines()
        reserved = [line for line in lines if line.startswith(self.RESERVED)]
        self.assertEqual(len(reserved), 1, f"a rerun must rewrite, not repeat, the reservation: {reserved}")
        self.assertIn("net.ipv4.ip_local_port_range=1024 65535", lines)
        self.assertEqual(calls.count("sysctl --system with-reservation"), 2, calls)
        self.assertNotIn("sysctl --system without-reservation", calls)
        return reserved[0][len(self.RESERVED):]

    def test_default_endpoint_reserves_api_site_ai_and_tunnel_metrics(self):
        self.assertEqual(self.render(), "8000,11435,20251")

    def test_reservation_follows_this_runs_site_ai_endpoint(self):
        self.assertEqual(self.render(SITE_AI_LOCAL_ENDPOINT="http://127.0.0.1:11500"), "8000,11500,20251")
        self.assertEqual(self.render(SITE_AI_LOCAL_ENDPOINT="http://127.0.0.1:11500/v1/"), "8000,11500,20251")

    def test_endpoint_without_a_usable_port_falls_back_to_the_default(self):
        for endpoint in ("http://127.0.0.1", "http://127.0.0.1:99999", "http://127.0.0.1:0"):
            self.assertEqual(self.render(SITE_AI_LOCAL_ENDPOINT=endpoint), "8000,11435,20251", endpoint)

    def test_rerun_reserves_the_endpoint_the_runtime_env_file_keeps(self):
        """A1-ARGON-F2: setup_control_sysctl runs before write_env, and write_env
        keeps ${ENV_FILE}'s SITE_AI_LOCAL_ENDPOINT when this run supplies none.
        The reservation must follow that file, and a value this run supplies
        still wins."""
        env_file = self.p("root/vpn_auth.env")
        write(env_file, "SITE_AI_LOCAL_ENDPOINT='http://127.0.0.1:11500'\n", mode=0o600)
        self.assertEqual(self.render(ENV_FILE=env_file), "8000,11500,20251")
        self.assertEqual(self.render(ENV_FILE=env_file, SITE_AI_LOCAL_ENDPOINT="http://127.0.0.1:11600"),
                         "8000,11600,20251")
        self.assertEqual(self.render(ENV_FILE=self.p("root/absent.env")), "8000,11435,20251")
        write(env_file, "SITE_AI_LOCAL_ENDPOINT='http://127.0.0.1'\n", mode=0o600)
        self.assertEqual(self.render(ENV_FILE=env_file), "8000,11435,20251")


class ControlIdsRewriteFailureTests(TempRoot):
    """A1-ARGON-F1 on the control plane (the data-plane and Core twins):
    install_control_ids_ips takes the CP-6 snapshot and then rewrites
    suricata.yaml. A rewrite that fails part way must put the last-good set
    back and leave no snapshot directory, as every later refusal does. The
    function runs up to its first write after the rewrite (the local rules);
    python3 is a double that writes and then returns PYTHON_RC."""

    OLD_CONFIG = "vars:\n  address-groups: {}\nlast-good: config\n"
    OLD_LOCAL = "drop http any any -> any any (msg:\"old\"; sid:9900001; rev:1;)\n"
    CUT = "  cat > /etc/suricata/disable.conf <<'EOF'\n"

    def run_install(self, python_rc):
        os.makedirs(self.p("etc/suricata"), exist_ok=True)
        os.makedirs(self.p("var/lib/suricata/rules"), exist_ok=True)
        os.makedirs(self.p("run"), exist_ok=True)
        os.makedirs(self.p("usr/local/bin"), exist_ok=True)
        write(self.p("etc/suricata/suricata.yaml"), self.OLD_CONFIG)
        write(self.p("var/lib/suricata/rules/wins-local.rules"), self.OLD_LOCAL)
        body = extract_function("install_control_ids_ips")
        self.assertIn(self.CUT, body)
        body = body[:body.index(self.CUT)] + '  echo "REACHED local rules"\n}\n'
        prefixes = ("/etc/suricata", "/var/lib/suricata", "/etc/fail2ban", "/run/wins-suricata-deploy",
                    "/usr/local/bin")
        script = (COMMON
                  + 'ip() { :; }\n'
                  + 'python3() { cat >/dev/null; printf "%s\\n" "vars: {}" "rewritten: config" > "$2"; return "${PYTHON_RC}"; }\n'
                  + "IONOS_HUB_IP=198.51.100.1\nHIDE_CONTROL_ORIGIN_DEFAULT=1\nCONTROL_DIRECT_CLOUDFLARE_ONLY_DEFAULT=1\n"
                  + self.pair()
                  + rooted(body, prefixes=prefixes)
                  + "install_control_ids_ips\n")
        return run_bash(script, {"PYTHON_RC": python_rc}, self.root)

    @staticmethod
    def pair():
        """suricata_deploy_snapshot and _restore; their opening lines carry a
        usage comment, so extract_function's `name() {` match does not apply."""
        out = ""
        for name in ("suricata_deploy_snapshot", "suricata_deploy_restore"):
            m = re.search(r"^" + name + r"\(\) \{ #.*?^\}\n", SOURCE, re.M | re.S)
            out += m.group(0) if m else f"{name}() {{ return 97; }}\n"
        return out

    def leftovers(self):
        return sorted(name for name in os.listdir(self.p("run")) if name.startswith("wins-suricata-deploy."))

    def test_failed_rewrite_puts_the_last_good_set_back(self):
        rc, out, _ = self.run_install(1)
        self.assertNotEqual(rc, 0, out)
        self.assertNotIn("REACHED", out)
        self.assertEqual(read(self.p("etc/suricata/suricata.yaml")), self.OLD_CONFIG,
                         "a partly rewritten suricata.yaml stayed after the rewrite failed")
        self.assertEqual(read(self.p("var/lib/suricata/rules/wins-local.rules")), self.OLD_LOCAL)
        self.assertFalse(os.path.exists(self.p("var/lib/suricata/rules/suricata.rules")))
        self.assertEqual(self.leftovers(), [])

    def test_successful_rewrite_continues(self):
        rc, out, _ = self.run_install(0)
        self.assertEqual(rc, 0, out)
        self.assertIn("REACHED local rules", out)
        self.assertIn("rewritten: config", read(self.p("etc/suricata/suricata.yaml")))
        self.assertIn("sid:9900001; rev:2;", read(self.p("var/lib/suricata/rules/wins-local.rules")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
