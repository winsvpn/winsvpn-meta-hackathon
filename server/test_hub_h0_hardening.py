#!/usr/bin/env python3
"""H0 hub hardening, design v17 sections 3.2, 3.3 and 5.2: requirements D1 to D8.

Every requirement has one check, check_d1 .. check_d8, that is a pure function
of the control-plane installer text as shipped: unit-text assertions over the
units it renders, static assertions over the embedded hub app, and (D7) the
installer's own env loader run under bash against a planted payload. Each
check returns the list of its failures, so the mutant test applies one
mutation per requirement (design 5.6, "one mutant per H0 requirement D1 to
D8") and asserts that the check for that requirement reports it.

Behavioural tests drive the real hub app and the real SPA helper extracted
from the installer. What needs a real systemd sandbox (connect() to each broker
socket, a transient unit, a write into root's SSH directory, an iptables write
from the app context) is test_hub_h0_sandbox_tier_a.sh, run on Tier A.
"""
import _toolchain  # noqa: F401
import ast
import base64
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness

INSTALLER = Path(__file__).resolve().parent / "wins_control_plane_setup_ONETOUCH.sh"
SOURCE = INSTALLER.read_text(encoding="utf-8")

HUB_UNIT = 'cat > "${SERVICE_FILE}" <<EOF'
SPA_UNIT = "cat > /etc/systemd/system/wins-hub-spa-window.service <<'EOF'"
PROBE_UNIT = "cat > /etc/systemd/system/wins-dataplane-probe.service <<'EOF'"
CANARY_UNIT = "cat > /etc/systemd/system/wins-gateway-canary.service <<'EOF'"
LOGROTATE_UNIT = "cat > /etc/systemd/system/wins-hub-logrotate.service <<'EOF'"
SUPPORTING_UNITS = (SPA_UNIT, PROBE_UNIT, CANARY_UNIT, LOGROTATE_UNIT)
SPA_HELPER = "cat > /usr/local/lib/wins_hub_spa_window.py <<'SPAWINDOWEOF'"
PROBE_SCRIPT = "cat > /usr/local/lib/wins_node_dataplane_probe.py <<'DPPROBEEOF'"
MAIN_PY = "cat > \"${APP_DIR}/main.py\" <<'PYEOF'"
TMPFILES = "cat > /etc/tmpfiles.d/wins-hub-runtime.conf <<'EOF'"

# D2: the only runtime paths the hub binds back into its empty /run.
HUB_RUNTIME_ALLOW_LIST = {
    "/run/litestream",
    "/run/wins-hub-spa-window",
    # H1 (3.4): the descriptor signer's socket directory. The signer itself
    # admits only a uid 0 peer in the wins-hub.service cgroup.
    "/run/wins-descriptor-signer",
    "-/run/systemd/resolve/stub-resolv.conf",
    "-/run/systemd/resolve/resolv.conf",
}
# D5: where a supporting unit may execute from. Each is root-owned on Ubuntu
# and outside every path the hub unit can write.
ROOT_OWNED_EXEC_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/")
SANDBOX_PROFILE = {
    "NoNewPrivileges": {"true"},
    "ProtectSystem": {"strict"},
    "ProtectHome": {"true", "yes", "read-only"},
    "PrivateTmp": {"true"},
    "PrivateDevices": {"true"},
    "ProtectKernelTunables": {"true"},
    "ProtectKernelModules": {"true"},
    "ProtectControlGroups": {"true"},
    "RestrictSUIDSGID": {"true"},
    "RestrictNamespaces": {"true"},
    "LockPersonality": {"true"},
}
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload", "ExecCondition")


# ------------------------------------------------------------- text helpers --

def heredoc(source, header):
    """Body of the heredoc whose opening line is exactly `header`."""
    tag = re.search(r"<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?$", header).group(1)
    start = source.index(header + "\n") + len(header) + 1
    end = source.index("\n" + tag + "\n", start - 1)
    return source[start:end + 1]


def function_body(source, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n(.*?)^\}\n", source, re.S | re.M)
    if not match:
        raise AssertionError(f"{name}() not found")
    return match.group(0)


def file_top(source, name):
    return re.search(r"^" + name + r'="([^"]*)"$', source, re.M).group(1)


def render(source, text):
    """Substitute the installer's own file-top values into an unquoted heredoc."""
    app_dir = file_top(source, "APP_DIR")
    values = {
        "APP_DIR": app_dir,
        "ENV_FILE": file_top(source, "ENV_FILE"),
        "LEGACY_ENV_FILE": app_dir + "/.env",
        "VENV_DIR": app_dir + "/venv",
        "bind_host": "127.0.0.1",
    }
    return re.sub(r"\$\{([A-Za-z_]+)\}", lambda m: values.get(m.group(1), m.group(0)), text)


def unit(source, header):
    """{key: [values]} over every section of one rendered unit; comments dropped."""
    parsed = {}
    for line in render(source, heredoc(source, header)).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        parsed.setdefault(key, []).append(value)
    return parsed


def words(entries):
    return [word for entry in entries for word in entry.split()]


def hub_writable_paths(source):
    return [path.lstrip("-") for path in words(unit(source, HUB_UNIT).get("ReadWritePaths", []))]


def under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def main_py(source):
    return heredoc(source, MAIN_PY)


def python_function(python_source, name):
    """The text of one top-level def, up to the next top-level def."""
    return re.search(r"^def " + name + r"\(.*?(?=^def |^@app\.)", python_source, re.S | re.M).group(0)


def string_constants(python_source):
    return [node.value for node in ast.walk(ast.parse(python_source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def sandbox_failures(name, parsed, capabilities):
    failures = []
    for key, accepted in SANDBOX_PROFILE.items():
        if parsed.get(key, [None])[-1] not in accepted:
            failures.append(f"{name}: {key} is {parsed.get(key)}, expected one of {sorted(accepted)}")
    if parsed.get("CapabilityBoundingSet") != [capabilities]:
        failures.append(f"{name}: CapabilityBoundingSet is {parsed.get('CapabilityBoundingSet')}, expected [{capabilities!r}]")
    if parsed.get("AmbientCapabilities") != [""]:
        failures.append(f"{name}: AmbientCapabilities is {parsed.get('AmbientCapabilities')}, expected empty")
    return failures


def exec_failures(source, name, parsed):
    """Every executed path is root-owned and outside the hub's writable set."""
    failures = []
    writable = hub_writable_paths(source)
    for key in EXEC_KEYS:
        for value in parsed.get(key, []):
            argv = value.lstrip("-+!@:").split()
            if not argv:
                continue  # an empty ExecStart= only resets the list
            paths = [argv[0]]
            if os.path.basename(argv[0]).startswith("python"):
                if "-I" not in argv:
                    failures.append(f"{name}: {key} runs Python without -I: {value}")
                paths += [arg for arg in argv[1:] if arg.startswith("/")]
            for path in paths:
                if not path.startswith(ROOT_OWNED_EXEC_PREFIXES):
                    failures.append(f"{name}: {key} executes {path}, not a root-owned path")
                if any(under(path, root) for root in writable):
                    failures.append(f"{name}: {key} executes {path}, which the hub app can write")
    for directory in parsed.get("WorkingDirectory", []):
        if any(under(directory, root) for root in writable):
            failures.append(f"{name}: WorkingDirectory {directory} is app-writable")
    return failures


# ------------------------------------------------------------------- checks --

def check_d1(source):
    """D1: the app cannot reach the service manager; the SPA window is a helper's."""
    failures = []
    hub = unit(source, HUB_UNIT)
    if hub.get("TemporaryFileSystem") != ["/run:ro"]:
        failures.append(f"hub unit TemporaryFileSystem is {hub.get('TemporaryFileSystem')}, expected ['/run:ro']")
    for path in words(hub.get("BindReadOnlyPaths", []) + hub.get("BindPaths", [])):
        bare = path.lstrip("-").split(":")[0]
        resolver_file = under(bare, "/run/systemd/resolve") and bare.endswith(".conf")
        if under(bare, "/run/dbus") or (under(bare, "/run/systemd") and not resolver_file):
            failures.append(f"hub unit binds {bare}, a service-manager or bus endpoint")
    forbidden = {"systemd-run", "systemctl", "busctl", "dbus-send", "gdbus", "loginctl"}
    for value in string_constants(main_py(source)):
        if value in forbidden:
            failures.append(f"hub app names the service-manager client {value!r}")
    spa = python_function(main_py(source), "open_spa_window")
    if "subprocess" in spa or "SPA_WINDOW_HELPER_SOCKET" not in spa:
        failures.append("open_spa_window does not go through the SPA helper socket only")
    if heredoc(source, SPA_HELPER).count("def open_window(") != 1:
        failures.append("the SPA helper program is missing")
    return failures


def check_d2(source):
    """D2: the hub's /run holds exactly the allow-listed runtime endpoints."""
    failures = []
    hub = unit(source, HUB_UNIT)
    if hub.get("TemporaryFileSystem") != ["/run:ro"]:
        failures.append("hub unit does not replace /run with an empty read-only tmpfs")
    bound = set(words(hub.get("BindReadOnlyPaths", [])))
    if bound != HUB_RUNTIME_ALLOW_LIST:
        failures.append(f"hub unit runtime allow-list is {sorted(bound)}, expected {sorted(HUB_RUNTIME_ALLOW_LIST)}")
    if hub.get("BindPaths"):
        failures.append(f"hub unit binds a writable path: {hub['BindPaths']}")
    for path in hub_writable_paths(source):
        if under(path, "/run") or under(path, "/var/run"):
            failures.append(f"hub unit can write {path} under the runtime directory")
    tmpfiles = heredoc(source, TMPFILES)
    for directory in ("/run/litestream", "/run/wins-hub-spa-window"):
        if not re.search(r"^d " + re.escape(directory) + r" ", tmpfiles, re.M):
            failures.append(f"{directory} is not created at boot, so its bind can be skipped")
    if "path: /run/litestream/litestream.sock" not in source:
        failures.append("the Litestream control socket is outside its allow-listed directory")
    if 'SPA_WINDOW_HELPER_SOCKET = "/run/wins-hub-spa-window/sock"' not in main_py(source):
        failures.append("the SPA helper socket is outside its allow-listed directory")
    return failures


def check_d3(source):
    """D3: no root login key or hook is writable; the hub is never a node."""
    failures = []
    for path in hub_writable_paths(source):
        if path in ("/root", "/root/") or under(path, "/root/.ssh") or under("/root/.ssh", path):
            failures.append(f"hub unit can write root's SSH material through {path}")
    if "/var/lib/wins-hub-ssh" not in hub_writable_paths(source):
        failures.append("the app's own SSH working directory is not in its writable set")
    app = main_py(source)
    for value in string_constants(app):
        if value.startswith("/root/.ssh") and value not in ("/root/.ssh/id_rsa", "/root/.ssh/id_rsa.pub"):
            failures.append(f"hub app names {value!r} under root's SSH directory")
    if 'HUB_MANAGEMENT_SSH_CONTROL_DIR = "/var/lib/wins-hub-ssh/cm"' not in app:
        failures.append("the ControlMaster directory is not the app's own")
    tree = ast.parse(app)
    for node in ast.walk(tree):
        if isinstance(node, ast.List) and len(node.elts) >= 2 and all(isinstance(e, ast.Constant) for e in node.elts[:2]) \
                and [e.value for e in node.elts[:2]] == ["bash", "-lc"]:
            failures.append(f"hub app runs a management command locally (line {node.lineno})")
    ssh = python_function(app, "node_ssh_command")
    if "refuse_hub_as_data_plane_node(host)" not in ssh:
        failures.append("node_ssh_command does not refuse this hub by name")
    if '"/var/lib/wins-site-ai-tunnel/authorized_keys"' not in app or 'SITE_AI_TUNNEL_SSH_USER = "wins-site-ai"' not in app:
        failures.append("the site-AI tunnel key is not written to the non-root forwarding account")
    for phase in ("preflight_control", "postflight_control"):
        if "refuse_hub_keys_authorized_for_root_here" not in function_body(source, phase):
            failures.append(f"{phase} does not reject hub key root authorization")
    sshd = function_body(source, "harden_control_sshd")
    for needed in ("PermitUserRC no", "PermitUserEnvironment no",
                   'sshd_effective_value_is "${effective}" permituserrc "no"',
                   'sshd_effective_value_is "${effective}" permituserenvironment "no"'):
        if needed not in sshd:
            failures.append(f"hub sshd policy lacks {needed!r}")
    block = re.search(r"^Match User wins-site-ai\n(.*?)^Match all$", sshd, re.S | re.M)
    if not block:
        failures.append("hub sshd policy has no Match block for the site-AI forwarding account")
    else:
        for needed in ("AuthorizedKeysFile /var/lib/wins-site-ai-tunnel/authorized_keys",
                       "ForceCommand /usr/sbin/nologin", "PermitTTY no", "AllowTcpForwarding remote"):
            if needed not in block.group(1):
                failures.append(f"site-AI Match block lacks {needed!r}")
        failures += recovery_expiry_failures(source, block.group(0) + "\n")
    return failures


def recovery_expiry_failures(source, site_ai_block):
    """The recovery-expiry helper strips only the recovery Match block."""
    helper = heredoc(source, "  cat > \"${ssh_recovery_disable_helper}\" <<'EOF'".strip())
    line = next(l for l in helper.splitlines() if l.lstrip().startswith("awk '") and "Match" in l)
    program = line.split("'")[1]
    config = ("Port 22\nUsePAM yes\n" + site_ai_block +
              "Match User recovery Address 203.0.113.4/32\n    PasswordAuthentication yes\nMatch all\n")
    kept = subprocess.run(["awk", program], input=config, capture_output=True, text=True, timeout=10).stdout
    failures = []
    if site_ai_block not in kept:
        failures.append("the recovery-expiry helper strips the site-AI forwarding account's Match block")
    if "PasswordAuthentication yes" in kept:
        failures.append("the recovery-expiry helper leaves the recovery Match block in place")
    return failures


def check_d4(source):
    """D4: the hub unit holds no capability."""
    failures = []
    hub = unit(source, HUB_UNIT)
    if hub.get("CapabilityBoundingSet") != [""]:
        failures.append(f"hub unit CapabilityBoundingSet is {hub.get('CapabilityBoundingSet')}, expected empty")
    if hub.get("AmbientCapabilities") != [""]:
        failures.append(f"hub unit AmbientCapabilities is {hub.get('AmbientCapabilities')}, expected empty")
    for value in string_constants(main_py(source)):
        if value in {"iptables", "ip6tables", "nft", "iptables-restore"}:
            failures.append(f"hub app still invokes the firewall tool {value!r}")
    if unit(source, SPA_UNIT).get("CapabilityBoundingSet") != ["CAP_NET_ADMIN"]:
        failures.append("the SPA helper's capability set is not exactly CAP_NET_ADMIN")
    return failures


def check_d5(source):
    """D5: supporting units run only root-owned paths, under a sandbox profile."""
    failures = []
    capabilities = {SPA_UNIT: "CAP_NET_ADMIN"}
    for header in SUPPORTING_UNITS:
        parsed = unit(source, header)
        name = header.split("/")[-1].split()[0]
        failures += sandbox_failures(name, parsed, capabilities.get(header, ""))
        failures += exec_failures(source, name, parsed)
    for program in ("/usr/local/lib/wins_hub_spa_window.py", "/usr/local/lib/wins_node_dataplane_probe.py"):
        if f"chown root:root {program}" not in source or f"chmod 0644 {program}" not in source:
            failures.append(f"{program} is not installed root-owned 0644")
    # No rendered unit but the hub's own executes anything the hub can write.
    for header in re.findall(r"^\s*((?:cat >|install_generated_file [0-7]{3,4}) /etc/systemd/system/\S+ <<'?EOF'?)$",
                             source, re.M):
        failures += [f for f in exec_failures(source, header.split("/")[-1].split()[0], unit(source, header.strip()))
                     if "app-writable" in f or "which the hub app can write" in f]
    return failures


def check_d6(source):
    """D6: the probe timer runs a root-owned script, isolated, sandboxed."""
    failures = []
    parsed = unit(source, PROBE_UNIT)
    if parsed.get("ExecStart") != ["/usr/bin/python3 -I /usr/local/lib/wins_node_dataplane_probe.py"]:
        failures.append(f"probe ExecStart is {parsed.get('ExecStart')}")
    failures += sandbox_failures("wins-dataplane-probe.service", parsed, "")
    failures += exec_failures(source, "wins-dataplane-probe.service", parsed)
    if '"${APP_DIR}/wins_node_dataplane_probe.py" <<' in source:
        failures.append("the probe is still written into the app directory")
    probe = heredoc(source, PROBE_SCRIPT)
    imported = set()
    for node in ast.walk(ast.parse(probe)):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add(node.module.split(".")[0])
    outside = sorted(imported - set(sys.stdlib_module_names) - {"__future__"})
    if outside:
        failures.append(f"the probe imports non-standard modules {outside}, so the system interpreter cannot run it")
    return failures


D7_SENTINELS = ("PWNED_SUBST", "PWNED_SEMICOLON", "PWNED_BACKTICK")


def d7_run(source, work):
    """Run the installer's own load_existing_envs over a planted legacy file."""
    app = Path(work, "app")
    app.mkdir()
    legacy, env_file = app / ".env", Path(work, "vpn_auth.env")
    legacy.write_text(
        f"ADMIN_TOKEN='it'\"'\"'s $(touch {work}/PWNED_SUBST)'\n"
        f"SPA_KEY='x'; touch {work}/PWNED_SEMICOLON; Z='y'\n"
        f"`touch {work}/PWNED_BACKTICK`\n"
        "VENV_DIR='/evil/venv'\n"
        "WINS_GATEWAY_CANARY_BIN='/evil/canary'\n"
        "TMPDIR='/evil'\n"
        "XRAY_UUID='from-legacy'\n"
        "MANAGEMENT_NAME_HMAC_KEY='legacy-only'\n"
        "RATE_LIMIT_SECRET='legacy-rate'\n",
        encoding="utf-8")
    env_file.write_text("XRAY_UUID='from-env-file'\nHUB_DOMAIN='hub.example.test'\n", encoding="utf-8")
    script = "\n".join([
        "set -Eeuo pipefail",
        'warn() { echo "WARN $*" >&2; }; log() { :; }',
        function_body(source, "load_existing_envs"),
        function_body(source, "load_env_file_as_data") if "load_env_file_as_data() {" in source else "",
        function_body(source, "wins_runtime_owned_key"),
        f"LEGACY_ENV_FILE={str(legacy)!r}",
        f"ENV_FILE={str(env_file)!r}",
        "VENV_DIR=/root/vpn_auth/venv",
        "RATE_LIMIT_SECRET=operator-rate",
        "unset TMPDIR WINS_GATEWAY_CANARY_BIN",
        "load_existing_envs",
        'for k in ADMIN_TOKEN SPA_KEY VENV_DIR WINS_GATEWAY_CANARY_BIN TMPDIR XRAY_UUID '
        'MANAGEMENT_NAME_HMAC_KEY RATE_LIMIT_SECRET HUB_DOMAIN; do printf "%s=%s\\n" "$k" "${!k:-}"; done',
    ])
    # A clean environment: the hub harness exports ADMIN_TOKEN and friends
    # process-wide, and an inherited value would mask the fill-only rule.
    clean = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C"}
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, env=clean)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    return result, values


def check_d7(source):
    """D7: a payload planted in the app-writable .env is parsed, never run."""
    failures = []
    hub = unit(source, HUB_UNIT)
    if render(source, "${VENV_DIR}") not in words(hub.get("ReadOnlyPaths", [])):
        failures.append("the installer executes an app-writable venv")
    setup = function_body(source, "setup_python")
    if '-r "${APP_DIR}/' in setup or 'mktemp /root/.wins-control-plane-requirements.' not in setup:
        failures.append("the root installer reads an app-writable requirements lock")
    if '${VENV_DIR}/bin/python" -m py_compile' in source:
        failures.append("root byte compilation writes into an app-writable output directory")
    body = function_body(source, "load_existing_envs")
    if re.search(r'(^|\s)(source|\.) +"\$\{LEGACY_ENV_FILE\}"', body):
        failures.append("load_existing_envs sources the app-writable legacy env file")
    with tempfile.TemporaryDirectory(prefix="h0-d7-") as work:
        result, values = d7_run(source, work)
        if result.returncode != 0:
            failures.append(f"load_existing_envs failed: {result.stderr.strip()[-300:]}")
        for sentinel in D7_SENTINELS:
            if Path(work, sentinel).exists():
                failures.append(f"a planted payload ran ({sentinel})")
    expected = {
        "ADMIN_TOKEN": f"it's $(touch {work}/PWNED_SUBST)",  # parsed literally
        "SPA_KEY": "",                                       # not write_env_kv form
        "VENV_DIR": "/root/vpn_auth/venv",                   # never redirected
        "WINS_GATEWAY_CANARY_BIN": "",
        "TMPDIR": "",
        "XRAY_UUID": "from-env-file",                        # root-owned file wins
        "MANAGEMENT_NAME_HMAC_KEY": "legacy-only",           # generated key kept
        "RATE_LIMIT_SECRET": "operator-rate",                # never overridden
        "HUB_DOMAIN": "hub.example.test",                    # root-owned file sourced
    }
    for key, want in expected.items():
        if values.get(key) != want:
            failures.append(f"{key} is {values.get(key)!r} after load_existing_envs, expected {want!r}")
    return failures


def check_d8(source, runtime=None):
    """D8: root jobs have read-only app paths and no writable database handle."""
    failures = []
    canary = unit(source, CANARY_UNIT)
    failures += sandbox_failures("wins-gateway-canary.service", canary, "")
    failures += exec_failures(source, "wins-gateway-canary.service", canary)

    writable = {
        path.lstrip("-")
        for path in words(canary.get("ReadWritePaths", []))
    }
    allowed = {"/var/log/winsvpn", "/var/lib/wins-canary-results", "/var/lib/wins-canary-dispatch"}
    extra = writable - allowed
    if extra:
        failures.append(f"canary can write {sorted(extra)}")
    if any(under(path, file_top(source, "APP_DIR")) for path in writable):
        failures.append("the canary can write the app directory")

    script = heredoc(source, "cat > /usr/local/bin/wins-gateway-canary <<'EOF'")
    if re.search(r"python3 - ", script):
        failures.append("the canary runs embedded Python without -I")
    if runtime is None:
        runtime = Path(__file__).with_name('wins_winn3_canary_runtime.py').read_text()
    facts = function_body(script, "winn3_canary_entries")
    if ("'?mode=ro', uri=True" not in facts or "'?mode=ro', uri=True" not in runtime
            or "connection.execute('PRAGMA query_only=ON')" not in runtime):
        failures.append("the canary's database reader does not open the database read-only")
    if re.search(
        r"\b(?:ALTER\s+TABLE|UPDATE\s+nodes|INSERT\s+INTO|DELETE\s+FROM)\b",
        script,
        re.I,
    ):
        failures.append("the canary still contains database writes")

    request = unit(source, "cat > /etc/systemd/system/wins-winn3-canary-requests.service <<'EOF'")
    failures += sandbox_failures("wins-winn3-canary-requests.service", request, "")
    failures += exec_failures(source, "wins-winn3-canary-requests.service", request)
    if set(words(request.get("ReadWritePaths", []))) != {
        "/var/lib/wins-canary-results", "/var/lib/wins-canary-dispatch", "/var/lib/wins-canary-requests",
    }:
        failures.append("on-demand canary has an unexpected writable path")
    if request.get("ReadOnlyPaths") != ["/root/vpn_auth"]:
        failures.append("on-demand canary database is not mounted read-only")

    rotate = unit(source, LOGROTATE_UNIT)
    failures += sandbox_failures("wins-hub-logrotate.service", rotate, "")
    failures += exec_failures(source, "wins-hub-logrotate.service", rotate)
    if rotate.get("PrivateNetwork") != ["true"]:
        failures.append("the logrotate unit has network access")
    if set(words(rotate.get("ReadWritePaths", []))) != {
        "/var/log/winsvpn",
        "/var/lib/wins-hub-logrotate",
    }:
        failures.append(f"the logrotate unit can write {rotate.get('ReadWritePaths')}")
    if (
        "cat > /etc/logrotate.d/wins-winsvpn" in source
        or "rm -f /etc/logrotate.d/wins-winsvpn" not in source
    ):
        failures.append("the distribution's logrotate still rotates /var/log/winsvpn")
    return failures


CHECKS = {"D1": check_d1, "D2": check_d2, "D3": check_d3, "D4": check_d4,
          "D5": check_d5, "D6": check_d6, "D7": check_d7, "D8": check_d8}

# One mutant per requirement: each re-grants exactly what its requirement
# removes. (requirement, text in the shipped installer, replacement)
MUTANTS = (
    ("D1", "BindReadOnlyPaths=/run/litestream /run/wins-hub-spa-window /run/wins-descriptor-signer\n",
     "BindReadOnlyPaths=/run/litestream /run/wins-hub-spa-window /run/wins-descriptor-signer /run/systemd/private\n"),
    ("D2", "BindReadOnlyPaths=/run/litestream /run/wins-hub-spa-window /run/wins-descriptor-signer\n",
     "BindReadOnlyPaths=/run/litestream /run/wins-hub-spa-window /run/wins-descriptor-signer /run/docker.sock\n"),
    ("D3", "ReadWritePaths=${APP_DIR} /var/lib/wins-hub-ssh",
     "ReadWritePaths=${APP_DIR} /root/.ssh /var/lib/wins-hub-ssh"),
    ("D4", "# is in wins-hub-spa-window.service.\nCapabilityBoundingSet=\n",
     "# is in wins-hub-spa-window.service.\nCapabilityBoundingSet=CAP_NET_ADMIN\n"),
    ("D5", "ExecStart=/usr/bin/python3 -I /usr/local/lib/wins_hub_spa_window.py\n",
     "ExecStart=/usr/bin/python3 -I /root/vpn_auth/wins_hub_spa_window.py\n"),
    ("D6", "ExecStart=/usr/bin/python3 -I /usr/local/lib/wins_node_dataplane_probe.py\n",
     "ExecStart=/root/vpn_auth/venv/bin/python /root/vpn_auth/wins_node_dataplane_probe.py\n"),
    ("D7", '  load_env_file_as_data "${LEGACY_ENV_FILE}"\n',
     '  source "${LEGACY_ENV_FILE}" || true\n'),
    ("D8", "# validated and committed by the hub app, never by this privileged job.\n"
           "NoNewPrivileges=true\n",
     "# validated and committed by the hub app, never by this privileged job.\n"),
)


class H0RequirementTests(unittest.TestCase):
    def test_each_requirement_holds_on_the_shipped_installer(self):
        for name, check in CHECKS.items():
            with self.subTest(requirement=name):
                self.assertEqual(check(SOURCE), [])

    def test_one_mutant_per_requirement_is_killed(self):
        self.assertEqual(sorted({name for name, _, _ in MUTANTS}), sorted(CHECKS))
        for name, old, new in MUTANTS:
            with self.subTest(mutant=name):
                # Anti-vacuity: the mutated text must exist exactly once.
                self.assertEqual(SOURCE.count(old), 1, f"{name} mutant anchor drifted")
                self.assertNotEqual(CHECKS[name](SOURCE.replace(old, new, 1)), [])

    def test_canary_cannot_regain_a_writable_reader(self):
        # Design 5.6 kill list: the canary job regains a writable database
        # handle. The reader and the result publisher cannot mutate the database.
        runtime = Path(__file__).with_name('wins_winn3_canary_runtime.py').read_text()
        reader = "connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=30)"
        self.assertEqual(runtime.count(reader), 1)
        mutated = runtime.replace(reader, reader.replace("?mode=ro", "?mode=rw"))
        self.assertIn("the canary's database reader does not open the database read-only", check_d8(SOURCE, mutated))


    def test_recovery_expiry_cannot_strip_the_forwarding_block(self):
        # The pre-H0 helper stripped every Match block; with the site-AI
        # account's block in the same file that would drop its policy.
        narrowed = "awk '/^Match User [^ ]+ Address / {skip=1} {if (!skip) print} skip && /^Match all$/ {skip=0}'"
        self.assertEqual(SOURCE.count(narrowed), 1)
        mutated = SOURCE.replace(narrowed, "awk '/^Match / {skip=1} {if (!skip) print} /^Match all$/ {skip=0}'")
        self.assertIn("the recovery-expiry helper strips the site-AI forwarding account's Match block", check_d3(mutated))

    def test_d7_mutant_actually_executes_the_payload(self):
        # The kill is behavioural, not textual: under the source-again mutant
        # the planted command substitution runs.
        old, new = MUTANTS[6][1], MUTANTS[6][2]
        with tempfile.TemporaryDirectory(prefix="h0-d7m-") as work:
            d7_run(SOURCE.replace(old, new, 1), work)
            self.assertTrue(Path(work, "PWNED_SEMICOLON").exists())
            self.assertTrue(Path(work, "PWNED_BACKTICK").exists())


class H0HubAppBehaviourTests(unittest.TestCase):
    """The real embedded hub app, extracted and loaded by the shared harness."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="h0-app-")
        cls.keys = os.path.join(cls.tmp, "site-ai", "authorized_keys")
        cls.owned = os.path.join(cls.tmp, "site_ai_owned.json")
        cls.mod = harness.load_hub(
            IONOS_HUB_IP="203.0.113.10", HIDE_CONTROL_ORIGIN="0",
            SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE=cls.keys, SITE_AI_TUNNEL_OWNERSHIP_FILE=cls.owned,
            DURABILITY_BARRIER_ENABLED="0", DURABILITY_BARRIER_REQUIRED="0")

    @classmethod
    def tearDownClass(cls):
        for name in ("SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE", "SITE_AI_TUNNEL_OWNERSHIP_FILE", "IONOS_HUB_IP"):
            os.environ.pop(name, None)
        shutil.rmtree(cls.mod._TMPDIR, ignore_errors=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_d3_hub_hosts_are_refused_by_name(self):
        for host in ("127.0.0.1", "127.8.9.10", "::1", "[::1]", "::ffff:127.0.0.1", "0.0.0.0", "::",
                     "localhost", "LOCALHOST.", "db.localhost", "", "203.0.113.10",
                     "127.1", "127.0.1", "2130706433", "0x7f.0.0.1", "0.0", "3405803786"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(ValueError, "Refusing to manage this hub as a data-plane node"):
                    self.mod.node_ssh_command(host, "true")
        self.assertFalse(self.mod.node_host_names_this_hub("node-a.mgmt.example.test"))
        self.assertFalse(self.mod.node_host_names_this_hub("198.51.100.7"))

    def test_d3_local_management_paths_run_nothing_here(self):
        cfg = {"client_public_key": "A" * 43 + "=", "vpn_internal_ip": "10.8.0.9", "preshared_key": ""}
        with patch.object(self.mod.subprocess, "run", side_effect=AssertionError("ran a command")):
            for host in ("127.0.0.1", "localhost", "", "203.0.113.10"):
                with self.subTest(host=host):
                    self.assertFalse(self.mod.sync_peer_to_node(host, cfg))
                    self.assertFalse(self.mod.verify_node_management_access(host or "localhost"))
                    self.assertFalse(self.mod.remove_peer_from_node(host, "A" * 43 + "="))

    def test_d3_control_sockets_live_outside_root_ssh(self):
        with patch.object(self.mod, "management_known_hosts_has_hostname", return_value=True), \
                patch.object(self.mod.os, "makedirs") as makedirs:
            argv = self.mod.node_ssh_command("node-a.mgmt.example.test", "true")
        self.assertIn("ControlPath=/var/lib/wins-hub-ssh/cm/%C", argv)
        makedirs.assert_called_once_with("/var/lib/wins-hub-ssh/cm", mode=0o700, exist_ok=True)

    def test_d3_site_ai_key_goes_to_the_forwarding_account_not_root(self):
        hostkeys = os.path.join(self.tmp, "etc-ssh")
        os.makedirs(hostkeys, exist_ok=True)
        Path(hostkeys, "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 " + "A" * 68 + " host\n", encoding="utf-8")
        blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(32)).decode()
        real_path = self.mod.Path
        def fake_path(*parts):
            return real_path(hostkeys) if parts and str(parts[0]) == "/etc/ssh" else real_path(*parts)
        payload = self.mod.SiteAiTunnelKeyRequest(public_key=f"ssh-ed25519 {blob} core", listen_port=11435)
        with patch.object(self.mod, "require_core_token"), patch.object(self.mod, "Path", side_effect=fake_path):
            response = self.mod.register_site_ai_tunnel_key(payload, harness.FakeRequest(), "core-token")
        self.assertEqual(response["ssh_user"], "wins-site-ai")
        text = Path(self.keys).read_text(encoding="utf-8")
        self.assertEqual(text, f'restrict,port-forwarding,permitlisten="127.0.0.1:11435" ssh-ed25519 {blob} wins-core-site-ai\n')
        self.assertEqual(stat.S_IMODE(os.stat(self.keys).st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.keys)).st_mode), 0o755)

    def test_d3_site_ai_key_refuses_a_foreign_listen_port(self):
        blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(32)).decode()
        payload = self.mod.SiteAiTunnelKeyRequest(public_key=f"ssh-ed25519 {blob} core", listen_port=8000)
        with patch.object(self.mod, "require_core_token"):
            with self.assertRaises(self.mod.HTTPException) as ctx:
                self.mod.register_site_ai_tunnel_key(payload, harness.FakeRequest(), "core-token")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_d3_pubkey_route_never_writes_root_ssh(self):
        refuse = AssertionError("wrote root's SSH directory")
        with patch.object(self.mod, "require_node_token"), \
                patch.object(self.mod.os, "makedirs", side_effect=refuse), \
                patch.object(self.mod.os, "chmod", side_effect=refuse), \
                patch.object(self.mod.subprocess, "run", side_effect=refuse), \
                patch("builtins.open", side_effect=FileNotFoundError("/root/.ssh/id_rsa.pub")):
            self.assertEqual(self.mod.get_pubkey(harness.FakeRequest(), slug="node-a", x_node_token="t"), {"pubkey": ""})

    def test_d1_spa_window_is_one_verb_to_the_helper(self):
        directory = tempfile.mkdtemp(prefix="h0s-", dir="/tmp" if os.path.isdir("/tmp") else None)
        path = os.path.join(directory, "sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        seen = []
        def serve(reply):
            conn, _ = server.accept()
            with conn:
                seen.append(conn.recv(64))
                conn.sendall(reply)
        try:
            with patch.object(self.mod, "SPA_WINDOW_HELPER_SOCKET", path), \
                    patch.object(self.mod.subprocess, "run", side_effect=AssertionError("ran a command")):
                for reply, opened in ((b"ok\n", True), (b"refused\n", False)):
                    worker = threading.Thread(target=serve, args=(reply,))
                    worker.start()
                    self.assertIs(self.mod.open_spa_window("192.0.2.4"), opened)
                    worker.join(5)
                self.assertFalse(self.mod.open_spa_window("not-an-address"))
            self.assertEqual(seen, [b"open 192.0.2.4\n", b"open 192.0.2.4\n"])
            os.unlink(path)
            with patch.object(self.mod, "SPA_WINDOW_HELPER_SOCKET", path):
                self.assertFalse(self.mod.open_spa_window("192.0.2.4"))  # helper absent: fail closed
        finally:
            server.close()
            shutil.rmtree(directory, ignore_errors=True)


class H0SpaHelperTests(unittest.TestCase):
    """The SPA helper program, extracted from the installer as shipped."""

    def setUp(self):
        namespace = {"__name__": "wins_hub_spa_window_test"}
        exec(compile(heredoc(SOURCE, SPA_HELPER), "wins_hub_spa_window.py", "exec"), namespace)
        self.helper = types.SimpleNamespace(**namespace)

    def request(self, data, is_hub=True, recent=None):
        a, b = socket.socketpair()
        with a, b:
            a.sendall(data)
            a.shutdown(socket.SHUT_WR)
            with patch.dict(self.helper.handle.__globals__, {"peer_is_hub": lambda conn: is_hub}):
                return self.helper.handle(b, recent if recent is not None else self.helper.collections.deque())

    def test_one_verb_only_and_only_from_the_hub(self):
        opened = []
        with patch.dict(self.helper.handle.__globals__, {"open_window": opened.append}):
            self.assertEqual(self.request(b"open 192.0.2.4\n"), b"ok\n")
            for data in (b"close 192.0.2.4\n", b"open 192.0.2.4 22\n", b"open 192.0.2.004\n",
                         b"open ::1\n", b"open 192.0.2.4", b"open 192.0.2.4\nopen 192.0.2.5\n",
                         b"open " + b"1" * 70 + b"\n"):
                with self.subTest(data=data):
                    self.assertEqual(self.request(data), b"refused\n")
            self.assertEqual(self.request(b"open 192.0.2.4\n", is_hub=False), b"refused\n")
        self.assertEqual(opened, ["192.0.2.4"])

    def test_open_windows_are_bounded(self):
        recent = self.helper.collections.deque()
        with patch.dict(self.helper.handle.__globals__, {"open_window": lambda source: None}):
            replies = [self.request(b"open 192.0.2.4\n", recent=recent) for _ in range(self.helper.MAX_OPEN_WINDOWS + 1)]
        self.assertEqual(replies[:-1], [b"ok\n"] * self.helper.MAX_OPEN_WINDOWS)
        self.assertEqual(replies[-1], b"refused\n")

    def test_peer_must_be_root_in_the_hub_cgroup(self):
        a, b = socket.socketpair()
        with a, b:
            if not hasattr(socket, "SO_PEERCRED"):
                self.skipTest("SO_PEERCRED is Linux only")
            self.assertEqual(self.helper.peer_is_hub(b), False)  # this test process is not wins-hub.service


if __name__ == "__main__":
    unittest.main(verbosity=2)
