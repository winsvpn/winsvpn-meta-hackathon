#!/usr/bin/env python3
"""Installer fix wave 2026-09-29, lane FX-DP-MED: regressions for the data-plane
findings IA-DP-04 .. IA-DP-09 and IA-DP-11 (IA-DP-10 lives in
wins_winn3_gateway_install_maintenance_test.sh, next to the backup it runs).

Every dynamic check executes the installer's OWN function text, or the OWN
text of a script the installer generates, in a Bash 4 subshell inside a
private temp dir. Stubs replace only what a non-root macOS/Linux test cannot
do (curl to the internet, tc/ip on real devices, root-ownership checks) and
every stub records its calls so a check can also prove what did NOT run.
No network, no writes outside the temp dir.

Usage: python3 server/test_data_plane_installer_fx_med.py [installer path]
"""
from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import os
import re
import stat as statmod
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "wins_data_plane_setup_ONETOUCH.sh")
BASH = _toolchain.bash4()
SRC = open(SCRIPT, encoding="utf-8").read()
FAILURES: list[tuple[str, str]] = []
PASSED = [0]
UUID = "22222222-2222-4222-8222-222222222222"


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def function(src: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, f"{name}() not found"
    return m.group(0)


def heredoc(src: str, opener: str, terminator: str) -> str:
    start = src.index(opener)
    start = src.index("\n", start) + 1
    end = src.index("\n" + terminator + "\n", start)
    return src[start:end] + "\n"


def top_level_line(src: str, prefix: str) -> str:
    lines = [l for l in src.splitlines() if l.startswith(prefix)]
    assert lines, f"{prefix!r} not found"
    return lines[0]


# The installer's runtime err/warn/log: the definitions at the helper block
# (err there prints to STDOUT, which is why detect_public_ipv4 must redirect).
ERR = top_level_line(SRC, "err()  {")
WARN = top_level_line(SRC, "warn() {")
LOG = top_level_line(SRC, "log()  {")


def bash(prog: str, env: dict | None = None, args: list[str] | None = None, timeout: int = 60):
    run_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}
    run_env.update(env or {})
    return subprocess.run([BASH, "-c", prog, "harness", *(args or [])], env=run_env,
                          capture_output=True, text=True, timeout=timeout)


def write_exec(path: str, body: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


# --------------------------------------------------------------------------
# IA-DP-04: node.env values can never become a command substitution.
TRICKY = [
    "France - Paris",
    "$(touch {marker})",
    "`touch {marker}`",
    "${{HOME}} and $HOME",
    'back\\slash "quoted" \\$(x)',
    "trailing backslash \\",
    "Côte d'Ivoire - Abidjan",
]


def test_write_env_kv_round_trips_without_executing():
    body = function(SRC, "write_env_kv")
    with tempfile.TemporaryDirectory(prefix="fx-med-envkv-") as tmp:
        marker = os.path.join(tmp, "EXECUTED")
        env_file = os.path.join(tmp, "node.env")
        for raw in TRICKY:
            value = raw.format(marker=marker)
            prog = "\n".join([
                "set -Eeuo pipefail", body, 'NODE_ENV_KV_BUFFER=""',
                'write_env_kv NODE_NAME "$1"',
                f'printf "%s" "${{NODE_ENV_KV_BUFFER}}" > "{env_file}"',
                f'source "{env_file}"', 'printf "%s" "${NODE_NAME}"'])
            out = bash(prog, args=[value])
            assert out.returncode == 0, (value, out.stderr)
            assert out.stdout == value, (value, out.stdout)
            assert not os.path.exists(marker), f"sourcing node.env executed {value!r}"


def test_valid_node_display_name():
    body = function(SRC, "valid_node_display_name")
    good = ["France - Paris", "São Paulo", "Côte d'Ivoire - Abidjan", "x" * 128, "US | East"]
    bad = ["", "$(id)", "a`id`", 'a"b', "a\\b", "tab\there", "new\nline", "x" * 129, "bell\x07"]
    for value in good + bad:
        out = bash("\n".join([body, 'valid_node_display_name "$1"']), args=[value])
        want = 0 if value in good else 1
        assert out.returncode == want, (value, out.returncode, out.stderr)


def test_collect_inputs_refuses_a_bad_node_name_before_writing():
    body = function(SRC, "collect_inputs")
    call = 'valid_node_display_name "${NODE_NAME}" || {'
    assert call in body
    assert body.index('maybe_prompt_or_default NODE_NAME') < body.index(call) < body.index('write_env_kv NODE_NAME')
    after = body[body.index(call):].splitlines()[1:4]
    assert any("exit 1" in l for l in after), after


def test_geo_default_name_is_stripped_of_shell_metacharacters():
    prog = "\n".join([
        function(SRC, "sanitize_slug"), function(SRC, "flag_from_country_code"),
        function(SRC, "geo_node_defaults"),
        'curl() { printf "%s" "${FAKE_GEO}"; }',
        'geo_node_defaults 192.0.2.10'])
    fake = '{"city": "$(curl x|sh)`id`\\\\\\"|x", "country_name": "France", "country_code": "FR"}'
    out = bash(prog, env={"FAKE_GEO": fake})
    assert out.returncode == 0, out.stderr
    slug, name, _flag, _host = out.stdout.strip().split("|")
    for ch in "$`\\\"":
        assert ch not in name, name
    assert name.startswith("France - "), name
    assert re.fullmatch(r"[a-z0-9-]+", slug), slug


# --------------------------------------------------------------------------
# IA-DP-05: node.env secrets are not exported to children.
def test_load_existing_node_env_does_not_export_secrets():
    with tempfile.TemporaryDirectory(prefix="fx-med-seta-") as tmp:
        env_file = os.path.join(tmp, "node.env")
        with open(env_file, "w", encoding="utf-8") as fh:
            fh.write('NODE_SLUG="lab-node"\nNODE_TOKEN="fixture-token-not-a-secret"\n'
                     'XRAY_UUID="11111111-1111-4111-8111-111111111111"\n')
        os.chmod(env_file, 0o600)
        prog = "\n".join([
            "set -Eeuo pipefail", "stat() { echo 0; }", "find() { :; }",
            function(SRC, "load_existing_node_env"),
            f'load_existing_node_env "{env_file}"',
            'printf "parent=%s|%s|%s\\n" "${NODE_SLUG}" "${NODE_TOKEN}" "${XRAY_UUID}"',
            'env | grep -E "^(NODE_TOKEN|XRAY_UUID|NODE_SLUG)=" | sort | sed "s/^/child:/" || true'])
        out = bash(prog)
        assert out.returncode == 0, out.stderr
        assert "parent=lab-node|fixture-token-not-a-secret|11111111-1111-4111-8111-111111111111" in out.stdout, out.stdout
        assert "child:" not in out.stdout, out.stdout
        # An operator override from the environment still wins and stays exported.
        out = bash(prog, env={"NODE_SLUG": "intentional-rename"})
        assert out.returncode == 0, out.stderr
        assert "parent=intentional-rename|" in out.stdout, out.stdout
        assert "child:NODE_SLUG=intentional-rename" in out.stdout, out.stdout
        assert "child:NODE_TOKEN" not in out.stdout, out.stdout


# --------------------------------------------------------------------------
# IA-DP-06: a partial first install (node.env, no token, nothing deployed) reruns.
def _withdrawal(tmp, node_env_text, token, slug, artifacts=()):
    env_file = os.path.join(tmp, "node.env")
    if node_env_text is not None:
        with open(env_file, "w", encoding="utf-8") as fh:
            fh.write(node_env_text)
    guard = os.path.join(tmp, "wins-node-local-serving")
    register = os.path.join(tmp, "wins-node-register")
    for name in artifacts:
        write_exec({"guard": guard, "register": register}[name], "#!/bin/sh\nexit 0\n")
    calls = os.path.join(tmp, "calls")
    body = function(SRC, "begin_data_deployment_withdrawal_before_mutation")
    body = body.replace("/usr/local/sbin/wins-node-local-serving", guard)
    body = body.replace("/usr/local/bin/wins-node-register", register)
    prog = "\n".join([
        "set -Eeuo pipefail", ERR, WARN, LOG,
        f'curl() {{ echo curl >> "{calls}"; return 1; }}',
        f'data_plane_installer_path() {{ echo installer >> "{calls}"; echo /nonexistent; }}',
        f'NODE_ENV_FILE="{env_file}"', f'NODE_TOKEN="{token}"', f'NODE_SLUG="{slug}"',
        'HUB_API_BASE="https://hub.example.test"',
        body, "begin_data_deployment_withdrawal_before_mutation"])
    out = bash(prog)
    called = open(calls).read() if os.path.exists(calls) else ""
    return out, called


def test_partial_first_install_continues_as_first_install():
    with tempfile.TemporaryDirectory(prefix="fx-med-partial-") as tmp:
        out, called = _withdrawal(tmp, 'NODE_SLUG="lab-node"\nNODE_TOKEN=""\n', "", "lab-node")
        assert out.returncode == 0, out.stdout + out.stderr
        assert "partial first deployment" in out.stdout, out.stdout
        assert called == "", called


def test_tokenless_node_with_deployed_artifacts_is_still_refused():
    for artifact in ("guard", "register"):
        with tempfile.TemporaryDirectory(prefix="fx-med-partial-") as tmp:
            out, called = _withdrawal(tmp, 'NODE_TOKEN=""\n', "", "lab-node", (artifact,))
            assert out.returncode != 0, (artifact, out.stdout)
            assert "lacks NODE_SLUG or NODE_TOKEN" in out.stdout, out.stdout
            assert called == "", called


def test_token_without_slug_and_fresh_host_paths_are_unchanged():
    with tempfile.TemporaryDirectory(prefix="fx-med-partial-") as tmp:
        out, _ = _withdrawal(tmp, 'NODE_TOKEN="t"\n', "t", "")
        assert out.returncode != 0 and "lacks NODE_SLUG or NODE_TOKEN" in out.stdout, out.stdout
    with tempfile.TemporaryDirectory(prefix="fx-med-partial-") as tmp:
        out, called = _withdrawal(tmp, None, "", "")
        assert out.returncode == 0 and called == "", (out.stdout, called)


# --------------------------------------------------------------------------
# IA-DP-09: the node.env rewrite keeps NODE_MANAGEMENT_TUNNEL_ID, readable by
# both the rerun path and the recovery guard.
def _collect_inputs_rewrite_lines() -> str:
    body = function(SRC, "collect_inputs")
    start = body.index("  write_env_kv NODE_SLUG")
    end = body.index("\n", body.index('atomic_replace_file "${NODE_ENV_FILE}"'))
    return body[start:end]


def _rewrite(tmp, tunnel_line):
    env_file = os.path.join(tmp, "node.env")
    with open(env_file, "w", encoding="utf-8") as fh:
        fh.write('NODE_SLUG="lab-node"\nNODE_TOKEN="fixture-token"\n'
                 'NODE_SSH_HOST="node-lab.mgmt.example.test"\n' + tunnel_line)
    os.chmod(env_file, 0o600)
    guard = heredoc(SRC, "<<'WINS_NODE_SSH_RECOVERY_GUARD'", "WINS_NODE_SSH_RECOVERY_GUARD")
    token_file = os.path.join(tmp, "token")
    with open(token_file, "w") as fh:
        fh.write("T" * 100 + "\n")
    prog = "\n".join([
        "set -Eeo pipefail", "stat() { echo 0; }", "find() { :; }", ERR, WARN, LOG,
        function(SRC, "load_existing_node_env"), function(SRC, "write_env_kv"),
        function(SRC, "atomic_replace_file"), function(SRC, "valid_dns_hostname"),
        function(SRC, "data_resolve_management_tunnel_material"),
        function(guard, "state_value"),
        f'NODE_ENV_FILE="{env_file}"', f'WINS_NODE_MANAGEMENT_TOKEN_FILE="{token_file}"',
        f'load_existing_node_env "{env_file}"',
        "rewrite() {", "local NODE_ENV_KV_BUFFER=\"\"", _collect_inputs_rewrite_lines(), "}",
        "rewrite",
        'printf "guard=%s\\n" "$(state_value "${NODE_ENV_FILE}" NODE_MANAGEMENT_TUNNEL_ID || echo MISSING)"',
        "unset NODE_MANAGEMENT_TUNNEL_ID",
        f'load_existing_node_env "{env_file}"',
        'if data_resolve_management_tunnel_material >/dev/null; then echo "rerun=${EDGE_MGMT_TUNNEL_ID}"; else echo rerun=REFUSED; fi'])
    out = bash(prog)
    return out, open(env_file, encoding="utf-8").read()


def test_rewrite_keeps_the_tunnel_id_for_guard_and_rerun():
    with tempfile.TemporaryDirectory(prefix="fx-med-tunnel-") as tmp:
        out, text = _rewrite(tmp, f"NODE_MANAGEMENT_TUNNEL_ID={UUID}\n")
        assert out.returncode == 0, out.stdout + out.stderr
        assert f"guard={UUID}" in out.stdout, out.stdout
        assert f"rerun={UUID}" in out.stdout, out.stdout
        assert text.count("NODE_MANAGEMENT_TUNNEL_ID=") == 1, text


def test_rewrite_drops_a_malformed_tunnel_id_and_adds_none_when_absent():
    with tempfile.TemporaryDirectory(prefix="fx-med-tunnel-") as tmp:
        out, text = _rewrite(tmp, 'NODE_MANAGEMENT_TUNNEL_ID="$(id)"\n')
        assert out.returncode == 0, out.stdout + out.stderr
        assert "NODE_MANAGEMENT_TUNNEL_ID" not in text, text
    with tempfile.TemporaryDirectory(prefix="fx-med-tunnel-") as tmp:
        out, text = _rewrite(tmp, "")
        assert out.returncode == 0, out.stdout + out.stderr
        assert "NODE_MANAGEMENT_TUNNEL_ID" not in text and "rerun=REFUSED" in out.stdout, (text, out.stdout)


# --------------------------------------------------------------------------
# IA-DP-11: HTTPS only, two sources must agree, no local fallback.
def _detect(table: dict[str, str]):
    with tempfile.TemporaryDirectory(prefix="fx-med-ip-") as tmp:
        calls = os.path.join(tmp, "calls")
        stub = "\n".join([
            "curl() {",
            f'  printf "%s\\n" "$*" >> "{calls}"',
            '  local url="${@: -1}"',
            '  case "${url}" in',
            *[f'    "{u}") printf "%s\\n" "{v}" ;;' for u, v in table.items()],
            "    *) return 7 ;;",
            "  esac",
            "}",
            f'hostname() {{ echo hostname >> "{calls}"; echo 10.0.0.5; }}'])
        prog = "\n".join(["set -Eeuo pipefail", ERR, function(SRC, "valid_ipv4"), stub,
                          function(SRC, "detect_public_ipv4"),
                          'ip="$(detect_public_ipv4)" || { echo "rc=1 out=[${ip}]"; exit 0; }',
                          'echo "rc=0 out=[${ip}]"'])
        out = bash(prog)
        called = open(calls).read() if os.path.exists(calls) else ""
        return out, called


A, B, C, D = ("https://api.ipify.org", "https://checkip.amazonaws.com",
              "https://ifconfig.me/ip", "https://ipv4.icanhazip.com")


def test_public_ip_needs_two_agreeing_https_sources():
    out, called = _detect({A: "198.51.100.7", B: "198.51.100.7"})
    assert "rc=0 out=[198.51.100.7]" in out.stdout, out.stdout + out.stderr
    out, _ = _detect({B: "198.51.100.7", D: "198.51.100.7"})
    assert "rc=0 out=[198.51.100.7]" in out.stdout, out.stdout + out.stderr
    out, _ = _detect({A: "999.1.1.1", B: "198.51.100.7", C: "198.51.100.7"})
    assert "rc=0 out=[198.51.100.7]" in out.stdout, out.stdout + out.stderr


def test_public_ip_refuses_disagreement_single_source_and_none():
    for table, why in (({A: "198.51.100.7", B: "203.0.113.9"}, "disagrees"),
                       ({D: "203.0.113.9"}, "Only one HTTPS source"),
                       ({}, "Could not detect")):
        out, called = _detect(table)
        assert "rc=1 out=[]" in out.stdout, (table, out.stdout)
        assert why in out.stderr, (table, out.stderr)
        assert "hostname" not in called, called


def test_public_ip_lookups_are_https_only():
    _, called = _detect({})
    lines = [l for l in called.splitlines() if l]
    assert len(lines) == 4, lines
    for line in lines:
        assert "--proto =https" in line, line
        assert "http://" not in line and line.split()[-1].startswith("https://"), line
    body = function(SRC, "check_not_hub")
    assert "--proto '=https'" in body and "https://" in body and "http://" not in body, body
    resolve = function(SRC, "data_resolve_node_defaults")
    assert 'detected_ip="$(detect_public_ipv4)" || return 1' in resolve
    assert "data_resolve_node_defaults || return 1" in function(SRC, "data_preflight_public_identity")
    assert "data_resolve_node_defaults || exit 1" in function(SRC, "collect_inputs")


# --------------------------------------------------------------------------
# IA-DP-07: awg0/amn0 get the calibrated fq on every creation.
EDGE = heredoc(SRC, "<<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")

TC_STUB = r"""#!/usr/bin/env bash
printf 'tc %s\n' "$*" >> "${FX_CALLS}"
if [[ "$1 $2" == "qdisc replace" ]]; then
  # Like the kernel: a parent whose major is 0 is never found.
  if [[ "${5:-}" == parent && "${6:-}" =~ ^0*: ]]; then
    echo "Error: Failed to find specified qdisc." >&2; exit 2
  fi
  dev="$4"; shift 5
  printf '%s\n' "$*" > "${FX_STATE}/qdisc.${dev}"
  if [[ -n "${FX_RECREATE_ONCE:-}" && ! -e "${FX_STATE}/recreated" ]]; then
    touch "${FX_STATE}/recreated"; echo 99 > "${FX_SYS}/${dev}/ifindex"
  fi
  exit 0
fi
if [[ "$1 $2" == "qdisc show" ]]; then
  dev="$4"
  args="$(cat "${FX_STATE}/qdisc.${dev}" 2>/dev/null || echo 'fq limit 10000 flow_limit 100')"
  read -r -a a <<< "${args}"
  lim=10000; flow=100
  for ((i = 0; i < ${#a[@]}; i++)); do
    [[ "${a[$i]}" == limit ]] && lim="${a[$((i + 1))]}"
    [[ "${a[$i]}" == flow_limit ]] && flow="${a[$((i + 1))]}"
  done
  [[ -n "${FX_SHOW_DEFAULT:-}" ]] && { lim=10000; flow=100; }
  printf 'qdisc fq 8001: root refcnt 2 limit %sp flow_limit %sp buckets 1024 orphan_mask 1023 quantum 1280b\n' "${lim}" "${flow}"
  exit 0
fi
exit 0
"""


def _vpn_qdisc(args, devices=("awg0",), extra_env=None):
    with tempfile.TemporaryDirectory(prefix="fx-med-qdisc-") as tmp:
        sysdir = os.path.join(tmp, "sys-class-net")
        state = os.path.join(tmp, "state")
        stubs = os.path.join(tmp, "bin")
        for d in (sysdir, state, stubs):
            os.makedirs(d)
        for dev in devices:
            os.makedirs(os.path.join(sysdir, dev))
            with open(os.path.join(sysdir, dev, "ifindex"), "w") as fh:
                fh.write("7\n")
        calls = os.path.join(tmp, "calls")
        open(calls, "w").close()
        write_exec(os.path.join(stubs, "tc"), TC_STUB)
        write_exec(os.path.join(stubs, "ip"), '#!/usr/bin/env bash\nprintf "ip %s\\n" "$*" >> "${FX_CALLS}"\n')
        for fw in ("iptables", "ip6tables", "iptables-save", "iptables-restore", "ip6tables-restore",
                   "sysctl", "systemctl", "docker", "nft", "ethtool"):
            write_exec(os.path.join(stubs, fw),
                       f'#!/usr/bin/env bash\nprintf "FIREWALL-OR-SYSTEM {fw} %s\\n" "$*" >> "${{FX_CALLS}}"\nexit 1\n')
        node_env = os.path.join(tmp, "node.env")
        with open(node_env, "w") as fh:
            fh.write('VPN_INTERFACES="awg0 amn0"\n')
        script = os.path.join(tmp, "wins-edge-hardening")
        write_exec(script, EDGE.replace("/sys/class/net/", sysdir + "/"))
        # A firewall input that full hardening refuses (not root-owned 0600);
        # a queue mode must never read it, so its presence must not matter.
        admission = os.path.join(tmp, "admission.env")
        with open(admission, "w") as fh:
            fh.write("PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        os.chmod(admission, 0o644)
        env = {"PATH": stubs + ":" + os.environ.get("PATH", "/usr/bin:/bin"), "FX_CALLS": calls,
               "FX_STATE": state, "FX_SYS": sysdir, "NODE_ENV_FILE": node_env,
               "PUBLIC_VPN_INGRESS_ADMISSION_FILE": admission,
               "WINSVPN_TEST_ROOT": os.path.join(tmp, "root")}
        env.update(extra_env or {})
        out = subprocess.run([BASH, script, *args], env=env, capture_output=True, text=True, timeout=60)
        return out, open(calls).read()


def test_first_install_without_jq_still_gets_the_geo_default():
    # N-4 (both seats): a minimal 24.04 image has no jq until apt_install. The
    # defaults must be resolved after it, so the geo name and slug are kept.
    with tempfile.TemporaryDirectory(prefix="fx-med-n4-") as tmp:
        out, _ = _main_until_withdrawal(tmp, AGREE, "", geo=OK_GEO, continue_collect=True,
                                        first_install=True, jq_until_apt=True)
        assert out.returncode == 0, out.stdout + out.stderr
        assert "collect-name=France - Paris\n" in out.stdout, out.stdout
        assert "collect-slug=france-paris\n" in out.stdout, out.stdout
        assert "choose_calls=1\n" in out.stdout, out.stdout


def test_first_install_with_a_broken_resolver_reaches_apt_install():
    # N-5 (Seat C): before apt_install repairs DNS, no echo host resolves. A
    # first install must not refuse there; it detects after the repair.
    with tempfile.TemporaryDirectory(prefix="fx-med-n5-") as tmp:
        out, _ = _main_until_withdrawal(tmp, AGREE, "", geo=OK_GEO, continue_collect=True,
                                        first_install=True, dns_until_apt=True)
        assert out.returncode == 0, out.stdout + out.stderr
        assert "collect-name=France - Paris\n" in out.stdout, out.stdout
    # A rerun with the same broken resolver still refuses before the withdrawal
    # (the withdrawal itself needs DNS for the hub).
    with tempfile.TemporaryDirectory(prefix="fx-med-n5-") as tmp:
        out, withdrawn = _main_until_withdrawal(tmp, AGREE, "", geo=OK_GEO, dns_until_apt=True)
        assert out.returncode != 0 and withdrawn is None, (out.stdout, withdrawn)


def test_main_runs_apt_install_between_withdrawal_and_collect_inputs():
    calls = [l.strip() for l in MAIN.splitlines()]
    order = [calls.index(n) for n in ("data_preflight_public_identity || exit 1",
                                      "begin_data_deployment_withdrawal_before_mutation",
                                      "apt_install", "collect_inputs")]
    assert order == sorted(order), order
    pre = function(SRC, "data_preflight_public_identity")
    guard = '  [[ -f "${NODE_ENV_FILE}" ]] || return 0\n'
    assert guard in pre and pre.index(guard) < pre.index("data_resolve_node_defaults"), pre


def _vpn_qdisc_seq(steps, devices=("awg0",), extra_env=None):
    """Like _vpn_qdisc, but several steps share one device state. A step is an
    argument list for the script, or ("recreate", dev, ifindex), which replaces
    the device with a new incarnation on the kernel-default qdisc."""
    results = []
    with tempfile.TemporaryDirectory(prefix="fx-med-qdisc-seq-") as tmp:
        sysdir = os.path.join(tmp, "sys-class-net")
        state = os.path.join(tmp, "state")
        stubs = os.path.join(tmp, "bin")
        for d in (sysdir, state, stubs):
            os.makedirs(d)
        for dev in devices:
            os.makedirs(os.path.join(sysdir, dev))
            with open(os.path.join(sysdir, dev, "ifindex"), "w") as fh:
                fh.write("7\n")
        calls = os.path.join(tmp, "calls")
        open(calls, "w").close()
        write_exec(os.path.join(stubs, "tc"), TC_STUB)
        write_exec(os.path.join(stubs, "ip"), '#!/usr/bin/env bash\nprintf "ip %s\\n" "$*" >> "${FX_CALLS}"\n')
        node_env = os.path.join(tmp, "node.env")
        with open(node_env, "w") as fh:
            fh.write('VPN_INTERFACES="awg0 amn0"\n')
        script = os.path.join(tmp, "wins-edge-hardening")
        write_exec(script, EDGE.replace("/sys/class/net/", sysdir + "/"))
        env = {"PATH": stubs + ":" + os.environ.get("PATH", "/usr/bin:/bin"), "FX_CALLS": calls,
               "FX_STATE": state, "FX_SYS": sysdir, "NODE_ENV_FILE": node_env,
               "WINSVPN_TEST_ROOT": os.path.join(tmp, "root")}
        env.update(extra_env or {})
        for step in steps:
            if step[0] == "recreate":
                _, dev, idx = step
                with open(os.path.join(sysdir, dev, "ifindex"), "w") as fh:
                    fh.write(f"{idx}\n")
                q = os.path.join(state, f"qdisc.{dev}")
                if os.path.exists(q):
                    os.remove(q)
                continue
            before = open(calls).read()
            out = subprocess.run([BASH, script, *step], env=env, capture_output=True, text=True, timeout=60)
            results.append((out, open(calls).read()[len(before):]))
        final = {}
        for dev in devices:
            idx = open(os.path.join(sysdir, dev, "ifindex")).read().strip()
            q = os.path.join(state, f"qdisc.{dev}")
            final[dev] = (idx, open(q).read().strip() if os.path.exists(q) else "default")
        return results, final


def _instance_arg(dev, ifindex, seqnum=100):
    # Render the udev rule's SYSTEMD_WANTS for one device incarnation, the way
    # udev substitutes $name and $attr{ifindex}, then take the %i part.
    start = SRC.index("\nwrite_edge_hardening_script() {\n")
    body = SRC[start:SRC.index("\nset_public_vpn_ingress_admission() {\n", start)]
    rule = heredoc(body, "cat > /etc/udev/rules.d/61-winsvpn-vpn-qdisc.rules <<'EOF_VPN_QDISC_UDEV'",
                   "EOF_VPN_QDISC_UDEV")
    wants = re.search(r'ENV\{SYSTEMD_WANTS\}\+="([^"]+)"', rule).group(1)
    unit = wants.replace("$name", dev).replace("$attr{ifindex}", str(ifindex)).replace("$env{SEQNUM}", str(seqnum))
    assert "$" not in unit, unit
    assert unit.startswith("wins-vpn-qdisc@") and unit.endswith(".service"), unit
    return unit[len("wins-vpn-qdisc@"):-len(".service")]


def test_each_device_incarnation_gets_its_own_unit_instance():
    # N-2 (Sol): a recreation must never be able to merge into a running job for
    # the previous incarnation. Distinct ifindex -> distinct unit instance.
    assert _instance_arg("awg0", 7) != _instance_arg("awg0", 99)
    assert _instance_arg("awg0", 7, 100) == "awg0:7:100"
    # Sol (Turn 3): a recreation that REUSES the ifindex is a new uevent, so it
    # is still a new instance and cannot merge into the running one.
    assert _instance_arg("awg0", 7, 100) != _instance_arg("awg0", 7, 101)


def test_same_ifindex_recreation_during_a_run_is_still_calibrated():
    # Sol's Turn 3 sequence: event 100 for incarnation 7 runs; awg0 is
    # recreated with the SAME ifindex 7 (kernel default qdisc); event 101
    # requests its own instance, which runs and calibrates the new device.
    results, final = _vpn_qdisc_seq([
        ["--vpn-qdisc-only", _instance_arg("awg0", 7, 100)],
        ("recreate", "awg0", 7),
        ["--vpn-qdisc-only", _instance_arg("awg0", 7, 101)]])
    assert all(o.returncode == 0 for o, _ in results), [o.stdout + o.stderr for o, _ in results]
    assert final["awg0"][0] == "7" and "flow_limit 256" in final["awg0"][1], final


def test_recreation_after_the_last_check_is_still_calibrated():
    # Sol's sequence: incarnation 7's run completes (its final check passed),
    # then awg0 is recreated as incarnation 99. Its own instance runs and must
    # leave the NEW device calibrated.
    results, final = _vpn_qdisc_seq([
        ["--vpn-qdisc-only", _instance_arg("awg0", 7)],
        ("recreate", "awg0", 99),
        ["--vpn-qdisc-only", _instance_arg("awg0", 99)]])
    (first, _), (second, _) = results
    assert first.returncode == 0 and "incarnation 7" in first.stdout, first.stdout + first.stderr
    assert second.returncode == 0 and "incarnation 99" in second.stdout, second.stdout + second.stderr
    assert final["awg0"][0] == "99" and "flow_limit 256" in final["awg0"][1], final


def test_stale_incarnation_instance_does_nothing():
    results, final = _vpn_qdisc_seq([("recreate", "awg0", 99), ["--vpn-qdisc-only", "awg0:7"]])
    (out, calls), = results
    assert out.returncode == 0 and "incarnation 7 is gone" in out.stdout, out.stdout + out.stderr
    assert "qdisc replace" not in calls, calls
    assert final["awg0"] == ("99", "default"), final


def test_recreation_during_a_bound_run_hands_over_to_the_new_instance():
    results, final = _vpn_qdisc_seq([["--vpn-qdisc-only", "awg0:7"]], extra_env={"FX_RECREATE_ONCE": "1"})
    (out, calls), = results
    assert out.returncode == 0, out.stdout + out.stderr
    assert "was recreated while incarnation 7" in out.stdout and "verified" not in out.stdout, out.stdout
    results, final = _vpn_qdisc_seq([["--vpn-qdisc-only", "awg0:7"], ["--vpn-qdisc-only", "awg0:7"]],
                                    extra_env={"FX_SHOW_DEFAULT": "1"})
    assert all(o.returncode == 1 for o, _ in results), [o.stdout for o, _ in results]


def test_bound_argument_forms_are_strict():
    for bad in ("awg0:", "awg0:0", "awg0:x", "awg0:7:0", "awg0:7:x", "awg0:7:1:2", "awg0:7:", "eth0:7", ":7"):
        results, _ = _vpn_qdisc_seq([["--vpn-qdisc-only", bad]])
        (out, calls), = results
        assert out.returncode == 2 and "qdisc replace" not in calls, (bad, out.stdout + out.stderr)
    for good in ("awg0:7", "awg0:7:123", "awg0:7:18446744073709551615"):
        results, _ = _vpn_qdisc_seq([["--vpn-qdisc-only", good]])
        (out, _calls), = results
        assert out.returncode == 0 and "incarnation 7" in out.stdout, (good, out.stdout + out.stderr)


def test_vpn_qdisc_mode_applies_and_verifies_one_interface():
    out, calls = _vpn_qdisc(["--vpn-qdisc-only", "awg0"], devices=("awg0", "amn0"))
    assert out.returncode == 0, out.stdout + out.stderr + calls
    assert "tc qdisc replace dev awg0 root fq limit 20480 flow_limit 256 " in calls, calls
    assert "verified on awg0" in out.stdout, out.stdout
    assert "FIREWALL-OR-SYSTEM" not in calls, calls
    assert "amn0" not in calls, calls


def test_vpn_qdisc_mode_fails_when_the_read_back_is_the_kernel_default():
    out, calls = _vpn_qdisc(["--vpn-qdisc-only", "awg0"], extra_env={"FX_SHOW_DEFAULT": "1"})
    assert out.returncode == 1, out.stdout + out.stderr
    assert "does not carry the calibrated settings" in out.stdout + out.stderr
    assert "FIREWALL-OR-SYSTEM" not in calls, calls


def test_vpn_qdisc_mode_rejects_foreign_interfaces_and_skips_absent_ones():
    for bad in ("eth0", "", "awg0;id", "winn3gw0"):
        out, calls = _vpn_qdisc(["--vpn-qdisc-only", bad])
        assert out.returncode == 2, (bad, out.stdout + out.stderr)
        assert "tc " not in calls and "FIREWALL-OR-SYSTEM" not in calls, (bad, calls)
    out, calls = _vpn_qdisc(["--vpn-qdisc-only", "amn0"], devices=("awg0",))
    assert out.returncode == 0, out.stdout + out.stderr
    assert "qdisc replace" not in calls and "FIREWALL-OR-SYSTEM" not in calls, calls


def test_vpn_qdisc_mode_reapplies_after_a_mid_run_recreation():
    out, calls = _vpn_qdisc(["--vpn-qdisc-only", "awg0"], extra_env={"FX_RECREATE_ONCE": "1"})
    assert out.returncode == 0, out.stdout + out.stderr + calls
    assert calls.count("tc qdisc replace dev awg0 root") == 2, calls


def test_installer_writes_the_udev_rule_and_template_unit():
    # The function embeds whole scripts whose own functions close at column 0,
    # so take it up to the next top-level function instead.
    start = SRC.index("\nwrite_edge_hardening_script() {\n")
    body = SRC[start:SRC.index("\nset_public_vpn_ingress_admission() {\n", start)]
    unit = heredoc(body, "cat > /etc/systemd/system/wins-vpn-qdisc@.service <<'EOF_VPN_QDISC_UNIT'",
                   "EOF_VPN_QDISC_UNIT")
    rule = heredoc(body, "cat > /etc/udev/rules.d/61-winsvpn-vpn-qdisc.rules <<'EOF_VPN_QDISC_UDEV'",
                   "EOF_VPN_QDISC_UDEV")
    assert "ExecStart=/usr/local/bin/wins-edge-hardening --vpn-qdisc-only %i\n" in unit, unit
    assert "Type=oneshot" in unit and "RemainAfterExit" not in unit and "[Install]" not in unit, unit
    rules = [l for l in rule.splitlines() if l and not l.startswith("#")]
    assert rules == ['ACTION=="add", SUBSYSTEM=="net", KERNEL=="awg0|amn0", TAG+="systemd", '
                     'ENV{SYSTEMD_WANTS}+="wins-vpn-qdisc@$name:$attr{ifindex}:$env{SEQNUM}.service"'], rules
    reload_at = body.index("udevadm control --reload")
    assert body.index("61-winsvpn-vpn-qdisc.rules") < reload_at < body.rindex("systemctl daemon-reload")


# --------------------------------------------------------------------------
# IA-DP-08: heartbeat waits out AdGuard (ordering + bounded retry) and weekly
# maintenance waits for local DNS after restarting it.
REGISTER = heredoc(SRC, "cat > /usr/local/bin/wins-node-register <<'EOF'", "EOF")
WEEKLY = heredoc(SRC, "cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'", "EOF")


def test_register_unit_is_ordered_after_adguard_without_pulling_it_in():
    unit = heredoc(SRC, "cat > /etc/systemd/system/wins-node-register.service <<'EOF'", "EOF")
    after = [l for l in unit.splitlines() if l.startswith("After=")]
    assert after and "AdGuardHome.service" in after[0].split("=", 1)[1].split(), unit
    assert not any(l.startswith(("Wants=", "Requires=")) and "AdGuardHome" in l for l in unit.splitlines()), unit


def test_post_registration_retries_transient_failures_with_bounds():
    with tempfile.TemporaryDirectory(prefix="fx-med-reg-") as tmp:
        calls = os.path.join(tmp, "calls")
        prog = "\n".join([
            "set -Eeuo pipefail",
            f'curl() {{ printf "%s\\n" "$*" >> "{calls}"; cat >> "{calls}.stdin"; echo "{{}}"; }}',
            'payload=\'{"secret_token":"fixture"}\'',
            function(REGISTER, "post_registration"),
            'post_registration https://hub.example.test/api/v1/nodes/register'])
        out = bash(prog)
        assert out.returncode == 0, out.stderr
        argv = open(calls).read()
        for flag in ("--retry 6", "--retry-delay 5", "--retry-max-time 60", "--max-time 30", "--connect-timeout 10"):
            assert flag in argv, (flag, argv)
        assert "--retry-all-errors" not in argv, argv
        assert "fixture" not in argv and "fixture" in open(calls + ".stdin").read()


def test_weekly_maintenance_waits_for_local_dns_after_adguard_restart():
    lines = WEEKLY.splitlines()
    restart = lines.index('run_step "restart AdGuardHome" systemctl restart AdGuardHome')
    assert lines[restart + 1:restart + 5].count(
        'run_step "wait for local DNS after the AdGuardHome restart" wait_for_local_dns') == 1
    assert WEEKLY.index("wait_for_local_dns\n", WEEKLY.index("restart AdGuardHome")) < WEEKLY.index("register node heartbeat")
    fn = function(WEEKLY, "wait_for_local_dns")
    with tempfile.TemporaryDirectory(prefix="fx-med-dns-") as tmp:
        count = os.path.join(tmp, "count")
        for answer_after, want in ((3, 0), (10_000, 1)):
            with open(count, "w") as fh:
                fh.write("0")
            prog = "\n".join([
                "set -Eeuo pipefail", "sleep() { :; }",
                # dig prints its failures to STDOUT (N-1); a CNAME line alone is
                # not an answer either.
                f'dig() {{ n=$(( $(cat "{count}") + 1 )); echo "$n" > "{count}"; '
                f'printf "%s\\n" "$*" >> "{count}.args"; '
                f'if (( n >= {answer_after} )); then printf "hub-cname.example.test.\\n203.0.113.5\\n"; '
                f'elif (( n == 1 )); then echo "hub-cname.example.test."; '
                f'else echo ";; connection timed out; no servers could be reached"; return 9; fi; }}',
                'HUB_DOMAIN="hub.example.test"', fn,
                'if wait_for_local_dns; then echo rc=0; else echo rc=1; fi'])
            out = bash(prog)
            assert f"rc={want}" in out.stdout, (answer_after, out.stdout, out.stderr)
            n = int(open(count).read().split()[0])
            assert n == (3 if want == 0 else 30), n
            assert "@127.0.0.1 hub.example.test" in open(count + ".args").read()


def test_no_dig_check_treats_any_output_as_an_answer():
    # N-1: `[[ -n "$(dig ...)" ]]` is true for dig's own ";; connection timed
    # out" line. Every readiness check must look for an IPv4 answer instead.
    assert '[[ -n "$(dig' not in SRC, "a dig readiness check still accepts any output"
    ipv4 = "grep -Eq '^([0-9]{1,3}\\.){3}[0-9]{1,3}$'"
    adguard = SRC[SRC.index("\ninstall_adguard() {\n"):]
    adguard = adguard[:adguard.index('echo "nameserver 127.0.0.1" > /etc/resolv.conf')]
    for target in ("@127.0.0.1 raw.githubusercontent.com", '@"${ADGUARD_DNS_BIND_DEFAULT}" raw.githubusercontent.com'):
        at = adguard.index(target)
        assert adguard.rfind(ipv4, 0, at) > adguard.rfind("&&", 0, at - 80), (target, adguard[at - 200:at + 60])
    wait = function(WEEKLY, "wait_for_local_dns")
    assert ipv4 in wait, wait


def test_vpn_qdisc_unit_is_not_start_rate_limited():
    start = SRC.index("\nwrite_edge_hardening_script() {\n")
    body = SRC[start:SRC.index("\nset_public_vpn_ingress_admission() {\n", start)]
    unit = heredoc(body, "cat > /etc/systemd/system/wins-vpn-qdisc@.service <<'EOF_VPN_QDISC_UNIT'",
                   "EOF_VPN_QDISC_UNIT")
    head = unit.split("[Service]")[0]
    assert "StartLimitIntervalSec=0\n" in head, unit


# --------------------------------------------------------------------------
# OI-DPMED-1: refusable reads run before the hub withdrawal.
MAIN = function(SRC, "main")


def _opt(name):
    return [function(SRC, name)] if f"\n{name}() {{\n" in SRC else []


def _main_until_withdrawal(tmp, curl_answers, node_name, geo=None, continue_collect=False,
                           first_install=False, jq_until_apt=False, dns_until_apt=False):
    """Run main's own text from check_not_hub through the withdrawal call on a
    deployed-node rerun (node.env loaded with an explicit environment
    override), optionally continuing into collect_inputs up to its name check.
    Returns (proc, withdrawal marker text or None)."""
    marker = os.path.join(tmp, "WITHDRAWN")
    count = os.path.join(tmp, "choose_calls")
    env_file = os.path.join(tmp, "node.env")
    if not first_install:
        with open(env_file, "w") as fh:
            fh.write('NODE_SLUG="lab-node"\nNODE_NAME="Old Name"\nNODE_TOKEN="fixture-token"\n')
        os.chmod(env_file, 0o600)
    apt_done = os.path.join(tmp, "APT_DONE")
    seg = MAIN[MAIN.index("  check_not_hub\n"):]
    seg = seg[:seg.index("  begin_data_deployment_withdrawal_before_mutation\n")] + \
        "  begin_data_deployment_withdrawal_before_mutation\n"
    collect = function(SRC, "collect_inputs")
    collect = collect[:collect.index("  maybe_prompt_or_default NODE_FLAG")] + \
        '  printf "collect-name=%s\\n" "${NODE_NAME}"\n  printf "collect-slug=%s\\n" "${NODE_SLUG}"\n}\n'
    collect = collect.replace("collect_inputs() {", "collect_prefix() {", 1)
    table = "\n".join(f'    "{u}") printf "%s\\n" "{v}" ;;' for u, v in curl_answers.items())
    geo_arm = '    https://ipapi.co/*) [[ -n "${FAKE_GEO:-}" ]] && printf "%s" "${FAKE_GEO}" || return 22 ;;'
    # N-5: a broken resolver until apt_install's ensure_bootstrap_dns repairs it.
    dns_gate = (f'  [[ -e "{apt_done}" ]] || {{ echo "curl: (6) Could not resolve host" >&2; return 6; }}'
                if dns_until_apt else "  :")
    # N-4: a minimal image has no jq until apt_install installs it.
    jq_stub = (f'jq() {{ [[ -e "{apt_done}" ]] || {{ echo "jq: command not found" >&2; return 127; }}; command jq "$@"; }}'
               if jq_until_apt else ":")
    prog = "\n".join([
        "set -Eeuo pipefail", ERR, WARN, LOG, "stat() { echo 0; }", "find() { :; }",
        function(SRC, "load_existing_node_env"),
        function(SRC, "valid_ipv4"), function(SRC, "detect_public_ipv4"),
        function(SRC, "sanitize_slug"), function(SRC, "flag_from_country_code"),
        function(SRC, "geo_node_defaults"), function(SRC, "known_node_defaults"),
        function(SRC, "resolve_a_records"), function(SRC, "host_resolves_to_ip"),
        function(SRC, "choose_auto_node_defaults"), function(SRC, "maybe_prompt_or_default"),
        # Optional so an older installer fails on the ordering, not on a lookup.
        *_opt("valid_node_display_name"), *_opt("data_resolve_node_defaults"),
        *_opt("data_preflight_public_identity"),
        'eval "$(declare -f choose_auto_node_defaults | sed "1s/choose_auto_node_defaults/real_choose_auto_node_defaults/")"',
        f'choose_auto_node_defaults() {{ echo x >> "{count}"; real_choose_auto_node_defaults "$@"; }}',
        'hostname() { case "${1:-}" in -s) echo lab-node ;; *) return 1 ;; esac; }',
        'curl() { local url="${@: -1}"', dns_gate, '  case "${url}" in', table, geo_arm, '    *) return 7 ;; esac; }',
        jq_stub, f'apt_install_stub() {{ touch "{apt_done}"; }}',
        "check_not_hub() { :; }", "verify_disk_encryption_posture() { :; }",
        "data_management_tunnel_rerun_gate() { :; }",
        "data_print_disk_encryption_guarantee() { :; }",
        f'begin_data_deployment_withdrawal_before_mutation() {{ echo "ip=${{DATA_DETECTED_PUBLIC_IPV4:-}} name=${{NODE_NAME:-}}" > "{marker}"; }}',
        f'NODE_ENV_FILE="{env_file}"', 'NODE_DEFAULTS_FILE=/nonexistent', 'DNS_BASE_DOMAIN=""',
        'DATA_DETECTED_PUBLIC_IPV4=""',
        f'load_existing_node_env "{env_file}"',
        "run_main_segment() {", seg, "}",
        collect,
        "run_main_segment",
        *(["apt_install_stub", "collect_prefix",
           f'printf "choose_calls=%s\\n" "$(wc -l < "{count}" | tr -d " ")"'] if continue_collect else [])])
    env = {"NODE_NAME": node_name}
    if geo is not None:
        env["FAKE_GEO"] = geo
    out = bash(prog, env=env)
    return out, (open(marker).read() if os.path.exists(marker) else None)


AGREE = {A: "198.51.100.7", B: "198.51.100.7"}


def test_rerun_with_failing_ip_detection_never_withdraws():
    for answers in ({A: "198.51.100.7", B: "203.0.113.9"}, {D: "203.0.113.9"}, {}):
        with tempfile.TemporaryDirectory(prefix="fx-med-order-") as tmp:
            out, withdrawn = _main_until_withdrawal(tmp, answers, "France - Paris")
            assert out.returncode != 0, (answers, out.stdout)
            assert withdrawn is None, (answers, "withdrawal ran before the refusal")
    with tempfile.TemporaryDirectory(prefix="fx-med-order-") as tmp:
        out, withdrawn = _main_until_withdrawal(tmp, AGREE, 'Legacy "quoted" name')
        assert out.returncode != 0 and withdrawn is None, (out.stdout, withdrawn)
    # Control: agreeing sources and a valid name reach the withdrawal, and the
    # detected address is what collect_inputs will reuse.
    with tempfile.TemporaryDirectory(prefix="fx-med-order-") as tmp:
        out, withdrawn = _main_until_withdrawal(tmp, AGREE, "France - Paris")
        assert out.returncode == 0, out.stdout + out.stderr
        assert withdrawn == "ip=198.51.100.7 name=France - Paris\n", withdrawn


LONG_GEO = '{"city": "' + "C" * 125 + '", "country_name": "France", "country_code": "FR"}'
OK_GEO = '{"city": "Paris", "country_name": "France", "country_code": "FR"}'


def test_empty_name_override_resolves_the_effective_name_before_withdrawal():
    # N-3 (Sol): NODE_NAME="" survives load_existing_node_env on a rerun, and the
    # automatic default ("France - " + 125 characters = 134) is invalid. The
    # refusal must come before the withdrawal, not in collect_inputs after it.
    with tempfile.TemporaryDirectory(prefix="fx-med-n3-") as tmp:
        out, withdrawn = _main_until_withdrawal(tmp, AGREE, "", geo=LONG_GEO, continue_collect=True)
        assert out.returncode != 0, out.stdout
        assert withdrawn is None, ("withdrawn before the name refusal", withdrawn, out.stdout)
        assert "NODE_NAME must be" in out.stdout, out.stdout
    # A valid automatic default becomes the effective name before the
    # withdrawal, collect_inputs keeps it, and the defaults are resolved once.
    with tempfile.TemporaryDirectory(prefix="fx-med-n3-") as tmp:
        out, withdrawn = _main_until_withdrawal(tmp, AGREE, "", geo=OK_GEO, continue_collect=True)
        assert out.returncode == 0, out.stdout + out.stderr
        assert withdrawn == "ip=198.51.100.7 name=France - Paris\n", withdrawn
        assert "collect-name=France - Paris\n" in out.stdout, out.stdout
        assert "choose_calls=1\n" in out.stdout, out.stdout
    # The explicit empty override really survives node.env (the precondition).
    with tempfile.TemporaryDirectory(prefix="fx-med-n3-") as tmp:
        out, withdrawn = _main_until_withdrawal(tmp, AGREE, "", geo=None, continue_collect=True)
        assert out.returncode == 0, out.stdout + out.stderr
        assert withdrawn == "ip=198.51.100.7 name=lab-node\n", withdrawn


# --------------------------------------------------------------------------
# OI-DPMED-2: the hub token is validated and escaped before node.env.
def test_persist_node_token_escapes_hub_text():
    with tempfile.TemporaryDirectory(prefix="fx-med-token-") as tmp:
        marker = os.path.join(tmp, "PWNED")
        env_file = os.path.join(tmp, "node.env")
        with open(env_file, "w") as fh:
            fh.write('NODE_SLUG="lab-node"\nNODE_TOKEN=""\nADMIN_TOKEN="old"\n')
        token = f'tok$(touch {marker})`touch {marker}2`"\\\nINJECTED=1'
        prog = "\n".join([
            "set -Eeuo pipefail", function(SRC, "write_env_kv"), function(SRC, "persist_node_token"),
            f'NODE_ENV_FILE="{env_file}"', 'persist_node_token "$1"',
            f'source "{env_file}"', 'printf "%s|%s|%s" "${NODE_TOKEN}" "${ADMIN_TOKEN}" "${INJECTED-unset}"'])
        out = bash(prog, args=[token])
        assert out.returncode == 0, out.stderr
        assert not os.path.exists(marker) and not os.path.exists(marker + "2"), "sourcing node.env ran the token"
        assert out.stdout == token.replace("\n", " ") + "||unset", out.stdout
        text = open(env_file).read()
        assert text.count("NODE_TOKEN=") == 1 and text.count("ADMIN_TOKEN=") == 1, text


def _bootstrap(tmp, hub_token):
    env_file = os.path.join(tmp, "node.env")
    with open(env_file, "w") as fh:
        fh.write('NODE_SLUG="lab-node"\nNODE_TOKEN=""\n')
    prog = "\n".join([
        "set -Eeuo pipefail", ERR, WARN, LOG, function(SRC, "write_env_kv"),
        function(SRC, "persist_node_token"), function(SRC, "bootstrap_node_token"),
        'curl() { jq -cn --arg t "${FAKE_TOKEN}" \'{ok:true,node_token:$t}\'; }',
        f'NODE_ENV_FILE="{env_file}"', 'NODE_SLUG="lab-node"', 'NODE_TOKEN=""',
        'NODE_BOOTSTRAP_TOKEN="grant-0123456789abcdefghijklmnopqrstuv"',
        'HUB_API_BASE="https://hub.example.test"', "bootstrap_node_token"])
    out = bash(prog, env={"FAKE_TOKEN": hub_token})
    return out, open(env_file).read()


def test_bootstrap_refuses_a_token_outside_the_hub_alphabet():
    good = "Ab0_-" * 12 + "Zz9_"  # 64 URL-safe characters, like token_urlsafe(48)
    with tempfile.TemporaryDirectory(prefix="fx-med-boot-") as tmp:
        out, text = _bootstrap(tmp, good)
        assert out.returncode == 0, out.stdout + out.stderr
        assert f'NODE_TOKEN="{good}"' in text, text
    for bad in ("short_token", "tok$(id)" + "a" * 40, "a" * 40 + "`id`", "a" * 40 + " b", "a" * 257, "a" * 40 + "\nX=1"):
        with tempfile.TemporaryDirectory(prefix="fx-med-boot-") as tmp:
            out, text = _bootstrap(tmp, bad)
            assert out.returncode != 0, bad
            assert 'NODE_TOKEN=""' in text and "$(" not in text, text
            assert bad not in out.stdout + out.stderr or len(bad) < 12, "token echoed"


# --------------------------------------------------------------------------
# OI-DPMED-5: the IA-DP-06 detection keys on two artifacts that exist only
# after bootstrap_node_token; pin that order and the single writer of each.
def test_partial_install_artifacts_are_written_only_after_bootstrap():
    calls = [l.strip() for l in MAIN.splitlines()]
    def at(name):
        assert calls.count(name) == 1, (name, calls.count(name))
        return calls.index(name)
    boot = at("bootstrap_node_token")
    assert at("begin_data_deployment_withdrawal_before_mutation") < boot
    assert at("write_node_local_serving_guard") > boot
    assert at("write_register_script") > boot
    main_names = {c for c in calls if re.fullmatch(r"[a-z_][a-z0-9_]*", c)}
    defs = sorted((m.start(), m.group(1)) for m in re.finditer(r"^([a-z_][a-z0-9_]*)\(\) \{$", SRC, re.M)
                  if m.group(1) in main_names)
    for writer, owner in (('install -o root -g root -m 700 "${guard_tmp}" /usr/local/sbin/wins-node-local-serving',
                           "write_node_local_serving_guard"),
                          ("cat > /usr/local/bin/wins-node-register <<", "write_register_script")):
        assert SRC.count(writer) == 1, writer
        pos = SRC.index(writer)
        enclosing = [name for start, name in defs if start < pos][-1]
        assert enclosing == owner, (writer, enclosing)


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    print(f"FX-DP-MED data-plane regressions against {SCRIPT}")
    for t in TESTS:
        check(t.__name__, t)
    for name, tb in FAILURES:
        print(f"\n--- {name}\n{tb}")
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    sys.exit(1 if FAILURES else 0)
