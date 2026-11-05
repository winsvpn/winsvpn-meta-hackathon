#!/usr/bin/env bash
set -Eeuo pipefail
# Runs as root in a disposable Linux container or VM with systemd as PID 1 and
# a writable /run/netns (Ubuntu 24.04 is the reference). Several sections start
# transient systemd units, create network namespaces and load real firewall
# rules, so never run it on a deployed host. It also reads two files outside
# server/ and tools/: .env.example and lib/main.dart.
# WINS_RUNTIME_SUITE_KEEP_GOING=1 runs every section below even after one
# fails, reports each, and still exits 1 if any failed.
#
# Most expectations here are bare commands under `set -e`, so a failed one used
# to abort the whole run silently. Name the failing line and command instead.
# Only while errexit is on: negative checks run under `set +e` and fail on
# purpose, and ERR fires for them too.
trap '[[ $- == *e* ]] && echo "FAIL ${BASH_SOURCE[0]##*/}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTROL_SCRIPT="${ROOT_DIR}/server/wins_control_plane_setup_ONETOUCH.sh"
DATA_SCRIPT="${ROOT_DIR}/server/wins_data_plane_setup_ONETOUCH.sh"
CORE_SCRIPT="${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh"
COWRIE_HONEYPOT_SCRIPT="${ROOT_DIR}/server/wins_cowrie_honeypot_ONETOUCH.sh"
WINDOWS_PRESEED_SCRIPT="${ROOT_DIR}/tools/wins_deployment_preseed.ps1"

for command_name in nginx openssl python3 runuser suricata ssh-keygen jq ip unshare sqlite3 age tc; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "Missing runtime validator dependency: ${command_name}" >&2
    exit 1
  }
done
[[ "$(id -u)" == "0" ]] || {
  echo "The runtime validator must run as root (network namespaces, firewall rules, transient units)." >&2
  exit 1
}
[[ -d /run/systemd/system ]] || {
  echo "The runtime validator needs systemd as PID 1; start the container with /sbin/init." >&2
  exit 1
}
missing_inputs=()
for input_name in .env.example lib/main.dart; do
  [[ -f "${ROOT_DIR}/${input_name}" ]] || missing_inputs+=("${input_name}")
done
((${#missing_inputs[@]} == 0)) || {
  echo "Missing repository inputs outside server/ and tools/: ${missing_inputs[*]}" >&2
  exit 1
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
chmod 755 "${work_dir}"

extract_heredoc() {
  local script="$1" needle="$2" terminator="$3"
  awk -v needle="${needle}" -v terminator="${terminator}" '
    index($0, needle) { capture=1; next }
    capture && $0 == terminator { exit }
    capture { print }
  ' "${script}"
}

# The installer writes wins-edge-hardening from a heredoc and then prepends the
# shared guard functions it calls (winn3_prepend_shared_functions, with the
# names it passes), so a node runs that prepended file. Tests that run the
# script extract it the same way. A bare heredoc has no wins_late_failure_hold.
extract_edge_hardening() {
  local script="$1" out="$2"
  local -a shared=()
  extract_heredoc "${script}" "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'" WINS_EDGE_EOF > "${out}"
  read -r -a shared < <(sed -n 's#^  winn3_prepend_shared_functions /usr/local/bin/wins-edge-hardening ##p' "${script}")
  ((${#shared[@]} > 0)) || { echo "extract_edge_hardening: ${script} names no shared functions for wins-edge-hardening" >&2; return 1; }
  (
    # The installer parses its own arguments when sourced; give it none.
    set --
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${script}")
    winn3_prepend_shared_functions "${out}" "${shared[@]}"
  )
}

# WINS_RUNTIME_SUITE_KEEP_GOING=1: run each top-level line below the section
# marker in its own errexit subshell, in order and sharing work_dir, so one
# failing section cannot hide the others. Every section is reported and the
# run exits 1 if any failed.
run_sections_keep_going() {
  local suite="$1" marker='# Top-level sections (keep-going mode runs each line below).'
  local start call total=0 failed=0 rc
  local -a failures=()
  # Never call this function from a condition (if, ||, &&): bash then ignores
  # errexit inside every section and a failing check would not stop it.
  start="$(grep -nFx -- "${marker}" "${suite}" | cut -d: -f1 || true)"
  [[ "${start}" =~ ^[0-9]+$ ]] || { echo "keep-going: section marker not found exactly once" >&2; return 1; }
  while IFS= read -r call; do
    [[ "${call}" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "${call}" == 'echo "Deployment runtime configuration simulation passed."' ]] && continue
    [[ "${call}" != *\\ ]] || { echo "keep-going: cannot run a continued line: ${call}" >&2; return 1; }
    total=$((total + 1))
    set +e
    (
      set -Eeuo pipefail
      trap '[[ $- == *e* ]] && echo "FAIL ${BASH_SOURCE[0]##*/}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
      eval "${call}"
    ) < /dev/null
    rc=$?
    set -e
    if ((rc == 0)); then
      echo "KEEP-GOING ${total} PASS ${call}"
    else
      failed=$((failed + 1))
      failures+=("${call} (rc=${rc})")
      echo "KEEP-GOING ${total} FAIL rc=${rc} ${call}" >&2
    fi
  done < <(tail -n "+$((start + 1))" "${suite}")
  echo "KEEP-GOING sections=${total} passed=$((total - failed)) failed=${failed}"
  ((total > 0)) || { echo "keep-going: no sections found" >&2; return 1; }
  ((failed == 0)) || { printf 'KEEP-GOING failed: %s\n' "${failures[@]}" >&2; return 1; }
}

# Lane L9: Suricata reads nfq.mode only from a YAML mapping. A list renders as
# nfq.0.mode, which Suricata 8 ignores, and it then runs in terminal
# ACCEPT/DROP mode, so every rule below a queue rule is skipped for queued
# packets. Check both the parsed type and what Suricata itself resolves.
nfq_repeat_mapping_check() {
  local cfg="$1" dump
  shift
  python3 - "${cfg}" <<'PYEOF' || return 1
import sys
import yaml

nfq = (yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}).get("nfq")
if not isinstance(nfq, dict):
    sys.exit(f"nfq parses as {type(nfq).__name__}, not a mapping")
if nfq.get("mode") != "repeat" or nfq.get("repeat-mark") != 0x40000000 \
        or nfq.get("repeat-mask") != 0x40000000:
    sys.exit(f"nfq is not repeat mode with the 0x40000000 queue-rule mark: {nfq}")
PYEOF
  dump="$("$@" --dump-config -c "${cfg}" 2>/dev/null)" || return 1
  grep -Fxq 'nfq.mode = repeat' <<<"${dump}" || {
    echo "suricata --dump-config does not resolve nfq.mode = repeat" >&2
    return 1
  }
  grep -Fxq 'nfq.repeat-mark = 1073741824' <<<"${dump}" || return 1
  grep -Fxq 'nfq.repeat-mask = 1073741824' <<<"${dump}" || return 1
  ! grep -Eq '^nfq\.[0-9]+' <<<"${dump}" || return 1
}

assert_nfq_repeat_mode() {
  local role="$1" cfg="$2"
  shift 2
  local mutant="${cfg%.yaml}.nfq-list-mutant.yaml"
  nfq_repeat_mapping_check "${cfg}" "$@" || {
    echo "${role} Suricata nfq is not a repeat-mode mapping" >&2
    return 1
  }
  # Anti-vacuity: the installer's pre-L9 list form must be rejected.
  python3 - "${cfg}" "${mutant}" <<'PYEOF'
import sys
from pathlib import Path
import yaml

data = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
data["nfq"] = [data["nfq"]]
Path(sys.argv[2]).write_text("%YAML 1.1\n---\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PYEOF
  chmod 644 "${mutant}"
  if nfq_repeat_mapping_check "${mutant}" "$@" 2>/dev/null; then
    echo "${role} nfq repeat-mode check accepted the list-form mutant" >&2
    return 1
  fi
}

# Owner ruling CS2: the data-plane fail-open default is the value write_env
# stores in node.env, which wins-edge-hardening then reads through
# EnvironmentFile=. Source the installer with the variable unset and with no
# defaults, secrets or node.env file, then run its own write_env_kv line.
assert_data_node_env_fail_open_default() {
  local script="$1" case_dir="$2" kv_line
  kv_line="$(grep -E '^[[:space:]]*write_env_kv SURICATA_NFQUEUE_FAIL_OPEN ' "${script}" || true)"
  [[ "$(grep -c . <<<"${kv_line}")" == 1 ]] || {
    echo 'data installer must write SURICATA_NFQUEUE_FAIL_OPEN to node.env exactly once' >&2
    return 1
  }
  (
    unset SURICATA_NFQUEUE_FAIL_OPEN
    export WINS_DEFAULTS_FILE="${case_dir}/missing-fail-open-defaults.env"
    export WINS_SECRETS_FILE="${case_dir}/missing-fail-open-secrets.env"
    export NODE_ENV_FILE="${case_dir}/missing-fail-open-node.env"
    # The installer parses "$@" at top level; source it with no arguments.
    set --
    # shellcheck disable=SC1090
    source "${script}"
    NODE_ENV_KV_BUFFER=""
    eval "${kv_line}"
    [[ "${NODE_ENV_KV_BUFFER}" == 'SURICATA_NFQUEUE_FAIL_OPEN="1"'$'\n' ]] || {
      echo "data installer writes ${NODE_ENV_KV_BUFFER%$'\n'} to node.env, not the ruled fail-open default" >&2
      return 1
    }
  )
}

test_suricata_role() {
  local role="$1" script="$2" python_needle="$3"
  local role_dir="${work_dir}/${role}-suricata"
  local cfg="${role_dir}/suricata.yaml"
  local -a suricata_validator=(suricata)
  mkdir -p "${role_dir}/rules"
  chmod 755 "${role_dir}" "${role_dir}/rules"
  if [[ -r /etc/suricata/suricata.yaml ]]; then
    cp /etc/suricata/suricata.yaml "${cfg}"
  elif sudo -n test -r /etc/suricata/suricata.yaml 2>/dev/null; then
    # Only the source read needs elevation; cfg belongs to this test user.
    # shellcheck disable=SC2024
    sudo -n cat /etc/suricata/suricata.yaml > "${cfg}"
    # The stock config references sibling files below the root-only system directory.
    suricata_validator=(sudo -n suricata)
  else
    echo "Suricata runtime validation requires a readable /etc/suricata/suricata.yaml." >&2
    return 1
  fi

  if [[ "${role}" == "control" ]]; then
    extract_heredoc "${script}" "${python_needle}" PYEOF |
      python3 - "${cfg}" eth0 192.0.2.10/32 1 1
    python3 - "${cfg}" <<'PYEOF'
import sys
import yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
home_net = data["vars"]["address-groups"]["HOME_NET"]
eve = next(item["eve-log"] for item in data["outputs"] if "eve-log" in item)
assert "127.0.0.1/32" in home_net, home_net
assert eve["xff"] == {
    "enabled": True,
    "mode": "extra-data",
    "deployment": "reverse",
    "header": "CF-Connecting-IP",
}, eve["xff"]
PYEOF
  elif [[ "${role}" == "data" ]]; then
    extract_heredoc "${script}" "${python_needle}" PYEOF |
      python3 - "${cfg}" 192.0.2.20/32
    python3 - "${cfg}" <<'PYEOF'
import sys
import yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
home_net = data["vars"]["address-groups"]["HOME_NET"]
assert "127.0.0.1" not in home_net, home_net
PYEOF
  else
    extract_heredoc "${script}" "${python_needle}" PYEOF |
      python3 - "${cfg}" 192.0.2.30/32 10.9.0.0/16
    python3 - "${cfg}" <<'PYEOF'
import sys
import yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
home_net = data["vars"]["address-groups"]["HOME_NET"]
command = data["unix-command"]
eve = next(item["eve-log"] for item in data["outputs"] if "eve-log" in item)
assert "192.0.2.30/32" in home_net and "10.9.0.0/16" in home_net, home_net
assert command == {"enabled": True, "filename": "/var/run/suricata/suricata-command.socket"}
assert eve["enabled"] is True and eve["filename"] == "eve.json"
assert data["flow"]["memcap"] == "48mb"
assert data["stream"]["memcap"] == "48mb"
assert data["stream"]["reassembly"]["memcap"] == "96mb"
PYEOF
  fi
  # Literal source-code needles must retain their dollar expressions.
  # shellcheck disable=SC2016
  extract_heredoc "${script}" 'cat > "${local_rules}"' EOF > "${role_dir}/rules/wins-local.rules"
  : > "${role_dir}/rules/suricata.rules"
  local expected_sids
  if [[ "${role}" == "control" ]]; then
    expected_sids=$'sid:9900001\nsid:9900002\nsid:9900003\nsid:9900004\nsid:9900005'
  elif [[ "${role}" == "data" ]]; then
    expected_sids=$'sid:9910001\nsid:9910002\nsid:9910003\nsid:9910004\nsid:9910005'
  else
    expected_sids=$'sid:9920001\nsid:9920002\nsid:9920003\nsid:9920004\nsid:9920005'
  fi
  [[ "$(grep -Ec '^drop[[:space:]]' "${role_dir}/rules/wins-local.rules")" == "5" ]]
  [[ "$(grep -Eo 'sid:[0-9]+' "${role_dir}/rules/wins-local.rules" | sort)" == "${expected_sids}" ]]
  if grep -Eq '^(alert|pass|reject|rejectsrc|rejectdst|rejectboth)[[:space:]]' "${role_dir}/rules/wins-local.rules"; then false; fi

  local action_policy="${role_dir}/wins-suricata-action-policy"
  extract_heredoc "${script}" "cat > /usr/local/bin/wins-suricata-action-policy <<'EOF'" EOF \
    | sed "s#rules_dir=\"/var/lib/suricata/rules\"#rules_dir=\"${role_dir}/rules\"#" \
    > "${action_policy}"
  chmod 700 "${action_policy}"
  "${action_policy}"
  printf '%s\n' 'drop tcp any any -> any any (msg:"unexpected imported blocker"; sid:2210057; rev:1;)' \
    >> "${role_dir}/rules/suricata.rules"
  if "${action_policy}" >/dev/null 2>&1; then
    echo "${role} Suricata action policy accepted an unreviewed blocking SID" >&2
    return 1
  fi
  : > "${role_dir}/rules/suricata.rules"

  python3 - "${cfg}" "${role_dir}/rules" <<'PYEOF'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
data["default-rule-path"] = sys.argv[2]
data["default-log-dir"] = str(path.parent)
path.write_text("%YAML 1.1\n---\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PYEOF
  chmod 644 "${cfg}" "${role_dir}/rules/"*.rules
  "${suricata_validator[@]}" -T -c "${cfg}" >/dev/null
  if [[ "${role}" != "control" ]]; then
    assert_nfq_repeat_mode "${role}" "${cfg}" "${suricata_validator[@]}"
  fi
  if [[ "${role}" == "core" ]]; then
    # The Core postflight must accept the real mapping and refuse the list.
    local core_postflight_yaml="${role_dir}/core-postflight-suricata-yaml.py"
    extract_heredoc "${script}" "python3 - /etc/suricata/suricata.yaml <<'PYEOF'" PYEOF > "${core_postflight_yaml}"
    grep -Fq 'data.get("nfq")' "${core_postflight_yaml}"
    python3 "${core_postflight_yaml}" "${cfg}"
    if python3 "${core_postflight_yaml}" "${cfg%.yaml}.nfq-list-mutant.yaml" >/dev/null 2>&1; then
      echo "core postflight accepted the list-form nfq that Suricata ignores" >&2
      return 1
    fi
  fi
  grep -Eq '^ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0 ' "${script}"
  local nfqueue_posture="fail-closed"
  if [[ "${role}" == "data" ]]; then
    # Owner ruling, incident CS2 (2026-09-25): data planes fail open.
    # The installer's top-level default (what write_env puts in node.env) and
    # the generated wins-edge-hardening's own default are separate copies, and
    # a whole-file match is satisfied by either one alone, so require both.
    [[ "$(grep -cF 'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-1}"' "${script}")" == 2 ]]
    if grep -Fq 'SURICATA_NFQUEUE_FAIL_OPEN:-0}' "${script}"; then false; fi
    assert_data_node_env_fail_open_default "${script}" "${role_dir}"
    nfqueue_posture="fail-open"
  else
    grep -Fq 'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-0}"' "${script}"
  fi
  if [[ "${role}" == "control" ]]; then
    grep -Fq 'local -a nfqueue_target=(-j NFQUEUE --queue-num 0)' "${script}"
  else
    grep -Fq 'local -a nfqueue_target=(-m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0)' "${script}"
  fi
  grep -Fq 'nfqueue_target+=(--queue-bypass)' "${script}"
  if grep -Fq -- '-j NFQUEUE --queue-num 0 --queue-bypass' "${script}"; then
    echo "${role} has an unconditional fail-open NFQUEUE rule" >&2
    exit 1
  fi
  if [[ "${role}" == "data" ]]; then
    local generated_edge="${role_dir}/wins-edge-hardening"
    extract_heredoc "${script}" "cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'" WINS_EDGE_EOF > "${generated_edge}"
    bash -n "${generated_edge}"
    # Literal source-code needles must retain their dollar expressions.
    # shellcheck disable=SC2016
    grep -Fq 'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-1}"' "${generated_edge}"
    # shellcheck disable=SC2016
    grep -Fq 'write_env_kv SURICATA_NFQUEUE_FAIL_OPEN "${SURICATA_NFQUEUE_FAIL_OPEN:-$SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT}"' "${script}"
    # The public listener remains fail-closed on every dynamic fallback port.
    # The local Nginx-to-Xray WebSocket flow is deliberately not double-queued:
    # it contains only an accepted path followed by customer tunnel payload and
    # cannot expose TLS probes rejected before Nginx proxies the request.
    # shellcheck disable=SC2016
    grep -Fq 'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"' "${generated_edge}"
    # shellcheck disable=SC2016
    grep -Fq 'iptables -C WINVPN-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"' "${script}"
    grep -Fq 'the public packet stream up to Nginx TLS termination' "${generated_edge}"
    # Capture, then match (here and below): in `grep A | grep -q B` under
    # pipefail, grep -q exits on the first match, the writer dies of SIGPIPE
    # (141), and a present forbidden rule then reads as absent.
    local xray_inbound_rules
    # shellcheck disable=SC2016
    xray_inbound_rules="$(grep -F -- '--dport "${XRAY_INBOUND_PORT}"' "${generated_edge}")" || [[ $? == 1 ]]
    if grep -Fq 'NFQUEUE' <<<"${xray_inbound_rules}"; then
      echo 'data-plane firewall unexpectedly double-queues decrypted customer tunnel payload' >&2
      return 1
    fi
  elif [[ "${role}" == "core" ]]; then
    # Core queues its public TCP stealth transports before its
    # established-session shortcuts. Encrypted AmneziaWG UDP on
    # CORE_INGRESS_PORT is admitted directly instead, as on the data plane
    # (27faafd): Suricata cannot inspect it, and queueing it caused buffer
    # drops, handshake retries and latency. The decrypted Double VPN relay path
    # on the FORWARD chain is never queued (privacy invariant D-1).
    # shellcheck disable=SC2016
    grep -Fq 'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT' "${script}"
    # shellcheck disable=SC2016
    grep -Fq 'iptables -C WINVPN-CORE-INPUT -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT' "${script}"
    local core_ingress_rules core_forward_rules
    # shellcheck disable=SC2016
    core_ingress_rules="$(grep -F -- '--dport "${CORE_INGRESS_PORT}"' "${script}")" || [[ $? == 1 ]]
    # shellcheck disable=SC2016
    if grep -Fq '"${nfqueue_target[@]}"' <<<"${core_ingress_rules}"; then
      echo 'core firewall unexpectedly queues encrypted AmneziaWG UDP ingress to NFQUEUE' >&2
      return 1
    fi
    # shellcheck disable=SC2016
    grep -Fq 'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"' "${script}"
    # The decrypted relay path (FORWARD chain) must never be queued to Suricata:
    # no FORWARD rule may append the NFQUEUE target (privacy invariant D-1).
    core_forward_rules="$(grep -F -- '-A WINVPN-CORE-FORWARD' "${script}")" || [[ $? == 1 ]]
    # shellcheck disable=SC2016
    if grep -Fq '"${nfqueue_target[@]}"' <<<"${core_forward_rules}"; then
      echo 'core firewall unexpectedly queues the decrypted relay path to NFQUEUE' >&2
      return 1
    fi
    # Postflight enforces the same negative invariant at runtime.
    grep -Fq 'Decrypted Core relay traffic must never enter NFQUEUE.' "${script}"
    grep -Fq 'Core firewall was not changed because inline Suricata queue 0 is not healthy.' "${script}"
  fi
  echo "PASS ${role} Suricata NFQUEUE ${nfqueue_posture} default with explicit recovery override"
  if [[ "${role}" != "control" ]]; then
    echo "PASS ${role} Suricata nfq is a repeat-mode mapping (parsed type and --dump-config nfq.mode = repeat; list form rejected)"
  fi
}

test_nginx_transport_order() {
  local name="$1" transports="$2"
  local nginx_dir="${work_dir}/${name}-nginx"
  local listen_lines="" default_suffix=" default_server" route port security
  mkdir -p "${nginx_dir}/logs"
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "${nginx_dir}/origin.key" -out "${nginx_dir}/origin.crt" \
    -subj '/CN=transport.test' -addext 'subjectAltName=DNS:transport.test' \
    >/dev/null 2>&1
  while IFS= read -r route; do
    [[ -n "${route}" ]] || continue
    port="${route%%:*}"
    security="${route#*:}"
    if [[ "${security}" == "tls" ]]; then
      listen_lines+="    listen ${port} ssl http2${default_suffix};"$'\n'
    else
      listen_lines+="    listen ${port}${default_suffix};"$'\n'
    fi
    default_suffix=""
  done < <(tr ',' '\n' <<<"${transports}")
  cat > "${nginx_dir}/nginx.conf" <<EOF
pid ${nginx_dir}/nginx.pid;
error_log ${nginx_dir}/logs/error.log;
events { worker_connections 64; }
http {
  access_log off;
  # Keep nginx -t off the host's /var/lib/nginx (it chowns the compiled-in
  # temp directories to the default worker user).
  client_body_temp_path ${nginx_dir}/logs/body;
  proxy_temp_path ${nginx_dir}/logs/proxy;
  fastcgi_temp_path ${nginx_dir}/logs/fastcgi;
  uwsgi_temp_path ${nginx_dir}/logs/uwsgi;
  scgi_temp_path ${nginx_dir}/logs/scgi;
  server {
${listen_lines%$'\n'}
    server_name transport.test _;
    ssl_certificate ${nginx_dir}/origin.crt;
    ssl_certificate_key ${nginx_dir}/origin.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location = /healthz { return 200 'ok'; }
    location /wins-stealth-tunnel {
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_pass http://127.0.0.1:10085;
    }
  }
}
EOF
  nginx -t -c "${nginx_dir}/nginx.conf" -p "${nginx_dir}" >/dev/null
  echo "PASS Nginx ${name} transport order (${transports})"
}

# The two request-level oracles that let an active prober confirm a Win's VPN
# gateway THROUGH Cloudflare, where the raw-IP protections do not reach:
# /healthz answering 200 while every other path 404s, and a prefix-matched
# tunnel location that answered a plain GET differently from an unknown path.
# This test renders the installers' own artifacts, runs a real Nginx against
# them, and asserts on responses rather than on config text.
test_edge_probe_oracle_contract() {
  local dir="${work_dir}/edge-oracles"
  local token="fixture-only-never-a-real-token-01"
  mkdir -p "${dir}/conf.d" "${dir}/sites-enabled" "${dir}/logs"

  python3 - "${DATA_SCRIPT}" "${CORE_SCRIPT}" <<'PYEOF'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
core = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

for role, source, path_var, health in (
    ("data", data, "${XRAY_PATH}", '"ok"'),
    ("core", core, "${CORE_XRAY_PATH}", "'wins-core-ok'"),
):
    if f"location {path_var} {{" in source:
        raise SystemExit(f"{role} tunnel location is still a PREFIX match")
    if f"location = {path_var} {{" not in source:
        raise SystemExit(f"{role} tunnel location is not an exact match")
    tunnel = source.split(f"location = {path_var} {{", 1)[1].split("proxy_pass", 1)[0]
    if "$wins_ws_handshake = 0" not in tunnel or "return 404" not in tunnel:
        raise SystemExit(f"{role} tunnel location does not require a WebSocket upgrade")
    healthz = source.split("location = /healthz {", 1)[1].split("}", 1)[0]
    if "$wins_health_allowed = 0" not in healthz:
        raise SystemExit(f"{role} /healthz is not gated")
    if f"return 200 {health}" not in source:
        raise SystemExit(f"{role} health body changed; on-box consumers assert on it")
    # The gate must resolve to the same bare 404 an unknown path gets. Anything
    # else (403, a custom body, a distinct header set) is a new oracle.
    for blocked in (tunnel, healthz):
        if "return 403" in blocked or "deny all" in blocked:
            raise SystemExit(f"{role} gate answers with something other than 404")

# A regex-keyed map would let an operator token like "~." match everything.
if 'validate_health_probe_token' not in data:
    raise SystemExit("data plane does not validate NODE_HEALTH_PROBE_TOKEN")
if '^[A-Za-z0-9_-]{16,128}$' not in data:
    raise SystemExit("NODE_HEALTH_PROBE_TOKEN alphabet is not constrained")
PYEOF

  # Render the real artifacts: the installer's own generator function and its
  # own vhost heredoc, so nothing here is a hand-copied approximation.
  # Brace counting cannot delimit these functions: they embed Nginx map blocks
  # in heredocs, and those bodies contain bare `}` lines. Cut to the next
  # top-level function header instead.
  local extractor="${dir}/extract-function.py"
  cat > "${extractor}" <<'PYEOF'
import re
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith(sys.argv[2] + "() {"))
end = start + 1
while end < len(lines) and not re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{", lines[end]):
    end += 1
body = lines[start:end]
while body and (body[-1].strip() == "" or body[-1].startswith("#")):
    body.pop()
assert body[-1] == "}", body[-3:]
print("\n".join(body))
PYEOF
  local gates_script="${dir}/gen-gates.sh"
  {
    echo 'log() { :; }'
    echo 'err() { echo "ERR: $*" >&2; }'
    python3 "${extractor}" "${DATA_SCRIPT}" validate_health_probe_token
    python3 "${extractor}" "${DATA_SCRIPT}" write_nginx_edge_gates
    echo 'write_nginx_edge_gates'
  } > "${gates_script}"
  WINS_NGINX_HTTP_CONF_D="${dir}/conf.d" NODE_HEALTH_PROBE_TOKEN="${token}" \
    bash "${gates_script}"
  grep -Fq "\"${token}\" 1;" "${dir}/conf.d/31-wins-edge-gates.conf"

  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "${dir}/origin.key" -out "${dir}/origin.crt" \
    -subj '/CN=oracle.test' -addext 'subjectAltName=DNS:oracle.test' >/dev/null 2>&1
  local vhost
  vhost="$(extract_heredoc "${DATA_SCRIPT}" \
    'cat > /etc/nginx/sites-available/wins-node.conf <<EOF' EOF)"
  (
    STEALTH_HOST='oracle.test'
    alias_server_names=''
    NODE_HOST='203.0.113.10'
    XRAY_PATH='/wins-stealth-tunnel'
    XRAY_INBOUND_PORT='10085'
    NODE_MAX_PEERS='128'
    listen_lines='    listen 18081 default_server;'
    # The installer's heredoc consumes all seven through the eval below, and no
    # static analyser can see into that; naming them here is what makes it plain.
    : "${STEALTH_HOST}" "${alias_server_names}" "${NODE_HOST}" "${XRAY_PATH}" \
      "${XRAY_INBOUND_PORT}" "${NODE_MAX_PEERS}" "${listen_lines}"
    eval "cat > \"${dir}/sites-enabled/wins-node.conf\" <<WINS_VHOST_EOF
${vhost}
WINS_VHOST_EOF"
  )
  sed -i -e "s#/etc/winsvpn/node-origin/origin#${dir}/origin#g" \
         -e "s#/var/log/nginx/wins-node.error.log#${dir}/logs/error.log#" \
    "${dir}/sites-enabled/wins-node.conf"
  cat > "${dir}/conf.d/30-capacity.conf" <<'EOF'
limit_conn_zone $server_name zone=wins_xray_total:1m;
EOF
  cat > "${dir}/nginx.conf" <<EOF
pid ${dir}/nginx.pid;
error_log ${dir}/logs/error.log warn;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path ${dir}/logs/body;
  proxy_temp_path ${dir}/logs/proxy;
  fastcgi_temp_path ${dir}/logs/fastcgi;
  uwsgi_temp_path ${dir}/logs/uwsgi;
  scgi_temp_path ${dir}/logs/scgi;
  include ${dir}/conf.d/*.conf;
  include ${dir}/sites-enabled/*.conf;
}
EOF
  nginx -t -c "${dir}/nginx.conf" -p "${dir}" >/dev/null

  # A stub Xray that completes the upgrade, so a real handshake yields 101.
  python3 - "${dir}" <<'PYEOF' &
import socket
import sys
import threading

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 10085))
srv.listen(32)


def serve(conn):
    try:
        conn.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        if b"upgrade: websocket" in data.lower():
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\n\r\n")
        else:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    finally:
        conn.close()


with open(sys.argv[1] + "/stub.ready", "w") as handle:
    handle.write("1")
while True:
    client, _ = srv.accept()
    threading.Thread(target=serve, args=(client,), daemon=True).start()
PYEOF
  local stub_pid=$! attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [[ -e "${dir}/stub.ready" ]] && break
    sleep 0.2
  done
  [[ -e "${dir}/stub.ready" ]]
  nginx -c "${dir}/nginx.conf" -p "${dir}"
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [[ -s "${dir}/nginx.pid" ]] && break
    sleep 0.2
  done
  local nginx_pid
  nginx_pid="$(cat "${dir}/nginx.pid")"
  # shellcheck disable=SC2064
  trap "kill ${stub_pid} ${nginx_pid} 2>/dev/null || true; rm -rf '${work_dir}'" EXIT

  python3 - "${token}" <<'PYEOF'
import socket
import sys

PORT = 18081
token = sys.argv[1]


def request(raw):
    sock = socket.socket()
    sock.settimeout(5)
    sock.connect(("127.0.0.1", PORT))
    sock.sendall(raw.encode("ascii"))
    out = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            out += chunk
            sock.settimeout(0.4)
    except socket.timeout:
        pass
    finally:
        sock.close()
    text = out.decode("latin-1")
    return "\r\n".join(l for l in text.split("\r\n") if not l.lower().startswith("date:"))


def get(path, extra=""):
    return request("GET %s HTTP/1.1\r\nHost: oracle.test\r\nConnection: close\r\n%s\r\n"
                   % (path, extra))


def handshake(path):
    return request(
        "GET %s HTTP/1.1\r\nHost: oracle.test\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" % path)


unknown = get("/9c1f-not-a-real-path")
assert unknown.startswith("HTTP/1.1 404"), unknown.split("\r\n")[0]

# Loopback keeps its 200: wins-node-canary and validate_data_plane read it.
loopback_health = get("/healthz")
assert loopback_health.startswith("HTTP/1.1 200") and loopback_health.rstrip().endswith("ok"), \
    "loopback /healthz regressed: " + loopback_health.split("\r\n")[0]

# The token is what an off-box probe must present; this run is on loopback, so
# instead assert the blocked shapes that a prober would actually see.
for probe, label in (
    ("/wins-stealth-tunnel", "plain GET on the tunnel path"),
    ("/wins-stealth-tunnel/", "tunnel path with a trailing slash"),
    ("/wins-stealth-tunnel-extra", "tunnel path prefix extension"),
):
    body = get(probe)
    assert body == unknown, f"{label} is still an oracle: {body.split(chr(13))[0]}"

for extra, label in (
    ("Upgrade: websocket\r\nConnection: Upgrade\r\n", "upgrade without a key"),
    ("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "key without an upgrade"),
    ("Upgrade: h2c\r\nConnection: Upgrade\r\n", "a non-websocket upgrade"),
):
    body = get("/wins-stealth-tunnel", extra)
    assert body == unknown, f"{label} is still an oracle: {body.split(chr(13))[0]}"

# Every real client handshake must still reach Xray.
assert handshake("/wins-stealth-tunnel").startswith("HTTP/1.1 101"), \
    "the real client handshake no longer upgrades"
PYEOF

  kill "${stub_pid}" "${nginx_pid}" 2>/dev/null || true
  trap 'rm -rf "${work_dir}"' EXIT
  echo "PASS edge probe oracles closed: /healthz gated, tunnel exact-match and upgrade-gated, real handshake unaffected"
}

# The stealth half of /usr/local/sbin/wins-vpn-firewall used to log a warning
# and leave tcp/80 and tcp/443 open whenever the Cloudflare range fetch failed.
# Every branch below is executed, not inspected: a fail-closed change that has
# never been observed to fail closed is not a fix.
test_runtime_firewall_fails_closed() {
  local dir="${work_dir}/fw-fail-closed"
  local script="${dir}/wins-vpn-firewall"
  mkdir -p "${dir}/bin"
  extract_heredoc "${DATA_SCRIPT}" 'cat > "${script_tmp}" <<'"'"'WINS_VPN_FW_EOF'"'"'' WINS_VPN_FW_EOF \
    | sed -e 's|@WINVPN_FW_IFACES@|awg0 amn0|g' \
          -e 's|@WINVPN_FW_WAN_IF@|eth0|g' \
          -e 's|@WINVPN_FW_VPN_CIDR@|10.8.0.0/16|g' > "${script}"
  chmod +x "${script}"
  # `! cmd` is exempt from `set -e`, so these must be explicit.
  if grep -Fq 'leaving stealth ports OPEN' "${script}"; then
    echo "FAIL the stealth half still fails open on a failed Cloudflare fetch" >&2
    return 1
  fi
  if grep -q '@WINVPN_FW_[A-Z_]*@' "${script}"; then
    echo "FAIL the generated firewall carries an unsubstituted placeholder" >&2
    return 1
  fi

  cat > "${dir}/bin/iptables" <<'PYEOF'
#!/usr/bin/env python3
import json, os, sys
STATE = os.environ["MOCK_IPT_STATE"]
BASE = {"filter": ["INPUT", "FORWARD", "OUTPUT"],
        "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
        "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]}
state = json.load(open(STATE)) if os.path.exists(STATE) else \
    {t: {c: [] for c in v} for t, v in BASE.items()}
args, table, i = [], "filter", 0
argv = sys.argv[1:]
while i < len(argv):
    if argv[i] in ("-w", "--wait"):
        i += 2 if i + 1 < len(argv) and argv[i + 1].isdigit() else 1
        continue
    if argv[i] == "-t":
        table = argv[i + 1]; i += 2; continue
    args.append(argv[i]); i += 1
chains = state.setdefault(table, {c: [] for c in BASE.get(table, [])})
op = args[0]
if op == "-N":
    if args[1] in chains: sys.exit(1)
    chains[args[1]] = []
elif op == "-F":
    if args[1] not in chains: sys.exit(1)
    chains[args[1]] = []
elif op in ("-A", "-I", "-C"):
    chain, rest = args[1], args[2:]
    pos = 1
    if op == "-I" and rest and rest[0].isdigit():
        pos, rest = int(rest[0]), rest[1:]
    if chain not in chains: sys.exit(1)
    rule = " ".join(rest)
    if op == "-C": sys.exit(0 if rule in chains[chain] else 1)
    chains[chain].append(rule) if op == "-A" else chains[chain].insert(pos - 1, rule)
elif op == "-S":
    targets = [args[1]] if len(args) > 1 else sorted(chains)
    for chain in targets:
        if chain not in chains: sys.exit(1)
        for rule in chains[chain]:
            print("-A %s %s" % (chain, rule))
    sys.exit(0)
else:
    sys.exit(2)
json.dump(state, open(STATE, "w"))
PYEOF
  cat > "${dir}/bin/iptables-restore" <<'PYEOF'
#!/usr/bin/env python3
import json, os, sys
STATE = os.environ["MOCK_IPT_STATE"]
state = json.load(open(STATE)) if os.path.exists(STATE) else {}
table = "filter"
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#") or line == "COMMIT":
        continue
    if line.startswith("*"):
        table = line[1:]; state.setdefault(table, {}); continue
    chains = state.setdefault(table, {})
    if line.startswith(":"):
        chains.setdefault(line[1:].split()[0], []); continue
    parts = line.split()
    if parts[0] == "-F":
        chains[parts[1]] = []
    elif parts[0] == "-A":
        chains.setdefault(parts[1], []).append(" ".join(parts[2:]))
for base in ("INPUT", "FORWARD", "OUTPUT"):
    state.setdefault("filter", {}).setdefault(base, [])
for base in ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"):
    state.setdefault("nat", {}).setdefault(base, [])
for base in ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"):
    state.setdefault("mangle", {}).setdefault(base, [])
json.dump(state, open(STATE, "w"))
PYEOF
  chmod +x "${dir}/bin/iptables" "${dir}/bin/iptables-restore"

  cat > "${dir}/cf-good" <<'EOF'
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
EOF
  head -3 "${dir}/cf-good" > "${dir}/cf-truncated"
  printf '<!DOCTYPE html><title>502</title>\n' > "${dir}/cf-garbage"
  : > "${dir}/cf-empty"
  { cat "${dir}/cf-good"; echo '0.0.0.0/0'; } > "${dir}/cf-permissive"
  cat > "${dir}/txn" <<'EOF'
*filter
:INPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:WINVPN-FORWARD - [0:0]
:WINVPN-DOCKER - [0:0]
-A WINVPN-FORWARD -j DROP
COMMIT
*nat
:WINVPN-NAT-POSTROUTING - [0:0]
-A WINVPN-NAT-POSTROUTING -s 10.8.0.0/16 -o eth0 -j MASQUERADE
COMMIT
*mangle
:WINVPN-MANGLE-FORWARD - [0:0]
COMMIT
EOF

  local run_dir fw_rc
  fw_run() { # $1 = body fixture or "" for a hard fetch failure; $2 = cache seed
    run_dir="$(mktemp -d "${dir}/run.XXXXXX")"
    if [[ -z "${1}" ]]; then
      printf '#!/bin/sh\nexit 7\n' > "${run_dir}/curl"
    else
      printf '#!/bin/sh\ncat %q\n' "${1}" > "${run_dir}/curl"
    fi
    chmod +x "${run_dir}/curl"
    if [[ -n "${2:-}" ]]; then
      cp "${2}" "${run_dir}/cache"
    fi
    # A non-zero exit is the POINT of most of these runs, so it must be
    # captured rather than allowed to trip `set -e`.
    if MOCK_IPT_STATE="${run_dir}/ipt.json" \
       IPTABLES_BIN="${dir}/bin/iptables" \
       IPTABLES_RESTORE_BIN="${dir}/bin/iptables-restore" \
       CURL_BIN="${run_dir}/curl" \
       WINVPN_FW_TRANSACTION="${dir}/txn" \
       WINVPN_FW_CF_CACHE="${run_dir}/cache" \
         "${script}" > "${run_dir}/out" 2>&1; then
      fw_rc=0
    else
      fw_rc=$?
    fi
    return 0
  }
  fw_assert_closed() { # the only property that matters
    MOCK_IPT_STATE="${run_dir}/ipt.json" python3 - "$1" <<'PYEOF'
import json, os, sys
label = sys.argv[1]
state = json.load(open(os.environ["MOCK_IPT_STATE"]))
chain = state.get("filter", {}).get("WINVPN-STEALTH-CF", [])
jumps = state.get("filter", {}).get("INPUT", [])
assert any(r.endswith("-j WINVPN-STEALTH-CF") for r in jumps), \
    f"{label}: INPUT never jumps into the stealth chain, so tcp/80,443 are open"
assert chain, f"{label}: stealth chain is empty, so every packet falls back to INPUT ACCEPT"
assert chain[-1] == "-j DROP", f"{label}: stealth chain does not end in DROP: {chain[-1]}"
assert not any(r == "-s 0.0.0.0/0 -j RETURN" for r in chain), \
    f"{label}: an allow-everything RETURN was installed"
PYEOF
  }
  fw_range_count() {
    MOCK_IPT_STATE="${run_dir}/ipt.json" python3 -c '
import json, os
state = json.load(open(os.environ["MOCK_IPT_STATE"]))
print(sum(1 for r in state["filter"].get("WINVPN-STEALTH-CF", []) if r.startswith("-s ")))'
  }

  # A healthy fetch still works, and only a validated list is cached.
  fw_run "${dir}/cf-good" ""
  [[ ${fw_rc} -eq 0 ]]
  fw_assert_closed "healthy fetch"
  [[ "$(fw_range_count)" == 15 ]]
  diff -q "${run_dir}/cache" "${dir}/cf-good" >/dev/null

  # Every way the fetch can lie, plus a hard failure: refused, closed, loud.
  local scenario
  for scenario in "" "${dir}/cf-empty" "${dir}/cf-truncated" "${dir}/cf-garbage" "${dir}/cf-permissive"; do
    fw_run "${scenario}" ""
    [[ ${fw_rc} -ne 0 ]] || { echo "FAIL firewall stayed silent for '${scenario:-hard failure}'" >&2; return 1; }
    fw_assert_closed "${scenario:-hard failure}"
    [[ "$(fw_range_count)" == 0 ]] || {
      echo "FAIL firewall applied ranges from '${scenario}'" >&2; return 1; }
    [[ ! -e "${run_dir}/cache" ]] || {
      echo "FAIL firewall cached a bad response from '${scenario}'" >&2; return 1; }
  done

  # A failed fetch with a valid cache keeps the previous allowlist, audibly.
  fw_run "" "${dir}/cf-good"
  [[ ${fw_rc} -eq 0 ]]
  grep -Fq "from cache" "${run_dir}/out"
  grep -Fq "WARN: using the cached Cloudflare list" "${run_dir}/out"
  fw_assert_closed "cached fallback"
  [[ "$(fw_range_count)" == 15 ]]

  # A corrupted cache is refused rather than applied.
  fw_run "" "${dir}/cf-truncated"
  [[ ${fw_rc} -ne 0 ]]
  grep -Fq "cached Cloudflare list is itself invalid" "${run_dir}/out"
  fw_assert_closed "corrupt cache"
  [[ "$(fw_range_count)" == 0 ]]

  # No fetch and no cache, but a good live ruleset: keep it byte-identical.
  fw_run "${dir}/cf-good" ""
  local before after keep_dir="${run_dir}"
  before="$(MOCK_IPT_STATE="${run_dir}/ipt.json" python3 -c '
import json, os
print(json.load(open(os.environ["MOCK_IPT_STATE"]))["filter"]["WINVPN-STEALTH-CF"])')"
  rm -f "${keep_dir}/cache"
  printf '#!/bin/sh\nexit 7\n' > "${keep_dir}/curl"
  MOCK_IPT_STATE="${keep_dir}/ipt.json" \
  IPTABLES_BIN="${dir}/bin/iptables" \
  IPTABLES_RESTORE_BIN="${dir}/bin/iptables-restore" \
  CURL_BIN="${keep_dir}/curl" \
  WINVPN_FW_TRANSACTION="${dir}/txn" \
  WINVPN_FW_CF_CACHE="${keep_dir}/cache" \
    "${script}" > "${keep_dir}/out2" 2>&1 && {
      echo "FAIL firewall stayed silent when it could not refresh its allowlist" >&2; return 1; }
  grep -Fq "KEEPING the previously-applied stealth ruleset" "${keep_dir}/out2"
  run_dir="${keep_dir}"
  after="$(MOCK_IPT_STATE="${run_dir}/ipt.json" python3 -c '
import json, os
print(json.load(open(os.environ["MOCK_IPT_STATE"]))["filter"]["WINVPN-STEALTH-CF"])')"
  [[ "${before}" == "${after}" ]] || {
    echo "FAIL firewall modified the previously-applied ruleset it claimed to keep" >&2; return 1; }
  fw_assert_closed "preserved live ruleset"

  # The referenced chain is replaced by one restore transaction; no flush
  # or separate rule insertion may expose an intermediate empty chain.
  local trace="${dir}/trace" restore_trace="${dir}/restore-trace"
  : > "${trace}"
  : > "${restore_trace}"
  cat > "${dir}/bin/iptables-trace" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "${trace}"
exec "${dir}/bin/iptables" "\$@"
EOF
  cat > "${dir}/bin/iptables-restore-trace" <<EOF
#!/usr/bin/env bash
payload="\$(cat)"
printf '%s\n' "\${payload}" >> "${restore_trace}"
printf '%s\n' "\${payload}" | "${dir}/bin/iptables-restore" "\$@"
EOF
  chmod +x "${dir}/bin/iptables-trace" "${dir}/bin/iptables-restore-trace"
  run_dir="$(mktemp -d "${dir}/run.XXXXXX")"
  printf '#!/bin/sh\ncat %q\n' "${dir}/cf-good" > "${run_dir}/curl"
  chmod +x "${run_dir}/curl"
  MOCK_IPT_STATE="${run_dir}/ipt.json" \
  IPTABLES_BIN="${dir}/bin/iptables-trace" \
  IPTABLES_RESTORE_BIN="${dir}/bin/iptables-restore-trace" \
  CURL_BIN="${run_dir}/curl" \
  WINVPN_FW_TRANSACTION="${dir}/txn" \
  WINVPN_FW_CF_CACHE="${run_dir}/cache" \
    "${script}" >/dev/null 2>&1
  if grep -Eq -- '-(F|A|I) WINVPN-STEALTH-CF( |$)' "${trace}"; then
    echo "FAIL the stealth chain is changed outside its atomic transaction" >&2
    return 1
  fi
  python3 - "${restore_trace}" <<'PYEOF'
import sys
from pathlib import Path
commits = Path(sys.argv[1]).read_text().split("COMMIT")
stealth = [part for part in commits if ":WINVPN-STEALTH-CF - [0:0]" in part]
assert len(stealth) == 1, "stealth policy must use exactly one commit"
lines = [line for line in stealth[0].splitlines() if line.startswith("-A WINVPN-STEALTH-CF ")]
assert lines[-1] == "-A WINVPN-STEALTH-CF -j DROP"
assert sum(" -s " in line and line.endswith(" -j RETURN") for line in lines) == 15
PYEOF

  echo "PASS runtime firewall fails closed on every fetch, cache and ruleset failure"
}

test_data_canary_transport_urls() {
  local canary="${work_dir}/wins-node-canary"
  local helpers="${work_dir}/wins-node-canary-helpers"
  extract_heredoc "${DATA_SCRIPT}" "cat > /usr/local/bin/wins-node-canary <<'EOF'" EOF > "${canary}"
  sed -e '/^log "Node canary started/,$d' \
    -e "s#^LOG_FILE=.*#LOG_FILE=\"${work_dir}/node-canary.log\"#" \
    "${canary}" > "${helpers}"
  (
    # shellcheck disable=SC1090
    source "${helpers}"
    STEALTH_TRANSPORTS='443:none,80:tls,18080:none,18443:tls'
    STEALTH_PUBLIC_PORT=80
    XRAY_SECURITY=none
    [[ "$(local_origin_health_url)" == 'http://127.0.0.1:443/healthz' ]]
    [[ "$(public_health_url 127.0.0.1 443 none)" == 'http://127.0.0.1:443/healthz' ]]
    [[ "$(public_health_url 127.0.0.1 80 tls)" == 'https://127.0.0.1:80/healthz' ]]
    [[ "$(public_health_url 127.0.0.1 18080 none)" == 'http://127.0.0.1:18080/healthz' ]]
    [[ "$(public_health_url 127.0.0.1 18443 tls)" == 'https://127.0.0.1:18443/healthz' ]]
    [[ "$(public_websocket_url stealth.example 80 none /wins-stealth-tunnel)" == 'http://stealth.example/wins-stealth-tunnel' ]]
    [[ "$(public_websocket_url stealth.example 443 tls /wins-stealth-tunnel)" == 'https://stealth.example/wins-stealth-tunnel' ]]
    [[ "$(public_websocket_url stealth.example 18080 none /wins-stealth-tunnel)" == 'http://stealth.example:18080/wins-stealth-tunnel' ]]
    [[ "$(public_websocket_url stealth.example 18443 tls /wins-stealth-tunnel)" == 'https://stealth.example:18443/wins-stealth-tunnel' ]]
    unset STEALTH_TRANSPORTS
    STEALTH_PUBLIC_PORT=80
    XRAY_SECURITY=tls
    [[ "$(local_origin_health_url)" == 'https://127.0.0.1:80/healthz' ]]
  )
  grep -Fq "expected-websocket-status=101" "${canary}"
  grep -Fq "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "${canary}"
  echo "PASS data canary uses explicit Xray transport security and WebSocket upgrades on arbitrary ports"
}

test_data_automatic_stealth_hostname() {
  local helper="${work_dir}/data-stealth-host-helper"
  awk '
    /^cloudflare_default_stealth_host\(\)/ {capture=1}
    capture {print}
    capture && /^}/ {exit}
  ' "${DATA_SCRIPT}" > "${helper}"
  (
    # shellcheck disable=SC1090
    source "${helper}"
    NODE_SLUG='spain'
    CLOUDFLARE_STEALTH_ZONE_DEFAULT='app-cloud-sync.net'
    unset CLOUDFLARE_STEALTH_ZONE CLOUDFLARE_STEALTH_RECORD
    [[ "$(cloudflare_default_stealth_host)" == 'spain.app-cloud-sync.net' ]]
    CLOUDFLARE_STEALTH_RECORD='madrid.app-cloud-sync.net'
    [[ "$(cloudflare_default_stealth_host)" == 'madrid.app-cloud-sync.net' ]]
  )
  echo "PASS data-plane automatic TLS-capable stealth hostname"
}

test_control_transport_parser() {
  local app_source="${work_dir}/wins-hub-main.py"
  extract_heredoc "${CONTROL_SCRIPT}" 'cat > "${APP_DIR}/main.py" <<'\''PYEOF'\''' PYEOF > "${app_source}"
  python3 - "${app_source}" <<'PYEOF'
import ast
import ipaddress
import os
import sqlite3
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

source = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(source)
required_node_xray_identity_contract = (
    'xray_uuid: str = Field(default="", validation_alias=AliasChoices("xray_uuid", "xrayuuid"))',
    'add_column_if_missing(conn, "nodes", "xray_uuid", "TEXT")',
    'config_xray_uuid = (node.get("xray_uuid") or "").strip()',
    'Node xray_uuid must be a valid UUID when stealth_endpoint is enabled',
    'Selected node has no valid Xray identity registered.',
    'xray_uuid=excluded.xray_uuid',
)
missing_xray_contract = [item for item in required_node_xray_identity_contract if item not in source]
assert not missing_xray_contract, missing_xray_contract
assert 'config_xray_uuid = XRAY_UUID' not in source
function = next(
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "parse_xray_transports"
)
module = ast.Module(body=[function], type_ignores=[])
ast.fix_missing_locations(module)
namespace = {"Any": Any}
exec(compile(module, sys.argv[1], "exec"), namespace)
parse = namespace["parse_xray_transports"]

routes = [
    {"port": 443, "security": "none"},
    {"port": 80, "security": "tls"},
    {"port": 18080, "security": "none"},
    {"port": 18443, "security": "tls"},
]
assert parse(routes, 443, "none", strict=True) == routes
assert parse([], 80, "tls", strict=True) == [{"port": 80, "security": "tls"}]
assert parse([
    {"port": 443, "security": "none"},
    {"port": 443, "security": "tls"},
], 443, "none") == [{"port": 443, "security": "none"}]

invalid_cases = [
    ([{"port": 443, "security": "none"}, {"port": 443, "security": "tls"}], 443, "none"),
    ([{"port": 80, "security": "none"}], 443, "tls"),
    ([{"port": 80, "security": "reality"}], 80, "none"),
]
for value, port, security in invalid_cases:
    try:
        parse(value, port, security, strict=True)
    except ValueError:
        pass
    else:
        raise AssertionError((value, port, security))

support_nodes = [
    node for node in tree.body
    if (
        isinstance(node, ast.FunctionDef)
        and node.name in {"normalize_client_platform", "platform_support_metadata"}
    ) or (
        isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "APPLE_RELEASE_BLOCKERS" for target in node.targets)
    )
]
support_module = ast.Module(body=support_nodes, type_ignores=[])
ast.fix_missing_locations(support_module)
support_namespace = {
    "Any": Any,
    "DOUBLE_VPN_ENABLED": True,
    "FREE_ACCESS_ENABLED": True,
}
exec(compile(support_module, sys.argv[1], "exec"), support_namespace)
metadata = support_namespace["platform_support_metadata"]
linux = metadata("linux")["capabilities"]
android = metadata("android")["capabilities"]
ios = metadata("ios")["capabilities"]
assert linux["per_app_split_tunnel"] is True
assert linux["per_app_split_tunnel_scope"] == "launcher_cgroup"
assert linux["per_app_split_tunnel_requires_launcher"] is True
assert android["per_app_split_tunnel_scope"] == "native_os"
assert ios["per_app_split_tunnel"] is False
assert ios["per_app_split_tunnel_scope"] == "mdm_managed_only"
assert ios["per_app_split_tunnel_mdm_only"] is True

free_node_function_names = {
    "free_node_match_terms",
    "node_matches_free_access_defaults",
    "initial_node_free_access_enabled",
}
free_node_nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in free_node_function_names
]
assert {node.name for node in free_node_nodes} == free_node_function_names
free_node_module = ast.Module(body=free_node_nodes, type_ignores=[])
ast.fix_missing_locations(free_node_module)
free_node_namespace = {
    "sqlite3": sqlite3,
    "FREE_ACCESS_ENABLED": True,
    "FREE_ACCESS_NODE_SLUGS": [],
    "FREE_ACCESS_NODE_SLUG": "",
    "FREE_ACCESS_NODE_MATCHES": [],
}
exec(compile(free_node_module, sys.argv[1], "exec"), free_node_namespace)
free_conn = sqlite3.connect(":memory:")
free_conn.row_factory = sqlite3.Row
free_conn.execute("CREATE TABLE nodes (slug TEXT, free_access_enabled INTEGER DEFAULT 0)")
initial_free = free_node_namespace["initial_node_free_access_enabled"]
assert initial_free(free_conn, "first-plane") is True
free_conn.execute("INSERT INTO nodes VALUES ('first-plane', 1)")
assert initial_free(free_conn, "second-plane") is False
free_node_namespace["FREE_ACCESS_NODE_SLUGS"] = ["explicit-free"]
assert initial_free(free_conn, "explicit-free") is True
assert initial_free(free_conn, "unlisted-plane") is False
free_node_namespace["FREE_ACCESS_ENABLED"] = False
assert initial_free(free_conn, "explicit-free") is False

gateway_nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef)
    and node.name == "normalize_private_tunnel_gateway_ipv4"
]
assert len(gateway_nodes) == 1
gateway_module = ast.Module(body=gateway_nodes, type_ignores=[])
ast.fix_missing_locations(gateway_module)
gateway_namespace = {"Any": Any, "ipaddress": ipaddress}
exec(compile(gateway_module, sys.argv[1], "exec"), gateway_namespace)
normalize_gateway = gateway_namespace["normalize_private_tunnel_gateway_ipv4"]
assert normalize_gateway("10.8.1.1") == "10.8.1.1"
assert normalize_gateway("172.16.7.1") == "172.16.7.1"
assert normalize_gateway("192.168.50.1") == "192.168.50.1"
assert normalize_gateway("10.8.1.0") == ""
assert normalize_gateway("10.8.1.255") == ""
assert normalize_gateway("8.8.8.8") == ""
assert normalize_gateway("not-an-address") == ""

capacity_function_names = {
    "normalized_node_max_peers",
    "node_capacity_snapshot",
    "node_accepts_new_peer",
    "node_is_online_and_managed",
    "select_online_node",
    "node_v3_sessions_full",
    "allocate_internal_ip",
    "allocate_core_client_ip",
    "cleanup_stale_devices",
}
capacity_nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name in capacity_function_names
]
assert {node.name for node in capacity_nodes} == capacity_function_names
capacity_module = ast.Module(body=capacity_nodes, type_ignores=[])
ast.fix_missing_locations(capacity_module)

class TestHTTPException(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail

class TestBackgroundTasks:
    def __init__(self):
        self.tasks = []

    def add_task(self, function, *args):
        self.tasks.append((function, args))

def test_selection_generation(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("selection generation must be a string")
    return value

def test_node_field(node, key):
    return dict(node).get(key)

def test_protocol_eligible_slugs(conn, *_args, **_kwargs):
    return {
        str(row["slug"] or "").strip().lower()
        for row in conn.execute("SELECT slug FROM nodes").fetchall()
    }

reports = {}

capacity_namespace = {
    "Any": Any,
    "Optional": Optional,
    "sqlite3": sqlite3,
    "os": os,
    "HTTPException": TestHTTPException,
    "BackgroundTasks": TestBackgroundTasks,
    "DEFAULT_NODE_MAX_PEERS": 4096,
    "MAX_NODE_MAX_PEERS": 60000,
    "NODE_RUNTIME_PEER_RESERVE": 16,
    "VPN_CLIENT_POOL_THIRD_OCTET_MAX": 254,
    "STALE_DEVICE_RETENTION_DAYS": 90,
    "timedelta": timedelta,
    "utcnow": lambda: datetime(2026, 7, 17, tzinfo=timezone.utc),
    "remove_peer_from_node": lambda *_args: None,
    # cleanup_stale_devices now queues a durable peer revocation rather than
    # removing the peer inline; the outbox itself is not under test here.
    "queue_peer_revocation": lambda *_args: True,
    "extract_node_host": lambda endpoint: endpoint.rsplit(":", 1)[0],
    "typed_selection_generation": test_selection_generation,
    "_node_field": test_node_field,
    "WINN_PROTOCOL_V1": "winn-v1",
    "WINN_PROTOCOL_V3": "winn-v3",
    "is_free_node": lambda _node: True,
    "_protocol_eligible_slugs": test_protocol_eligible_slugs,
    "data_plane_sql": lambda _platform="": "",
    "node_is_operator_enabled": lambda node: dict(node).get("operator_enabled") == 1,
    "node_data_plane_is_available": lambda _node, _platform="": True,
    # P-8 steering (node_v3_sessions_full, the real function) reads a node's
    # stored performance report. A node has a report only when a test gives it
    # one below.
    "node_performance_report_fresh": lambda node, now=None: reports.get(dict(node).get("slug")),
    # The hub's own threshold, read from main.py, so the steering below runs
    # against the shipped value and not a copy of it.
    "NODE_V3_SESSIONS_FULL_PERCENT": next(
        node.value.value for node in tree.body
        if isinstance(node, ast.Assign)
        and [getattr(target, "id", None) for target in node.targets] == ["NODE_V3_SESSIONS_FULL_PERCENT"]
    ),
    "parse_iso_datetime": lambda _value: None,
}
exec(compile(capacity_module, sys.argv[1], "exec"), capacity_namespace)
conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row
conn.execute("CREATE TABLE devices (device_id TEXT, location_slug TEXT, vpn_internal_ip TEXT)")
conn.execute("CREATE TABLE nodes (slug TEXT, name TEXT, status TEXT, management_status TEXT, peer_count INTEGER, max_peers INTEGER, operator_enabled INTEGER DEFAULT 1, retired_at TEXT DEFAULT NULL)")
conn.executemany(
    "INSERT INTO nodes (slug, name, status, management_status, peer_count, max_peers) VALUES (?, ?, 'online', 'ok', ?, ?)",
    [("full", "Full", 1, 1), ("room", "Room", 0, 2)],
)
conn.execute("INSERT INTO devices VALUES ('existing', 'full', NULL)")
snapshot = capacity_namespace["node_capacity_snapshot"]
accepts = capacity_namespace["node_accepts_new_peer"]
select_node = capacity_namespace["select_online_node"]
full = conn.execute("SELECT * FROM nodes WHERE slug='full'").fetchone()
assert snapshot(conn, full) == (1, 1, 0)
assert accepts(conn, full) is False
assert capacity_namespace["node_v3_sessions_full"](conn, full) is False
assert select_node(conn, "auto")["slug"] == "room"
assert select_node(conn, "auto", existing_slug="full")["slug"] == "full"
assert select_node(conn, "full", existing_slug="full")["slug"] == "full"
assert select_node(conn, "full")["slug"] == "room"

# P-8, the real node_v3_sessions_full on winn/3 nodes: a node whose gateway
# carries NODE_V3_SESSIONS_FULL_PERCENT of its -max-sessions is full for a new
# assignment and is passed over while another node has room. When every other
# node is full or offline the first in the old order is still used, never none.
v3_conn = sqlite3.connect(":memory:")
v3_conn.row_factory = sqlite3.Row
v3_conn.execute("CREATE TABLE devices (device_id TEXT, location_slug TEXT, vpn_internal_ip TEXT, winn3_inner_v4 TEXT, updated_at TEXT)")
v3_conn.execute("CREATE TABLE nodes (slug TEXT, name TEXT, status TEXT, management_status TEXT, peer_count INTEGER, max_peers INTEGER, operator_enabled INTEGER DEFAULT 1, retired_at TEXT DEFAULT NULL, protocol_version TEXT DEFAULT '')")
v3_conn.executemany(
    "INSERT INTO nodes (slug, name, status, management_status, peer_count, max_peers, protocol_version) VALUES (?, ?, 'online', 'ok', 0, 100, 'winn-v3')",
    [("alpha", "Alpha"), ("bravo", "Bravo")],
)
v3_full = capacity_namespace["node_v3_sessions_full"]
alpha = v3_conn.execute("SELECT * FROM nodes WHERE slug='alpha'").fetchone()

def v3_report(carrying, maximum=1000, mode="active"):
    return {"gateway": {"mode": mode, "carrying": carrying, "max_sessions": maximum}}

# The smallest carrying count out of 1000 sessions that is full.
full_percent = capacity_namespace["NODE_V3_SESSIONS_FULL_PERCENT"]
assert 0 < full_percent <= 100, full_percent
full_edge = -(-1000 * full_percent // 100)
assert v3_full(v3_conn, alpha) is False
assert select_node(v3_conn, "auto")["slug"] == "alpha"
reports["alpha"] = v3_report(full_edge - 1)
assert v3_full(v3_conn, alpha) is False
assert select_node(v3_conn, "auto")["slug"] == "alpha"
reports["alpha"] = v3_report(full_edge)
assert v3_full(v3_conn, alpha) is True
assert select_node(v3_conn, "auto")["slug"] == "bravo"
v3_conn.execute("UPDATE nodes SET status = 'offline' WHERE slug = 'bravo'")
assert select_node(v3_conn, "auto")["slug"] == "alpha"
v3_conn.execute("UPDATE nodes SET status = 'online' WHERE slug = 'bravo'")
reports["bravo"] = v3_report(1000)
assert select_node(v3_conn, "auto")["slug"] == "alpha"
del reports["bravo"]
reports["alpha"] = v3_report(1000, mode="off")
assert v3_full(v3_conn, alpha) is False
reports["alpha"] = v3_report(1000, maximum=0)
assert v3_full(v3_conn, alpha) is False
reports["alpha"] = v3_report(1000)
v3_conn.execute("UPDATE nodes SET protocol_version = '' WHERE slug = 'alpha'")
alpha = v3_conn.execute("SELECT * FROM nodes WHERE slug='alpha'").fetchone()
assert v3_full(v3_conn, alpha) is False
reports.clear()
assert select_node(v3_conn, "auto")["slug"] == "alpha"

# Fill every remaining customer slot and prove new admission fails closed.
# Existing allocations may still reconnect at the ceiling because they do not
# consume another slot, but no automatic or explicitly selected new session is
# allowed to overrun a data plane.
conn.executemany(
    "INSERT INTO devices VALUES (?, 'room', NULL)",
    [("room-1",), ("room-2",)],
)
room = conn.execute("SELECT * FROM nodes WHERE slug='room'").fetchone()
assert snapshot(conn, room) == (2, 2, 0)
assert accepts(conn, room) is False
assert select_node(conn, "auto") is None
assert select_node(conn, "room", require_selected=True) is None
assert select_node(conn, "full", require_selected=True) is None
assert select_node(conn, "auto", existing_slug="full")["slug"] == "full"

# Exhaust the ordinary pool and prove the allocator fails closed instead of
# entering the Double VPN-reserved 10.8.255.0/24 range.
conn.execute("DELETE FROM devices")
conn.executemany(
    "INSERT INTO devices (vpn_internal_ip) VALUES (?)",
    ((f"10.8.{third}.{host}",) for third in range(1, 255) for host in range(2, 255)),
)
try:
    capacity_namespace["allocate_internal_ip"](conn)
except TestHTTPException as exc:
    assert exc.status_code == 503
    assert "No VPN addresses" in exc.detail
else:
    raise AssertionError("ordinary client allocator entered the reserved Double VPN subnet")

# System/Double VPN peers reported by the node heartbeat consume only the
# reviewed reserve. A low heartbeat cannot hide database assignments, while a
# high/spoofed heartbeat can only reduce capacity and therefore fails closed.
conn.execute("DELETE FROM devices")
conn.execute("DELETE FROM nodes")
conn.execute("INSERT INTO nodes (slug, name, status, management_status, peer_count, max_peers) VALUES ('reserve', 'Reserve', 'online', 'ok', 17, 2)")
conn.execute("INSERT INTO devices VALUES ('reserve-client', 'reserve', '10.8.1.3')")
reserve = conn.execute("SELECT * FROM nodes WHERE slug='reserve'").fetchone()
assert snapshot(conn, reserve) == (1, 2, 1)
conn.execute("UPDATE nodes SET peer_count=18 WHERE slug='reserve'")
reserve = conn.execute("SELECT * FROM nodes WHERE slug='reserve'").fetchone()
assert snapshot(conn, reserve) == (2, 2, 0)
assert accepts(conn, reserve) is False
conn.execute("UPDATE nodes SET peer_count=0 WHERE slug='reserve'")
conn.execute("INSERT INTO devices VALUES ('reserve-client-2', 'reserve', '10.8.1.4')")
reserve = conn.execute("SELECT * FROM nodes WHERE slug='reserve'").fetchone()
assert snapshot(conn, reserve) == (2, 2, 0)
conn.execute("UPDATE nodes SET peer_count=100000 WHERE slug='reserve'")
reserve = conn.execute("SELECT * FROM nodes WHERE slug='reserve'").fetchone()
assert snapshot(conn, reserve) == (99984, 2, 0)
assert select_node(conn, "auto") is None

# Purging a stale device must remove its active Double VPN assignment in the
# same transaction, preserve an inactive assignment whose device still exists,
# immediately release the 10.9.x IP, and omit all orphans from the Core view.
cleanup_conn = sqlite3.connect(":memory:")
cleanup_conn.row_factory = sqlite3.Row
cleanup_conn.executescript("""
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    account_number TEXT,
    client_public_key TEXT,
    last_seen TEXT,
    location_slug TEXT
);
CREATE TABLE nodes (slug TEXT PRIMARY KEY, endpoint TEXT, ssh_host TEXT);
CREATE TABLE double_vpn_assignments (
    device_id TEXT PRIMARY KEY,
    account_number TEXT,
    core_id TEXT,
    exit_slug TEXT,
    client_public_key TEXT,
    client_ip TEXT UNIQUE,
    status TEXT
);
CREATE TABLE users (account_number TEXT PRIMARY KEY, status TEXT);
CREATE TABLE core_exit_peers (core_id TEXT, exit_slug TEXT);
""")
cleanup_conn.execute("INSERT INTO nodes VALUES ('exit', 'exit.test:9110', 'exit.test')")
cleanup_conn.execute("INSERT INTO users VALUES ('acct', 'active')")
cleanup_conn.execute("INSERT INTO core_exit_peers VALUES ('core', 'exit')")
cleanup_conn.executemany(
    "INSERT INTO devices VALUES (?, 'acct', ?, ?, 'exit')",
    [
        ("stale", "stale-key", "2025-01-01T00:00:00+00:00"),
        ("current", "current-key", "2026-07-16T00:00:00+00:00"),
    ],
)
cleanup_conn.executemany(
    "INSERT INTO double_vpn_assignments VALUES (?, 'acct', 'core', 'exit', ?, ?, ?)",
    [
        ("stale", "stale-key", "10.9.1.2", "active"),
        ("current", "current-key", "10.9.1.3", "inactive"),
        ("historical-orphan", "orphan-key", "10.9.1.4", "active"),
    ],
)
manifest_query = """
    SELECT a.device_id
    FROM double_vpn_assignments a
    JOIN devices d ON d.device_id = a.device_id AND d.account_number = a.account_number
    JOIN users u ON u.account_number = a.account_number
    JOIN core_exit_peers e ON e.core_id = a.core_id AND e.exit_slug = a.exit_slug
    JOIN nodes n ON n.slug = a.exit_slug
    WHERE a.core_id = 'core' AND a.status = 'active' AND u.status = 'active'
"""
# Defense in depth: the migrated orphan is excluded even before cleanup; only
# the still-present (but now retention-stale) device can be advertised.
assert [row[0] for row in cleanup_conn.execute(manifest_query).fetchall()] == ["stale"]
cleanup_conn.commit()
cleanup_conn.execute("BEGIN IMMEDIATE")
removed = capacity_namespace["cleanup_stale_devices"](cleanup_conn, TestBackgroundTasks())
cleanup_conn.commit()
assert removed == 1
remaining = cleanup_conn.execute(
    "SELECT device_id, client_ip, status FROM double_vpn_assignments ORDER BY device_id"
).fetchall()
assert [tuple(row) for row in remaining] == [("current", "10.9.1.3", "inactive")]
assert capacity_namespace["allocate_core_client_ip"](cleanup_conn) == "10.9.1.2"
core_visible = cleanup_conn.execute(manifest_query).fetchall()
assert core_visible == []
cleanup_conn.execute(
    "INSERT INTO double_vpn_assignments VALUES "
    "('disabled-retention-orphan', 'acct', 'core', 'exit', 'disabled-key', '10.9.1.2', 'active')"
)
capacity_namespace["STALE_DEVICE_RETENTION_DAYS"] = 0
assert capacity_namespace["cleanup_stale_devices"](cleanup_conn) == 0
assert cleanup_conn.execute(
    "SELECT COUNT(*) FROM double_vpn_assignments WHERE device_id='disabled-retention-orphan'"
).fetchone()[0] == 0
assert cleanup_conn.execute(
    "SELECT COUNT(*) FROM double_vpn_assignments WHERE device_id='current' AND status='inactive'"
).fetchone()[0] == 1
capacity_namespace["STALE_DEVICE_RETENTION_DAYS"] = 90

# The production BEGIN IMMEDIATE pattern serializes admission and allocation.
# At one remaining customer slot, concurrent writers produce one complete row,
# never a collision or a partial over-capacity database state.
ordinary_fd, ordinary_path = tempfile.mkstemp(prefix="wins-capacity-", suffix=".sqlite")
os.close(ordinary_fd)
ordinary_seed = sqlite3.connect(ordinary_path)
ordinary_seed.executescript("""
PRAGMA journal_mode=WAL;
CREATE TABLE nodes (
    slug TEXT PRIMARY KEY,
    name TEXT,
    status TEXT,
    management_status TEXT,
    peer_count INTEGER,
    max_peers INTEGER
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    location_slug TEXT,
    vpn_internal_ip TEXT UNIQUE
);
INSERT INTO nodes VALUES ('near-full', 'Near Full', 'online', 'ok', 3, 4);
INSERT INTO devices VALUES ('seed-1', 'near-full', '10.8.1.3');
INSERT INTO devices VALUES ('seed-2', 'near-full', '10.8.1.4');
INSERT INTO devices VALUES ('seed-3', 'near-full', '10.8.1.5');
""")
ordinary_seed.commit()
ordinary_seed.close()
ordinary_results = []
ordinary_lock = threading.Lock()

def ordinary_worker(index):
    worker = sqlite3.connect(ordinary_path, timeout=30)
    worker.row_factory = sqlite3.Row
    try:
        worker.execute("BEGIN IMMEDIATE")
        node = worker.execute("SELECT * FROM nodes WHERE slug='near-full'").fetchone()
        if not capacity_namespace["node_accepts_new_peer"](worker, node):
            worker.rollback()
            result = "full"
        else:
            client_ip = capacity_namespace["allocate_internal_ip"](worker)
            worker.execute(
                "INSERT INTO devices VALUES (?, 'near-full', ?)",
                (f"concurrent-{index}", client_ip),
            )
            worker.commit()
            result = "ok"
    except Exception as exc:
        worker.rollback()
        result = f"error:{type(exc).__name__}"
    finally:
        worker.close()
    with ordinary_lock:
        ordinary_results.append(result)

ordinary_threads = [threading.Thread(target=ordinary_worker, args=(index,)) for index in range(8)]
for thread in ordinary_threads:
    thread.start()
for thread in ordinary_threads:
    thread.join()
assert ordinary_results.count("ok") == 1, ordinary_results
assert ordinary_results.count("full") == 7, ordinary_results
assert not [result for result in ordinary_results if result.startswith("error:")], ordinary_results
ordinary_check = sqlite3.connect(ordinary_path)
assert ordinary_check.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 4
assert ordinary_check.execute("SELECT COUNT(DISTINCT vpn_internal_ip) FROM devices").fetchone()[0] == 4
ordinary_check.close()
os.unlink(ordinary_path)

# Leave exactly one Double VPN client address. Concurrent writers again admit
# one complete assignment and every later writer receives the allocator's 503
# without inserting a partial or colliding row.
double_fd, double_path = tempfile.mkstemp(prefix="wins-double-capacity-", suffix=".sqlite")
os.close(double_fd)
double_seed = sqlite3.connect(double_path)
double_seed.execute("PRAGMA journal_mode=WAL")
double_seed.execute("CREATE TABLE double_vpn_assignments (device_id TEXT PRIMARY KEY, client_ip TEXT UNIQUE)")
double_seed.executemany(
    "INSERT INTO double_vpn_assignments VALUES (?, ?)",
    (
        (f"seed-{third}-{host}", f"10.9.{third}.{host}")
        for third in range(1, 256)
        for host in range(2, 255)
        if (third, host) != (1, 2)
    ),
)
double_seed.commit()
double_seed.close()
double_results = []
double_lock = threading.Lock()

def double_worker(index):
    worker = sqlite3.connect(double_path, timeout=30)
    worker.row_factory = sqlite3.Row
    try:
        worker.execute("BEGIN IMMEDIATE")
        client_ip = capacity_namespace["allocate_core_client_ip"](worker)
        worker.execute(
            "INSERT INTO double_vpn_assignments VALUES (?, ?)",
            (f"concurrent-{index}", client_ip),
        )
        worker.commit()
        result = "ok"
    except TestHTTPException as exc:
        worker.rollback()
        assert exc.status_code == 503
        result = "full"
    except Exception as exc:
        worker.rollback()
        result = f"error:{type(exc).__name__}"
    finally:
        worker.close()
    with double_lock:
        double_results.append(result)

double_threads = [threading.Thread(target=double_worker, args=(index,)) for index in range(8)]
for thread in double_threads:
    thread.start()
for thread in double_threads:
    thread.join()
assert double_results.count("ok") == 1, double_results
assert double_results.count("full") == 7, double_results
assert not [result for result in double_results if result.startswith("error:")], double_results
double_check = sqlite3.connect(double_path)
assert double_check.execute("SELECT COUNT(*) FROM double_vpn_assignments WHERE client_ip='10.9.1.2'").fetchone()[0] == 1
assert double_check.execute("SELECT COUNT(*) - COUNT(DISTINCT client_ip) FROM double_vpn_assignments").fetchone()[0] == 0
double_check.close()
os.unlink(double_path)

# Direct data-plane and physical Double VPN ingress defaults must remain
# disjoint; explicit registered endpoints may override either default.
assert 'wg_port: int = Field(default=9110' in source
assert 'split_host_port(core["ingress_endpoint"], 9210)' in source
PYEOF
  # The registration still carries the node's Xray UUID. IA-DP-02 (DP-HIGH)
  # hands it to jq through the environment, never argv (/proc/PID/cmdline is
  # world-readable), so an --arg copy of it is a regression too.
  grep -Fq -- 'WINS_REGISTER_XRAY_UUID="${XRAY_UUID}" jq -n' "${DATA_SCRIPT}"
  grep -Fq -- 'xray_uuid: $ENV.WINS_REGISTER_XRAY_UUID,' "${DATA_SCRIPT}"
  if grep -Fq -- '--arg xray_uuid' "${DATA_SCRIPT}"; then
    echo 'data registration passes the Xray UUID to jq on argv' >&2
    return 1
  fi
  grep -Fq -- "--write-out '%{http_code}'" "${DATA_SCRIPT}"
  grep -Fq -- 'NODE_CANARY_STRICT_PUBLIC=1 /usr/local/bin/wins-node-canary' "${DATA_SCRIPT}"
  echo "PASS control hub Xray, five-OS split-tunnel, and fail-closed capacity contracts"
}

test_data_capacity_calculator() {
  (
    export WINS_DEFAULTS_FILE="${work_dir}/missing-capacity-defaults.env"
    export WINS_SECRETS_FILE="${work_dir}/missing-capacity-secrets.env"
    export NODE_ENV_FILE="${work_dir}/missing-capacity-node.env"
    # shellcheck disable=SC1090
    source "${DATA_SCRIPT}"
    local automatic effective_capacity
    NGINX_WORKER_CONNECTIONS=32768
    NGINX_WORKER_NOFILE_LIMIT=65535
    NGINX_PROXY_HEADROOM_PERCENT=20
    nginx_worker_process_count() { printf '2'; }
    effective_capacity="$(nginx_effective_proxy_capacity)"
    [[ "${effective_capacity}" == "26214" ]]
    automatic="$(calculate_node_max_peers auto)"
    [[ "${automatic}" =~ ^[0-9]+$ ]]
    ((automatic >= 512 && automatic <= effective_capacity))
    [[ "$(calculate_node_max_peers 1)" == "1" ]]
    [[ "$(calculate_node_max_peers 26214)" == "26214" ]]
    if calculate_node_max_peers 0 >/dev/null 2>&1; then false; fi
    if calculate_node_max_peers 26215 >/dev/null 2>&1; then false; fi
    if calculate_node_max_peers unlimited >/dev/null 2>&1; then false; fi
  )
  echo "PASS data-plane automatic and explicit capacity bounds include Nginx proxy descriptors"
}

test_data_rerun_identity_contract() {
  local helper="${work_dir}/data-existing-node-env.sh"
  local existing_env="${work_dir}/existing-node.env"
  awk '
    /^load_existing_node_env\(\)/ {capture=1}
    capture {print}
    capture && /^}/ {exit}
  ' "${DATA_SCRIPT}" > "${helper}"
  cat > "${existing_env}" <<'EOF'
NODE_SLUG="spain-madrid"
NODE_NAME="Spain Madrid"
STEALTH_HOST="spain-madrid.app-cloud-sync.net"
NODE_SSH_HOST="node-spain-madrid.example.test"
XRAY_UUID="123e4567-e89b-42d3-a456-426614174000"
EOF
  chmod 600 "${existing_env}"
  (
    # shellcheck disable=SC1090
    source "${helper}"
    load_existing_node_env "${existing_env}"
    [[ "${NODE_SLUG}" == "spain-madrid" ]]
    [[ "${STEALTH_HOST}" == "spain-madrid.app-cloud-sync.net" ]]
    [[ "${XRAY_UUID}" == "123e4567-e89b-42d3-a456-426614174000" ]]
  )
  (
    export NODE_SLUG="intentional-rename"
    # shellcheck disable=SC1090
    source "${helper}"
    load_existing_node_env "${existing_env}"
    [[ "${NODE_SLUG}" == "intentional-rename" ]]
    [[ "${STEALTH_HOST}" == "spain-madrid.app-cloud-sync.net" ]]
  )
  echo "PASS data-plane rerun preserves identity while explicit overrides win"
}

test_data_pressure_admission() {
  local register_script="${work_dir}/wins-node-register-capacity"
  local pressure_helper="${work_dir}/wins-node-pressure-helper"
  extract_heredoc "${DATA_SCRIPT}" "cat > /usr/local/bin/wins-node-register <<'EOF'" EOF > "${register_script}"
  sed -n '/^node_status_from_pressure() {$/,/^}$/p' "${register_script}" > "${pressure_helper}"
  (
    # shellcheck disable=SC1090
    source "${pressure_helper}"
    [[ "$(node_status_from_pressure 1.0 4 1048576 262144)" == "online" ]]
    [[ "$(node_status_from_pressure 8.1 4 1048576 262144)" == "congested" ]]
    [[ "$(node_status_from_pressure 1.0 4 262143 262144)" == "congested" ]]
  )
  echo "PASS data-plane CPU and memory pressure admission gate"
}

prepare_fake_cloudflare_origin_ca() {
  local ca_dir="$1"
  mkdir -p "${ca_dir}"
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "${ca_dir}/ca.key" -out "${ca_dir}/ca.crt" \
    -subj '/O=Cloudflare/CN=Cloudflare Origin Test CA' >/dev/null 2>&1
}

# `! cmd` never trips errexit, so a negative expectation written that way can
# never fail. edge_refute makes the L41 negative checks load-bearing.
edge_refute() {
  if "$@"; then
    echo "FAIL expected failure: $*" >&2
    exit 1
  fi
}

# N-10. The hub edge helpers (core_edge_hub_call, the data-plane edge call and
# the generated ACME hook) hand curl its token header with
#   printf 'header = ...' | curl --config - ...
# and real curl reads that config from stdin. A mock curl that returns without
# reading it lets printf die of SIGPIPE when it loses the race, and under
# pipefail the call then reads as HTTP 000 (34 of 1200 calls under load, which
# showed up as a rare red section 16). Read stdin exactly when curl would.
mock_curl_read_stdin_config() {
  local prev="" arg
  for arg in "$@"; do
    if [[ "${arg}" == "-" && ( "${prev}" == "--config" || "${prev}" == "-K" ) ]]; then
      cat > /dev/null
      return 0
    fi
    prev="${arg}"
  done
  return 0
}

# L41: data planes and Cores no longer call Cloudflare. This fake stands in
# for the hub edge broker: it signs the posted CSR with a test "Origin CA" and
# answers in the broker's shape. It records the URL and argv so tests can prove
# the hub token never reaches curl's argv.
install_fake_edge_broker_curl() {
  local ca_dir="$1"
  FAKE_CLOUDFLARE_CA_DIR="${ca_dir}"
  curl() {
    mock_curl_read_stdin_config "$@"
    local arg payload_file="" output_file="" csr_text url=""
    local previous=""
    for arg in "$@"; do
      if [[ "${previous}" == "--data-binary" ]]; then
        payload_file="${arg#@}"
      elif [[ "${previous}" == "-o" ]]; then
        output_file="${arg}"
      fi
      [[ "${arg}" != http*://* ]] || url="${arg}"
      previous="${arg}"
    done
    printf '%s\n' "${url}" > "${FAKE_CLOUDFLARE_CA_DIR}/last-url"
    printf '%s\n' "$*" > "${FAKE_CLOUDFLARE_CA_DIR}/last-argv"
    [[ -n "${payload_file}" && -s "${payload_file}" ]]
    csr_text="$(jq -r '.csr' "${payload_file}")"
    printf '%s' "${csr_text}" > "${FAKE_CLOUDFLARE_CA_DIR}/request.csr"
    openssl x509 -req -in "${FAKE_CLOUDFLARE_CA_DIR}/request.csr" \
      -CA "${FAKE_CLOUDFLARE_CA_DIR}/ca.crt" \
      -CAkey "${FAKE_CLOUDFLARE_CA_DIR}/ca.key" \
      -CAcreateserial -days 60 -copy_extensions copyall \
      -out "${FAKE_CLOUDFLARE_CA_DIR}/issued.crt" >/dev/null 2>&1
    jq -n --rawfile certificate "${FAKE_CLOUDFLARE_CA_DIR}/issued.crt" \
      '{ok:true,certificate:$certificate,certificate_id:"test-cert"}' > "${output_file}"
    printf '200'
  }
}

test_data_origin_ca_contract() {
  (
    export WINS_DEFAULTS_FILE="${work_dir}/missing-data-defaults.env"
    export WINS_SECRETS_FILE="${work_dir}/missing-data-secrets.env"
    export NODE_ENV_FILE="${work_dir}/missing-node.env"
    export WINS_EDGE_LEGACY_ACME_CREDENTIALS="${work_dir}/missing-data-acme-credentials.ini"
    # shellcheck disable=SC1090
    source "${DATA_SCRIPT}"
    local case_dir="${work_dir}/data-origin-ca"
    mkdir -p "${case_dir}"
    prepare_fake_cloudflare_origin_ca "${case_dir}/ca"
    install_fake_edge_broker_curl "${case_dir}/ca"
    NODE_SLUG='node-test'
    NODE_TOKEN='node-token-must-not-enter-argv'
    HUB_API_BASE='https://hub.example.test'
    export CLOUDFLARE_ORIGIN_CA_VALIDITY_DAYS=30
    request_cloudflare_origin_certificate \
      "${case_dir}/origin.crt" "${case_dir}/origin.key" \
      transport.test backup.transport.test
    node_origin_cert_valid \
      "${case_dir}/origin.crt" "${case_dir}/origin.key" \
      transport.test backup.transport.test
    [[ "$(cat "${case_dir}/ca/last-url")" == 'https://hub.example.test/api/v1/nodes/node-test/edge/origin-certificate' ]]
    edge_refute grep -Fq "${NODE_TOKEN}" "${case_dir}/ca/last-argv"
    edge_refute grep -Fq 'api.cloudflare.com' "${case_dir}/ca/last-argv"
    openssl req -x509 -nodes -newkey rsa:2048 -days 60 \
      -keyout "${case_dir}/self.key" -out "${case_dir}/self.crt" \
      -subj '/CN=transport.test' -addext 'subjectAltName=DNS:transport.test' \
      >/dev/null 2>&1
    edge_refute node_origin_cert_valid "${case_dir}/self.crt" "${case_dir}/self.key" transport.test
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg output_file="" previous=""
      for arg in "$@"; do
        [[ "${previous}" != "-o" ]] || output_file="${arg}"
        previous="${arg}"
      done
      [[ -z "${output_file}" ]] || printf '%s\n' '{"detail":"Hostname is not bound to this subject"}' > "${output_file}"
      printf '403'
    }
    edge_refute request_cloudflare_origin_certificate \
      "${case_dir}/rejected.crt" "${case_dir}/rejected.key" transport.test
    # A failed Origin CA attempt must not leave a RETURN trap that crashes the
    # subsequent ACME fallback under `set -u`.
    post_origin_failure_probe() { :; }
    post_origin_failure_probe
    # A data plane refuses to run while it still carries a Cloudflare
    # credential, naming the variable and never its value.
    data_refuse_node_fleet_credentials
    # shellcheck disable=SC2034  # read indirectly (${!name}) by the refusal check
    CLOUDFLARE_API_TOKEN='canary-cloudflare-value'
    refusal="$(data_refuse_node_fleet_credentials 2>&1 || true)"
    [[ "${refusal}" == *'CLOUDFLARE_API_TOKEN'* && "${refusal}" != *'canary-cloudflare-value'* ]]
    edge_refute data_refuse_node_fleet_credentials 2>/dev/null
    unset CLOUDFLARE_API_TOKEN
    : > "${WINS_EDGE_LEGACY_ACME_CREDENTIALS}"
    edge_refute data_refuse_node_fleet_credentials 2>/dev/null
    rm -f -- "${WINS_EDGE_LEGACY_ACME_CREDENTIALS}"
    data_refuse_node_fleet_credentials
  )
  echo "PASS data-plane hub-brokered Origin CA issue, verify, fail-closed, and no-node-credential contract"
}

test_core_origin_ca_contract() {
  (
    export WINS_DEFAULTS_FILE="${work_dir}/missing-core-defaults.env"
    export WINS_SECRETS_FILE="${work_dir}/missing-core-secrets.env"
    export CORE_ENV_FILE="${work_dir}/missing-core.env"
    export WINS_EDGE_LEGACY_ACME_CREDENTIALS="${work_dir}/missing-core-acme-credentials.ini"
    # shellcheck disable=SC1090
    source "${CORE_SCRIPT}"
    local case_dir="${work_dir}/core-origin-ca"
    mkdir -p "${case_dir}"
    prepare_fake_cloudflare_origin_ca "${case_dir}/ca"
    install_fake_edge_broker_curl "${case_dir}/ca"
    CORE_ID='north-america-core-2'
    CORE_TOKEN='core-token-must-not-enter-argv'
    HUB_API_BASE='https://hub.example.test'
    export CLOUDFLARE_ORIGIN_CA_VALIDITY_DAYS=30
    request_cloudflare_core_origin_certificate \
      "${case_dir}/origin.crt" "${case_dir}/origin.key" core.transport.test
    core_origin_cert_valid \
      "${case_dir}/origin.crt" "${case_dir}/origin.key" core.transport.test
    [[ "$(cat "${case_dir}/ca/last-url")" == 'https://hub.example.test/api/v1/core/north-america-core-2/edge/origin-certificate' ]]
    edge_refute grep -Fq "${CORE_TOKEN}" "${case_dir}/ca/last-argv"
    edge_refute valid_dns_hostname 192.0.2.20
    valid_dns_hostname core.transport.test
    core_stealth_tls_required '80:none,443:tls'
    edge_refute core_stealth_tls_required '80:none,8080:none'
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg output_file="" previous=""
      for arg in "$@"; do
        [[ "${previous}" != "-o" ]] || output_file="${arg}"
        previous="${arg}"
      done
      [[ -z "${output_file}" ]] || printf '%s\n' '{"detail":"Cloudflare rejected the edge operation"}' > "${output_file}"
      printf '502'
    }
    edge_refute request_cloudflare_core_origin_certificate \
      "${case_dir}/rejected.crt" "${case_dir}/rejected.key" core.transport.test
    post_core_origin_failure_probe() { :; }
    post_core_origin_failure_probe
    CORE_ID='North America Core #2'
    CORE_STEALTH_ZONE='transport.test'
    [[ "$(default_core_stealth_host)" == 'north-america-core-2.transport.test' ]]
    CORE_ID='north-america-core-2'
    CORE_STEALTH_HOST="$(default_core_stealth_host)"
    CORE_REQUIRE_CLOUDFLARE_AUTOMATION=1
    unset ADMIN_TOKEN || true
    detect_public_ipv4() { printf '%s' '198.51.100.20'; }
    FAKE_CORE_DNS_REPLY='deny'
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg output_file="" previous="" url=""
      for arg in "$@"; do
        [[ "${previous}" != "-o" ]] || output_file="${arg}"
        [[ "${arg}" != http*://* ]] || url="${arg}"
        previous="${arg}"
      done
      case "${url}" in
        */api/v1/core/north-america-core-2/edge/hostnames)
          printf '%s\n' '{"ok":true,"zone":"transport.test","hostnames":["north-america-core-2.transport.test"]}' > "${output_file}"
          printf '200'
          ;;
        */api/v1/core/north-america-core-2/edge/dns)
          if [[ "${FAKE_CORE_DNS_REPLY}" == 'deny' ]]; then
            printf '%s\n' '{"detail":"Cloudflare rejected the edge operation"}' > "${output_file}"
            printf '502'
          else
            printf '%s\n' '{"ok":true,"records":{"north-america-core-2.transport.test":"created"}}' > "${output_file}"
            printf '200'
          fi
          ;;
        *)
          printf '%s\n' '{"detail":"unexpected mock request"}' > "${output_file}"
          printf '404'
          ;;
      esac
    }
    edge_refute cloudflare_upsert_core_stealth_record
    FAKE_CORE_DNS_REPLY='allow'
    cloudflare_upsert_core_stealth_record
    # A Core bound to no such hostname stops before any DNS request.
    CORE_STEALTH_HOST='other.transport.test'
    edge_refute cloudflare_upsert_core_stealth_record
    # shellcheck disable=SC2034  # read indirectly (${!name}) by the refusal check
    CLOUDFLARE_ORIGIN_CA_API_TOKEN='canary-cloudflare-value'
    edge_refute core_refuse_node_fleet_credentials 2>/dev/null
    unset CLOUDFLARE_ORIGIN_CA_API_TOKEN
    core_refuse_node_fleet_credentials
  )
  echo "PASS core hub-brokered DNS, Origin CA/ACME fallback, TLS-hostname, and no-node-credential contract"
}

test_control_honeypot_separation() {
  # The Cowrie deception listener must have zero footprint in any production
  # ONETOUCH deployment script; it exists only as the never-invoked, standalone
  # server/wins_cowrie_honeypot_ONETOUCH.sh.
  local script_path
  for script_path in "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${CORE_SCRIPT}"; do
    if grep -Eqi 'honeypot|cowrie' "${script_path}"; then
      echo "$(basename "${script_path}") must not reference the standalone honeypot" >&2
      return 1
    fi
  done
  echo "PASS production deployment scripts carry no honeypot/Cowrie footprint"
}

test_cowrie_honeypot_standalone_host_guard() {
  local helper="${work_dir}/require-dedicated-decoy-host.sh"
  sed -n '/^require_dedicated_decoy_host() {$/,/^}$/p' "${COWRIE_HONEYPOT_SCRIPT}" > "${helper}"
  (
    err() { printf '%s\n' "$*" >&2; }
    ROLE_FILE="${work_dir}/cowrie-role"
    COWRIE_ROLE_MARKER="cowrie-honeypot"
    rm -f "${ROLE_FILE}"
    # shellcheck disable=SC1090
    source "${helper}"

    if require_dedicated_decoy_host 2>/dev/null; then
      echo "standalone honeypot proceeded without the required acknowledgement" >&2
      return 1
    fi

    if HONEYPOT_ACK_STANDALONE=YES require_dedicated_decoy_host 2>/dev/null; then
      : # no role marker yet; acknowledged standalone deploy is allowed to proceed
    else
      echo "standalone honeypot refused a fresh host with no role marker" >&2
      return 1
    fi

    printf 'control\n' > "${ROLE_FILE}"
    if HONEYPOT_ACK_STANDALONE=YES require_dedicated_decoy_host 2>/dev/null; then
      echo "standalone honeypot proceeded on a host already marked 'control'" >&2
      return 1
    fi

    printf 'cowrie-honeypot\n' > "${ROLE_FILE}"
    HONEYPOT_ACK_STANDALONE=YES require_dedicated_decoy_host
  )
  echo "PASS standalone Cowrie honeypot refuses production roles and requires explicit acknowledgement"
}

test_shell_escaped_secret_env() {
  local env_file="${work_dir}/escaped-secrets.env"
  # The literal command-substitution characters are part of the test secret.
  # shellcheck disable=SC2016
  local expected=$'space # quote '\'' dollar $() semicolon ; newline\nsecond-line'
  printf 'SMTP_PASS=%q\n' "${expected}" > "${env_file}"
  unset SMTP_PASS || true
  # shellcheck disable=SC1090
  source "${env_file}"
  [[ "${SMTP_PASS}" == "${expected}" ]]
  echo "PASS shell-escaped one-touch secret environment"
}

test_secret_safe_curl_argv() {
  local role script
  for role in control data core; do
    case "${role}" in
      control) script="${CONTROL_SCRIPT}" ;;
      data) script="${DATA_SCRIPT}" ;;
      core) script="${CORE_SCRIPT}" ;;
    esac
    (
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      curl() {
        local arg config=""
        [[ "$*" != *'runtime-secret-must-not-enter-argv'* ]]
        for arg in "$@"; do
          if [[ "${arg}" == /dev/fd/* ]]; then
            config="$(cat "${arg}")"
          fi
        done
        [[ "${config}" == 'header = "Authorization: Bearer runtime-secret-must-not-enter-argv"' ]]
        printf '{"success":true}'
      }
      curl_bearer 'runtime-secret-must-not-enter-argv' -fsS https://api.example.test >/dev/null
      if [[ "${role}" == "control" ]]; then
        curl() {
          local arg config=""
          [[ "$*" != *'paypal-secret-must-not-enter-argv'* ]]
          for arg in "$@"; do
            if [[ "${arg}" == /dev/fd/* ]]; then
              config="$(cat "${arg}")"
            fi
          done
          [[ "${config}" == 'user = "paypal-client:paypal-secret-must-not-enter-argv"' ]]
          printf '{"access_token":"ok"}'
        }
        curl_paypal_oauth 'paypal-client' 'paypal-secret-must-not-enter-argv' \
          -fsS https://api.example.test/v1/oauth2/token >/dev/null
      fi
    )
  done
  echo "PASS bearer, PayPal client secret, and admin-token curl transports keep credentials out of process arguments"
}

test_documented_defaults_are_sourceable() {
  (
    set -a
    # shellcheck disable=SC1090
    source "${ROOT_DIR}/.env.example"
    set +a
    [[ "${SECURITY_TRIAGE_ABSENT_PRODUCTS}" == *'apache solr'* ]]
    [[ "${STEALTH_TRANSPORTS}" == '80:none,443:tls' ]]
  )
  echo "PASS documented defaults are sourceable Bash"
}

test_active_gateway_publisher() {
  (
    # Load function definitions without executing the deployment entrypoint.
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export REQUIRE_ACTIVE_GATEWAY_AUTOMATION=1
    export GITHUB_GIST_TOKEN='test-token-never-sent'
    export ACTIVE_GATEWAY_GIST_ID='325d9caf5c3cda5d6f933e0ac5ba8a02'
    export ACTIVE_GATEWAY_GIST_FILENAME='active-gateway.txt'
    export ACTIVE_GATEWAY_BASE='https://sync.example.test'
    export ACTIVE_GATEWAY_RAW_URL='https://gist.githubusercontent.com/winsvpn/test/raw/active-gateway.txt'
    sleep() { :; }
    curl() {
      local joined="$*" record="${ACTIVE_GATEWAY_BASE}" config payload_path
      if [[ "${joined}" == *'--config -'* ]]; then
        config="$(cat)"
        [[ "${joined}" != *'test-token-never-sent'* ]]
        [[ "${config}" == *'url = "https://api.github.com/gists/'* ]]
        [[ "${config}" == *'Authorization: Bearer test-token-never-sent'* ]]
        [[ "${config}" == *'X-GitHub-Api-Version: 2026-03-10'* ]]
        payload_path="$(sed -n 's/^data-binary = "@\(.*\)"$/\1/p' <<<"${config}")"
        [[ -f "${payload_path}" ]]
        grep -q 'sync.example.test' "${payload_path}"
        jq -n --arg id "${ACTIVE_GATEWAY_GIST_ID}" \
          --arg filename "${ACTIVE_GATEWAY_GIST_FILENAME}" \
          --arg content "${record}" \
          '{id:$id,files:{($filename):{content:($content + "\n")}}}'
      else
        printf '%s\n' "${record}"
      fi
    }
    publish_active_gateway_record
  )
  echo "PASS authenticated dynamic active-gateway publication"

  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export REQUIRE_ACTIVE_GATEWAY_AUTOMATION=0
    unset GITHUB_GIST_TOKEN || true
    export ACTIVE_GATEWAY_GIST_ID='325d9caf5c3cda5d6f933e0ac5ba8a02'
    export ACTIVE_GATEWAY_GIST_FILENAME='active-gateway.txt'
    export ACTIVE_GATEWAY_BASE='https://sync.example.test'
    export ACTIVE_GATEWAY_RAW_URL='https://gist.githubusercontent.com/winsvpn/test/raw/active-gateway.txt'
    curl() {
      [[ "$*" != *'https://api.github.com/gists/'* ]]
      printf '%s\n' "${ACTIVE_GATEWAY_BASE}"
    }
    publish_active_gateway_record
  )
  echo "PASS tokenless read-only active-gateway fallback verification"
}

test_secrets_file_sourced_without_blanket_export() {
  # The secrets-sourcing block must not be wrapped in `set -a`; the
  # surrounding defaults-sourcing block above it legitimately still is,
  # since WINS_DEFAULTS_FILE never carries credentials.
  for script in "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${CORE_SCRIPT}"; do
    local line_number preceding
    line_number="$(grep -n '^\s*\.\s*"\${WINS_SECRETS_FILE}"' "${script}" | head -1 | cut -d: -f1)"
    [[ -n "${line_number}" ]]
    preceding="$(sed -n "$((line_number - 4)),${line_number}p" "${script}")"
    [[ "${preceding}" != *'set -a'* ]]
  done
  echo "PASS WINS_SECRETS_FILE is sourced without a blanket set -a export in every ONETOUCH script"
}

test_preflight_credentials_not_left_exported() {
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export PREFLIGHT_VERIFY_EXTERNAL_CREDENTIALS=1
    export REQUIRE_CLOUDFLARE_AUTOMATION=0
    export REQUIRE_ACTIVE_GATEWAY_AUTOMATION=0
    export HIDE_CONTROL_ORIGIN=0
    export REQUIRE_CLOUDFLARE_ACCESS=0
    export STRICT_ONE_TOUCH_SECRETS=0
    export CLOUDFLARE_APPCLOUD_API_TOKEN='canary-secret-must-not-stay-exported'
    export CLOUDFLARE_APPCLOUD_ZONE_ID='' CLOUDFLARE_WINS_API_TOKEN=''
    export CLOUDFLARE_WINSVPN_ORG_ZONE_ID='' CLOUDFLARE_WINSVPN_COM_ZONE_ID=''
    export CLOUDFLARE_TUNNEL_ACCOUNT_ID='' CLOUDFLARE_TUNNEL_API_TOKEN='' CLOUDFLARE_WINS_ACCOUNT_ID=''
    export CLOUDFLARE_ACCESS_API_TOKEN='' CLOUDFLARE_ACCESS_SERVICE_TOKEN_NAME=''
    export CLOUDFLARE_ACCESS_SERVICE_TOKEN_DURATION='' CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID=''
    export TUNNEL_SERVICE_TOKEN_ID='' TUNNEL_SERVICE_TOKEN_SECRET=''
    export GITHUB_GIST_TOKEN='' ACTIVE_GATEWAY_GIST_ID='' SMTP_SERVER='' SMTP_PORT='' SMTP_USER='' SMTP_PASS=''
    export PAYPAL_MODE=live PAYPAL_CLIENT_ID='' PAYPAL_CLIENT_SECRET='' PAYPAL_WEBHOOK_ID='' PAYPAL_WEBHOOK_AUTO_ENSURE=0
    export PAYPAL_PLAN_1M='' PAYPAL_PLAN_1Y='' PAYPAL_PLAN_PERSONAL=''
    export PAYPAL_LIFETIME_SUPPORT_URL='' PAYPAL_LIFETIME_NO_SUPPORT_URL=''
    export PAYPAL_LIFETIME_SUPPORT_AMOUNT='' PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT='' PAYPAL_LIFETIME_CURRENCY=''
    verify_preflight_external_credentials
    # export -n must have dropped the export attribute: a freshly spawned
    # child process must not inherit the credential in its own environment.
    [[ -z "$(env | grep '^CLOUDFLARE_APPCLOUD_API_TOKEN=' || true)" ]]
    # The value itself must still be usable by this same script/process via
    # plain "${VAR}" expansion; export -n only drops the export attribute.
    [[ "${CLOUDFLARE_APPCLOUD_API_TOKEN}" == 'canary-secret-must-not-stay-exported' ]]
  )
  echo "PASS preflight-verified Cloudflare/PayPal/SMTP/Gist credentials are not left exported afterward"
}

test_paypal_webhook_auto_ensure() {
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export STRICT_ONE_TOUCH_SECRETS=1
    export PAYPAL_MODE=live
    export PAYPAL_CLIENT_ID='test-client-id'
    export PAYPAL_CLIENT_SECRET='test-client-secret'
    export PAYPAL_WEBHOOK_ID='stale-webhook-id'
    export PAYPAL_WEBHOOK_AUTO_ENSURE=1
    export PAYPAL_WEBHOOK_URL='https://sync.example.test/webhook/paypal'
    export SMTP_SERVER='smtp.example.test' SMTP_PORT=2525 SMTP_USER='test-user' SMTP_PASS='test-pass'
    ENV_FILE="${work_dir}/paypal-runtime.env"
    LEGACY_ENV_FILE="${work_dir}/paypal-runtime-legacy.env"
    : > "${ENV_FILE}"
    : > "${LEGACY_ENV_FILE}"
    python3() { :; }
    systemctl() { :; }
    sleep() { :; }
    curl() {
      local joined="$*"
      if [[ "${joined}" == *'/v1/oauth2/token'* ]]; then
        printf '{"access_token":"test-access-token"}'
      elif [[ "${joined}" == *'-X POST'* && "${joined}" == *'/v1/notifications/webhooks'* ]]; then
        jq -cn --arg url "${PAYPAL_WEBHOOK_URL}" '{
          id:"new-webhook-id",url:$url,event_types:[
            "BILLING.SUBSCRIPTION.ACTIVATED","BILLING.SUBSCRIPTION.UPDATED",
            "BILLING.SUBSCRIPTION.RE-ACTIVATED","BILLING.SUBSCRIPTION.CANCELLED",
            "BILLING.SUBSCRIPTION.SUSPENDED","BILLING.SUBSCRIPTION.EXPIRED",
            "BILLING.SUBSCRIPTION.PAYMENT.FAILED","PAYMENT.SALE.COMPLETED",
            "PAYMENT.SALE.REFUNDED","PAYMENT.SALE.REVERSED","PAYMENT.SALE.DENIED",
            "PAYMENT.CAPTURE.COMPLETED","PAYMENT.CAPTURE.DENIED",
            "PAYMENT.CAPTURE.DECLINED","PAYMENT.CAPTURE.REFUNDED",
            "PAYMENT.CAPTURE.REVERSED"
          ] | map({name:.})}'
      elif [[ "${joined}" == *'/v1/notifications/webhooks/new-webhook-id'* ]]; then
        jq -cn --arg url "${PAYPAL_WEBHOOK_URL}" '{
          id:"new-webhook-id",url:$url,event_types:[
            "BILLING.SUBSCRIPTION.ACTIVATED","BILLING.SUBSCRIPTION.UPDATED",
            "BILLING.SUBSCRIPTION.RE-ACTIVATED","BILLING.SUBSCRIPTION.CANCELLED",
            "BILLING.SUBSCRIPTION.SUSPENDED","BILLING.SUBSCRIPTION.EXPIRED",
            "BILLING.SUBSCRIPTION.PAYMENT.FAILED","PAYMENT.SALE.COMPLETED",
            "PAYMENT.SALE.REFUNDED","PAYMENT.SALE.REVERSED","PAYMENT.SALE.DENIED",
            "PAYMENT.CAPTURE.COMPLETED","PAYMENT.CAPTURE.DENIED",
            "PAYMENT.CAPTURE.DECLINED","PAYMENT.CAPTURE.REFUNDED",
            "PAYMENT.CAPTURE.REVERSED"
          ] | map({name:.})}'
      elif [[ "${joined}" == *'/v1/notifications/webhooks'* ]]; then
        printf '{"webhooks":[]}'
      elif [[ "${joined}" == *'127.0.0.1:8000/healthz'* ]]; then
        printf '{"ok":true}'
      else
        return 1
      fi
    }
    verify_external_integrations
    [[ "${PAYPAL_WEBHOOK_ID}" == 'new-webhook-id' ]]
    grep -q "^PAYPAL_WEBHOOK_ID='new-webhook-id'$" "${ENV_FILE}"
    grep -q "^PAYPAL_WEBHOOK_ID='new-webhook-id'$" "${LEGACY_ENV_FILE}"
  )
  echo "PASS PayPal webhook auto-create event contract and runtime persistence"
}

test_cloudflare_dns_fail_closed() {
  (
    # Load function definitions without executing the deployment entrypoint.
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export REQUIRE_CLOUDFLARE_AUTOMATION=1
    export IONOS_HUB_IP='8.8.8.8'
    export CLOUDFLARE_APPCLOUD_API_TOKEN='app-test-token-never-sent'
    export CLOUDFLARE_APPCLOUD_ZONE_ID='app-zone-test'
    export CLOUDFLARE_APPCLOUD_RECORDS='sync.example.test'
    export CLOUDFLARE_WINS_API_TOKEN='wins-test-token-never-sent'
    export CLOUDFLARE_WINSVPN_ORG_ZONE_ID='org-zone-test'
    export CLOUDFLARE_WINSVPN_COM_ZONE_ID='com-zone-test'
    export CLOUDFLARE_WINS_RECORDS='hub.example.test'
    export CLOUDFLARE_WINS_COM_RECORDS='sync.example.com'
    export HIDE_CONTROL_ORIGIN=1
    export CONTROL_TUNNEL_ID_FILE="${work_dir}/control-tunnel-id"
    printf '%s\n' '11111111-2222-4333-8444-555555555555' > "${CONTROL_TUNNEL_ID_FILE}"
    curl() {
      if [[ "$*" == *'/dns_records?name='* ]]; then
        printf '{"success":true,"result":[]}'
      elif [[ "$*" == *'/dns_records'* && "$*" != *'11111111-2222-4333-8444-555555555555.cfargotunnel.com'* ]]; then
        printf '{"success":false,"errors":[{"message":"expected tunnel CNAME"}]}'
      else
        printf '{"success":true,"result":{"id":"record-test"}}'
      fi
    }
    write_cloudflare_hub_dns

    curl() {
      if [[ "$*" == *'/dns_records?name='* ]]; then
        printf '{"success":true,"result":[]}'
      else
        printf '{"success":false,"errors":[{"message":"simulated denial"}]}'
      fi
    }
    if cloudflare_upsert_dns_record 'token' 'zone' 'A' 'failure.example.test' '8.8.8.8' 'true'; then
      err 'Cloudflare DNS upsert unexpectedly accepted a simulated API denial.'
      exit 1
    fi
  )
  grep -Fq 'server_tokens off;' "${CONTROL_SCRIPT}"
  grep -Fq 'ssl_protocols TLSv1.3;' "${CONTROL_SCRIPT}"
  grep -Fq 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' "${CONTROL_SCRIPT}"
  grep -Fq 'add_header Content-Security-Policy "default-src '\''none'\''; frame-ancestors '\''none'\''; base-uri '\''none'\''; form-action '\''none'\''" always;' "${CONTROL_SCRIPT}"
  grep -Fq 'add_header Cache-Control "no-store" always;' "${CONTROL_SCRIPT}"
  grep -Fq 'advertises-double-vpn-with-zero-exits' "${CONTROL_SCRIPT}"
  grep -Fq 'split_host_port(core["ingress_endpoint"], 9210)' "${CONTROL_SCRIPT}"
  grep -Fq 'core_ingress_host, core_ingress_port = split_host_port(payload.ingress_endpoint, 9210)' "${CONTROL_SCRIPT}"
  grep -Fq 'check_security_headers "sync gateway ${sync_domain} health"' "${CONTROL_SCRIPT}"
  grep -Fq 'server_tokens off;' "${DATA_SCRIPT}"
  grep -Fq 'add_header Content-Security-Policy "default-src '\''none'\''; frame-ancestors '\''none'\''; base-uri '\''none'\''; form-action '\''none'\''" always;' "${DATA_SCRIPT}"
  grep -Fq 'default_type text/plain;' "${DATA_SCRIPT}"
  if grep -Fq 'add_header Content-Type text/plain;' "${DATA_SCRIPT}"; then
    err 'Data-plane health location suppresses inherited security headers.'
    exit 1
  fi
  grep -Fq 'server_tokens off;' "${CORE_SCRIPT}"
  grep -Fq 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' "${CORE_SCRIPT}"
  grep -Fq 'add_header Content-Security-Policy "default-src '\''none'\''; frame-ancestors '\''none'\''; base-uri '\''none'\''; form-action '\''none'\''" always;' "${CORE_SCRIPT}"
  grep -Fq 'add_header Cache-Control "no-store" always;' "${CORE_SCRIPT}"
  grep -Fq 'default_type text/plain;' "${CORE_SCRIPT}"
  if grep -Fq 'add_header Content-Type text/plain;' "${CORE_SCRIPT}"; then
    err 'Core health location suppresses inherited security headers.'
    exit 1
  fi
  echo "PASS Cloudflare DNS fail-closed behavior and Nginx header/TLS hardening"
}

test_strict_one_touch_secret_contract() {
  (
    # Load function definitions without executing the deployment entrypoint.
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export STRICT_ONE_TOUCH_SECRETS=1
    export REQUIRE_REMOTE_BACKUP=1
    export REQUIRE_CLOUDFLARE_AUTOMATION=0
    export REQUIRE_ACTIVE_GATEWAY_AUTOMATION=0
    unset ADMIN_TOKEN SPA_KEY SPA_HMAC RCLONE_CONFIG_SOURCE RCLONE_CONFIG_B64 || true
    if validate_external_secret_contract >/dev/null 2>&1; then
      err 'Strict one-touch validation accepted missing shared and backup secrets.'
      exit 1
    fi

    export ADMIN_TOKEN='test-admin-token-0123456789abcdef0123456789abcdef'
    export SPA_KEY='<REDACTED_WG_KEY>'
    export SPA_HMAC='<REDACTED_WG_KEY>'
    export SMTP_USER='test-smtp-user'
    export SMTP_PASS='test-smtp-password'
    export PAYPAL_PUBLIC_CLIENT_ID='test-public-client'
    export PAYPAL_CLIENT_ID='test-public-client'
    export PAYPAL_CLIENT_SECRET='test-paypal-secret'
    export PAYPAL_WEBHOOK_ID='test-webhook'
    export PAYPAL_PLAN_1M='test-plan-1m'
    export PAYPAL_PLAN_1Y='test-plan-1y'
    export PAYPAL_PLAN_PERSONAL='test-plan-personal'
    export PAYPAL_LIFETIME_SUPPORT_URL='https://example.test/support'
    export PAYPAL_LIFETIME_NO_SUPPORT_URL='https://example.test/no-support'
    export PAYPAL_LIFETIME_SUPPORT_AMOUNT='1000.00'
    export PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT='100.00'
    export PAYPAL_LIFETIME_CURRENCY='USD'
    export HUB_ADMIN_SSH_CIDRS='203.0.113.10/32'
    export CLOUDFLARE_TUNNEL_ACCOUNT_ID='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export CLOUDFLARE_TUNNEL_API_TOKEN='test-tunnel-token-never-sent'
    export CLOUDFLARE_ACCESS_API_TOKEN='test-access-token-never-sent'
    export REQUIRE_SITE_AI_BACKUP=0
    export SITE_AI_VERTEX_PROJECT='runtime-validator'
    export SITE_AI_VERTEX_LOCATION='us-central1'
    export SITE_AI_VERTEX_CREDENTIALS_PATH="${work_dir}/not-provisioned-vertex-credentials.json"
    export BACKUP_AGE_RECIPIENTS_FILE="${work_dir}/backup-recipients.age"
    printf '%s\n' 'age1runtimevalidatorfixture0000000000000000000000' > "${BACKUP_AGE_RECIPIENTS_FILE}"
    chmod 600 "${BACKUP_AGE_RECIPIENTS_FILE}"
    RCLONE_CONFIG_B64="$(printf '[GoogleDrive_secured]\ntype = crypt\nremote = GoogleDrive:winsvpn\npassword = obscured-test\npassword2 = independent-obscured-test\nfilename_encryption = standard\ndirectory_name_encryption = true\nno_data_encryption = false\n' | base64 -w 0)"
    export RCLONE_CONFIG_B64
    # LSR (2026-10-02): DURABILITY_BARRIER_REQUIRED defaults to 1, and the
    # preflight then needs an off-host sftp:// replica with a pinned receiver
    # host key. A throwaway receiver key and a client key path that does not
    # exist yet (the deploy generates it) satisfy the same contract a real hub meets.
    rm -f -- "${work_dir}/litestream-receiver-host-key" "${work_dir}/litestream-receiver-host-key.pub"
    ssh-keygen -q -t ecdsa -b 256 -N '' -f "${work_dir}/litestream-receiver-host-key"
    export LITESTREAM_REPLICA_URL='sftp://wins-replica@replica.example.test/srv/wins-replica'
    LITESTREAM_SFTP_HOST_KEY="$(awk '{print $1 " " $2}' "${work_dir}/litestream-receiver-host-key.pub")"
    export LITESTREAM_SFTP_HOST_KEY
    export LITESTREAM_SFTP_KEY_PATH="${work_dir}/litestream-client-key-not-yet-generated"
    validate_external_secret_contract
    export PAYPAL_CLIENT_ID='mismatched-private-client'
    if validate_external_secret_contract >/dev/null 2>&1; then
      err 'Strict one-touch validation accepted mismatched PayPal public/server client IDs.'
      exit 1
    fi
  )
  echo "PASS strict one-touch shared-secret and backup preflight contract"
}

# L41 Round CF: a data plane or Core holds neither a Cloudflare credential nor
# ADMIN_TOKEN; it accepts only its own token or a slug-bound bootstrap grant,
# installs operator-arranged tunnel material, and keeps a durable handle for
# any redirect transaction it could not settle.
# Variables below are read by the sourced installer functions, and the curl
# override is invoked by them, which shellcheck cannot see.
# shellcheck disable=SC2034,SC2329
test_node_fleet_credential_and_bootstrap_contract() {
  (
    export WINS_DEFAULTS_FILE="${work_dir}/missing-fleet-defaults.env"
    export WINS_SECRETS_FILE="${work_dir}/fleet-secrets.env"
    export NODE_ENV_FILE="${work_dir}/missing-fleet-node.env"
    export WINS_EDGE_LEGACY_ACME_CREDENTIALS="${work_dir}/missing-fleet-acme.ini"
    export WINS_NODE_MANAGEMENT_TOKEN_FILE="${work_dir}/fleet-node-management-token"
    export WINS_EDGE_TXN_STATE_FILE="${work_dir}/fleet-edge-txn/edge-redirect-transaction.env"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    unset ADMIN_TOKEN NODE_TOKEN NODE_BOOTSTRAP_TOKEN NODE_SLUG || true
    # shellcheck disable=SC2034  # read indirectly (${!name}) by the refusal check
    ADMIN_TOKEN='canary-admin-value-0123456789abcdef0123'
    refusal="$(data_refuse_node_fleet_credentials 2>&1 || true)"
    [[ "${refusal}" == *'ADMIN_TOKEN'* && "${refusal}" != *'canary-admin-value'* ]]
    unset ADMIN_TOKEN
    data_refuse_node_fleet_credentials
    edge_refute data_require_subject_credential 2>/dev/null
    NODE_BOOTSTRAP_TOKEN='grant-0123456789abcdefghijklmnopqrstuv'
    edge_refute data_require_subject_credential 2>/dev/null
    NODE_SLUG='node-test'
    data_require_subject_credential
    unset NODE_BOOTSTRAP_TOKEN
    NODE_TOKEN='existing-node-token'
    data_require_subject_credential

    # Tunnel material: operator-supplied first, else the installed connector.
    unset NODE_SSH_HOST NODE_MANAGEMENT_TUNNEL_ID || true
    edge_refute data_resolve_management_tunnel_material 2>/dev/null
    NODE_MGMT_TUNNEL_TOKEN="$(printf 'T%.0s' $(seq 1 100))"
    NODE_MGMT_SSH_HOST='node-test-0123456789abcdef.mgmt.example.test'
    NODE_MGMT_TUNNEL_ID='12345678-1234-1234-1234-123456789abc'
    data_resolve_management_tunnel_material
    [[ "${EDGE_MGMT_SSH_HOST}" == 'node-test-0123456789abcdef.mgmt.example.test' ]]
    NODE_MGMT_TUNNEL_ID='not-a-uuid'
    edge_refute data_resolve_management_tunnel_material 2>/dev/null
    unset NODE_MGMT_TUNNEL_TOKEN NODE_MGMT_SSH_HOST NODE_MGMT_TUNNEL_ID
    printf '%s\n' "$(printf 'R%.0s' $(seq 1 100))" > "${WINS_NODE_MANAGEMENT_TOKEN_FILE}"
    NODE_SSH_HOST='node-test-0123456789abcdef.mgmt.example.test'
    NODE_MANAGEMENT_TUNNEL_ID='12345678-1234-1234-1234-123456789abc'
    data_resolve_management_tunnel_material
    [[ "${EDGE_MGMT_TOKEN}" == R* ]]

    # Consumed one-time material leaves the secrets file; other lines stay.
    printf "NODE_BOOTSTRAP_TOKEN='x'\nNODE_MGMT_TUNNEL_TOKEN='y'\nRCLONE_CONFIG_B64='keep'\n" > "${WINS_SECRETS_FILE}"
    chmod 600 "${WINS_SECRETS_FILE}"
    data_scrub_consumed_subject_material
    [[ "$(cat "${WINS_SECRETS_FILE}")" == "RCLONE_CONFIG_B64='keep'" ]]

    # Durable redirect handle: commit-pending is committed on the next run;
    # a hub refusal keeps the handle and stops before publication.
    NODE_SLUG='node-test'
    HUB_API_BASE='https://hub.example.test'
    local txn='0123456789abcdef0123456789abcdef' call_log="${work_dir}/fleet-txn-calls" mode=ok
    : > "${call_log}"
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg output_file="" previous="" url=""
      for arg in "$@"; do
        [[ "${previous}" != "-o" ]] || output_file="${arg}"
        [[ "${arg}" != http*://* ]] || url="${arg}"
        previous="${arg}"
      done
      printf '%s\n' "${url##*/edge/}" >> "${call_log}"
      if [[ "${mode}" == ok ]]; then
        printf '%s\n' '{"ok":true}' > "${output_file}"; printf '200'
      else
        printf '%s\n' '{"detail":"conflict"}' > "${output_file}"; printf '409'
      fi
    }
    edge_txn_record commit-pending "${txn}"
    edge_txn_reconcile
    [[ "$(tail -n 1 "${call_log}")" == "plaintext-exemption/${txn}/commit" && ! -e "${WINS_EDGE_TXN_STATE_FILE}" ]]
    edge_txn_record rollback-failed "${txn}"
    mode=refuse
    edge_refute edge_txn_reconcile 2>/dev/null
    [[ "$(tail -n 1 "${call_log}")" == "plaintext-exemption/${txn}/rollback" && -e "${WINS_EDGE_TXN_STATE_FILE}" ]]
    CLOUDFLARE_REDIRECT_TXN_ARMED=1
    CLOUDFLARE_REDIRECT_TXN_ID="${txn}"
    edge_txn_forget
    cloudflare_redirect_transaction_commit
    grep -q '^EDGE_TXN_STATE=commit-pending$' "${WINS_EDGE_TXN_STATE_FILE}"
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" ]]

    # CF-3: the node token only ever goes to https://<fronted hub hostname>.
    local sent="${work_dir}/fleet-plain-sent" bad
    : > "${sent}"
    curl() { printf 'sent\n' >> "${sent}"; printf '200'; }
    for bad in 'http://hub.example.test' 'https://192.0.2.10' 'https://hub.example.test:8443' 'https://hub.example.test/api' 'ftp://hub.example.test'; do
      HUB_API_BASE="${bad}"
      edge_refute edge_hub_call GET hostnames "" "${work_dir}/fleet-plain-out" 2>/dev/null
    done
    [[ ! -s "${sent}" ]]
  )
  (
    export WINS_DEFAULTS_FILE="${work_dir}/missing-fleet-core-defaults.env"
    export WINS_SECRETS_FILE="${work_dir}/missing-fleet-core-secrets.env"
    export CORE_ENV_FILE="${work_dir}/missing-fleet-core.env"
    export WINS_EDGE_LEGACY_ACME_CREDENTIALS="${work_dir}/missing-fleet-core-acme.ini"
    # shellcheck disable=SC1090
    source "${CORE_SCRIPT}"
    unset ADMIN_TOKEN CORE_TOKEN CORE_BOOTSTRAP_TOKEN || true
    # shellcheck disable=SC2034  # read indirectly (${!name}) by the refusal check
    ADMIN_TOKEN='canary-admin-value-0123456789abcdef0123'
    edge_refute core_refuse_node_fleet_credentials 2>/dev/null
    unset ADMIN_TOKEN
    core_refuse_node_fleet_credentials
    edge_refute core_require_subject_credential 2>/dev/null
    CORE_BOOTSTRAP_TOKEN='grant-0123456789abcdefghijklmnopqrstuv'
    core_require_subject_credential
    local sent="${work_dir}/fleet-core-plain-sent" bad
    : > "${sent}"
    curl() { printf 'sent\n' >> "${sent}"; printf '200'; }
    CORE_ID='north-core'
    CORE_TOKEN='core-token-for-plaintext-test'
    for bad in 'http://hub.example.test' 'https://192.0.2.10' 'https://hub.example.test:8443' 'https://hub.example.test/api'; do
      HUB_API_BASE="${bad}"
      edge_refute core_edge_hub_call GET hostnames "" "${work_dir}/fleet-core-plain-out" 2>/dev/null
    done
    [[ ! -s "${sent}" ]]
  )
  echo "PASS data/Core hold no fleet credential, accept only a subject token or grant, send it only over HTTPS to the fronted hub, install operator-arranged tunnels, and keep a durable redirect handle"
}

test_data_plane_dns_fail_closed() {
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    export REQUIRE_CLOUDFLARE_AUTOMATION=1
    NODE_SLUG='node-test'
    NODE_TOKEN='node-token-never-sent'
    HUB_API_BASE='https://hub.example.test'
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg output_file="" previous=""
      for arg in "$@"; do
        [[ "${previous}" != "-o" ]] || output_file="${arg}"
        previous="${arg}"
      done
      printf '%s\n' '{"detail":"Cloudflare rejected the edge operation"}' > "${output_file}"
      printf '502'
    }
    edge_refute hub_upsert_stealth_records '8.8.8.8' 'node.example.test'
    # No hostname at all is also a refusal when automation is required.
    edge_refute hub_upsert_stealth_records '8.8.8.8'
    # Positive arm, so the refusals above cannot pass merely because the
    # function is missing: an accepting hub is reached at the node-scoped URL.
    local url_log="${work_dir}/edge-dns-url"
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg output_file="" previous=""
      for arg in "$@"; do
        [[ "${previous}" != "-o" ]] || output_file="${arg}"
        [[ "${arg}" != http*://* ]] || printf '%s\n' "${arg}" > "${url_log}"
        previous="${arg}"
      done
      printf '%s\n' '{"ok":true,"records":{"node.example.test":"created"}}' > "${output_file}"
      printf '200'
    }
    hub_upsert_stealth_records '8.8.8.8' 'node.example.test'
    [[ "$(cat "${url_log}")" == 'https://hub.example.test/api/v1/nodes/node-test/edge/dns' ]]
  )
  echo "PASS data-plane hub-brokered DNS fail-closed behavior"
}

test_data_plane_adguard_policy() {
  local base_config="${work_dir}/adguard-base.yaml"
  local commercial_config="${work_dir}/adguard-commercial-dns4eu.yaml"
  local rejected_log="${work_dir}/adguard-public-dns4eu-rejected.log"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    ADGUARD_DNS_BIND_DEFAULT='10.8.1.1'
    ADGUARD_PRIMARY_DOH_DEFAULT='https://dns.quad9.net/dns-query'
    ADGUARD_OPENDNS_FALLBACK_DOH_DEFAULT='https://dns.opendns.com/dns-query'
    ADGUARD_RATE_LIMIT_QPS_DEFAULT='100'
    DNS4EU_COMMERCIAL_DOH_URL_DEFAULT=''
    write_adguard_config "${base_config}"

    DNS4EU_COMMERCIAL_DOH_URL_DEFAULT='https://winsvpn.customer.whalebone.example/dns-query?tenant=test'
    write_adguard_config "${commercial_config}"

    DNS4EU_COMMERCIAL_DOH_URL_DEFAULT='https://noads.joindns4.eu/dns-query'
    if write_adguard_config "${work_dir}/forbidden-public-dns4eu.yaml" >"${rejected_log}" 2>&1; then
      err 'Data-plane AdGuard policy accepted a public DNS4EU endpoint for commercial VPN traffic.'
      exit 1
    fi
    grep -Fq 'public resolvers prohibit commercial/provider use' "${rejected_log}"

    DNS4EU_COMMERCIAL_DOH_URL_DEFAULT=''
    for invalid_rate_limit in 0 0100; do
      ADGUARD_RATE_LIMIT_QPS_DEFAULT="${invalid_rate_limit}"
      if write_adguard_config "${work_dir}/invalid-adguard-rate-limit-${invalid_rate_limit}.yaml" \
          >"${work_dir}/invalid-adguard-rate-limit-${invalid_rate_limit}.log" 2>&1; then
        err "Data-plane AdGuard policy accepted invalid per-client DNS rate limit ${invalid_rate_limit}."
        exit 1
      fi
      grep -Fq 'ADGUARD_RATE_LIMIT_QPS must be an integer from 20 through 10000' \
        "${work_dir}/invalid-adguard-rate-limit-${invalid_rate_limit}.log"
    done
  )

  python3 - "${base_config}" "${commercial_config}" <<'PYEOF'
import pathlib
import sys
import yaml

base_path, commercial_path = map(pathlib.Path, sys.argv[1:])
base = yaml.safe_load(base_path.read_text(encoding="utf-8"))
commercial = yaml.safe_load(commercial_path.read_text(encoding="utf-8"))

expected_primary = ["https://dns.quad9.net/dns-query"]
expected_open_dns = "https://dns.opendns.com/dns-query"
assert base["schema_version"] == 34
assert base["dns"]["upstream_dns"] == expected_primary
assert base["dns"]["fallback_dns"] == [expected_open_dns]
assert commercial["dns"]["fallback_dns"] == [
    expected_open_dns,
    "https://winsvpn.customer.whalebone.example/dns-query?tenant=test",
]
assert base["dns"]["upstream_mode"] == "load_balance"
assert base["dns"]["enable_dnssec"] is True
assert base["dns"]["ratelimit"] == 100
assert base["dns"]["ratelimit_subnet_len_ipv4"] == 32
assert base["dns"]["ratelimit_subnet_len_ipv6"] == 128
# D13 (2026-08-12): the winn/3 gateway's loopback source is exempt from the DNS rate limiter -- see write_adguard_config in wins_data_plane_setup_ONETOUCH.sh.
assert base["dns"]["ratelimit_whitelist"] == ["127.0.0.1"]
assert base["dns"]["refuse_any"] is True
assert base["filtering"]["protection_enabled"] is True
assert base["filtering"]["filtering_enabled"] is True
assert base["filters"] == [{
    "enabled": True,
    "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "name": "AdGuard DNS filter",
    "id": 1,
}]
for rendered in (base_path.read_text(encoding="utf-8"), commercial_path.read_text(encoding="utf-8")):
    for forbidden in (
        "86.54.11.13",
        "upstream_mode: parallel",
        "94.140.14.14",
        "94.140.15.15",
        "dns.adguard-dns.com",
    ):
        assert forbidden not in rendered, forbidden
PYEOF
  echo "PASS deterministic AdGuard filter, Quad9 primary, OpenDNS fallback, and commercial-only DNS4EU contract"
}

test_data_plane_selective_https_redirect() {
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    local call_log="${work_dir}/edge-redirect-calls"
    local argv_log="${work_dir}/edge-redirect-argv"
    local body_dir="${work_dir}/edge-redirect-bodies"
    local mode_file="${work_dir}/edge-redirect-mode"
    local txn='0123456789abcdef0123456789abcdef'
    export WINS_EDGE_TXN_STATE_FILE="${work_dir}/edge-redirect-state/edge-redirect-transaction.env"
    mkdir -p "${body_dir}"
    : > "${call_log}"
    : > "${argv_log}"
    printf 'ok\n' > "${mode_file}"
    # Fake hub edge broker. The node now holds no Cloudflare credential: the
    # exact host/path exemption, its read-back, the Always Use HTTPS switch and
    # the compare-and-swap rollback all run on the hub (covered by the hub
    # suite). Here we prove the node-side contract: ordering, transaction
    # handling, fail-closed behavior, and no token in argv.
    curl() {
      mock_curl_read_stdin_config "$@"
      local arg previous="" method="GET" url="" output_file="" payload_file="" endpoint mode
      for arg in "$@"; do
        case "${previous}" in
          -X|--request) method="${arg}" ;;
          -o) output_file="${arg}" ;;
          --data-binary) payload_file="${arg#@}" ;;
        esac
        [[ "${arg}" != http*://* ]] || url="${arg}"
        previous="${arg}"
      done
      printf '%s\n' "$*" >> "${argv_log}"
      endpoint="${url#https://hub.example.test/api/v1/nodes/node-test/edge/}"
      printf '%s %s\n' "${method}" "${endpoint}" >> "${call_log}"
      [[ -z "${payload_file}" ]] || cp "${payload_file}" "${body_dir}/$(wc -l < "${call_log}" | tr -d ' ').json"
      mode="$(tr -d '[:space:]' < "${mode_file}")"
      case "${method} ${endpoint}" in
        'POST plaintext-exemption')
          if [[ "${mode}" == 'deny-exemption' ]]; then
            printf '%s\n' '{"detail":"Managed redirect did not read back as written"}' > "${output_file}"
            printf '502'
          elif [[ "${mode}" == 'already-committed' ]]; then
            printf '%s\n' '{"ok":true,"transaction_id":null,"state":"committed","added":0}' > "${output_file}"
            printf '200'
          elif [[ "${mode}" == 'no-handle' ]]; then
            printf '%s\n' '{"ok":true,"transaction_id":null,"state":"armed","added":1}' > "${output_file}"
            printf '200'
          else
            jq -n --arg txn "${txn}" '{ok:true,transaction_id:$txn}' > "${output_file}"
            printf '200'
          fi
          ;;
        "POST plaintext-exemption/${txn}/commit")
          if [[ "${mode}" == 'deny-commit' ]]; then
            printf '%s\n' '{"detail":"Edge transaction is rolled_back, not armed"}' > "${output_file}"
            printf '409'
          else
            printf '%s\n' '{"ok":true,"state":"committed"}' > "${output_file}"
            printf '200'
          fi
          ;;
        "POST plaintext-exemption/${txn}/rollback")
          if [[ "${mode}" == 'deny-rollback' ]]; then
            printf '%s\n' '{"detail":"The managed redirect changed after this transaction; operator review required"}' > "${output_file}"
            printf '409'
          else
            printf '%s\n' '{"ok":true,"state":"rolled_back"}' > "${output_file}"
            printf '200'
          fi
          ;;
        'POST dns')
          printf '%s\n' '{"ok":true,"records":{"new.example.test":"created","alias.example.test":"created"}}' > "${output_file}"
          printf '200'
          ;;
        *)
          printf '%s\n' '{"detail":"unexpected mock request"}' > "${output_file}"
          printf '404'
          ;;
      esac
    }
    NODE_SLUG='node-test'
    NODE_TOKEN='node-token-must-not-enter-argv'
    HUB_API_BASE='https://hub.example.test'
    CLOUDFLARE_STEALTH_ZONE_DEFAULT='example.test'
    REQUIRE_CLOUDFLARE_AUTOMATION=1
    CLOUDFLARE_MANAGE_HTTP_REDIRECTS=1
    STEALTH_TRANSPORTS='80:none,443:tls'
    STEALTH_HOST='new.example.test'
    REGIONAL_GATEWAY_ALIASES='alias.example.test'
    DETECTED_PUBLIC_IP='203.0.113.20'
    XRAY_PATH='/wins-stealth-tunnel'
    NODE_ENV_FILE="${work_dir}/edge-node.env"
    printf 'STEALTH_HOST=%q\nREGIONAL_GATEWAY_ALIASES=%q\nDETECTED_PUBLIC_IP=%q\nSTEALTH_TRANSPORTS=%q\nXRAY_PATH=%q\n' \
      "${STEALTH_HOST}" "${REGIONAL_GATEWAY_ALIASES}" "${DETECTED_PUBLIC_IP}" "${STEALTH_TRANSPORTS}" "${XRAY_PATH}" \
      > "${NODE_ENV_FILE}"
    chmod 600 "${NODE_ENV_FILE}"

    # 1. The exemption is armed on the hub BEFORE any DNS record is requested,
    #    for exactly this node's hosts and Xray path.
    publish_stealth_dns
    [[ "$(sed -n 1p "${call_log}")" == 'POST plaintext-exemption' ]]
    [[ "$(sed -n 2p "${call_log}")" == 'POST dns' ]]
    jq -e '.path == "/wins-stealth-tunnel" and (.hostnames | sort) == ["alias.example.test","new.example.test"]' \
      "${body_dir}/1.json" >/dev/null
    jq -e '.ipv4 == "203.0.113.20" and (.hostnames | sort) == ["alias.example.test","new.example.test"]' \
      "${body_dir}/2.json" >/dev/null
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "1" && "${CLOUDFLARE_REDIRECT_TXN_ID}" == "${txn}" ]]
    edge_refute grep -Fq "${NODE_TOKEN}" "${argv_log}"
    edge_refute grep -Fq 'api.cloudflare.com' "${argv_log}"

    # 2. A completed strict postflight commits on the hub; a later EXIT with a
    #    failure status then has nothing to roll back.
    cloudflare_redirect_transaction_commit
    [[ "$(tail -n 1 "${call_log}")" == "POST plaintext-exemption/${txn}/commit" ]]
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" ]]
    : > "${call_log}"
    cloudflare_redirect_transaction_on_exit 1
    [[ ! -s "${call_log}" ]]

    # 3. A failed strict postflight rolls the hub transaction back.
    cloudflare_configure_plaintext_stealth_routes
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "1" ]]
    cloudflare_redirect_transaction_on_exit 1
    [[ "$(tail -n 1 "${call_log}")" == "POST plaintext-exemption/${txn}/rollback" ]]
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" ]]

    # 4. A hub refusal stops before any DNS request and leaves nothing armed
    #    (the hub has already undone its own partial change).
    printf 'deny-exemption\n' > "${mode_file}"
    : > "${call_log}"
    edge_refute publish_stealth_dns
    edge_refute grep -q 'POST dns' "${call_log}"
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" ]]

    # 5. A refused rollback is reported and the handle is kept for review.
    printf 'ok\n' > "${mode_file}"
    cloudflare_configure_plaintext_stealth_routes
    printf 'deny-rollback\n' > "${mode_file}"
    edge_refute cloudflare_redirect_transaction_rollback
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "1" ]]

    grep -q '^EDGE_TXN_STATE=rollback-failed$' "${WINS_EDGE_TXN_STATE_FILE}"

    # 6. A refused commit after a passed postflight is not fatal, and the
    #    handle is kept durably as commit-pending instead of being discarded.
    printf 'deny-commit\n' > "${mode_file}"
    cloudflare_redirect_transaction_commit
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" ]]
    grep -q '^EDGE_TXN_STATE=commit-pending$' "${WINS_EDGE_TXN_STATE_FILE}"

    # 7. The next run settles that handle first; with no plaintext transport
    #    it makes no other redirect request.
    printf 'ok\n' > "${mode_file}"
    : > "${call_log}"
    STEALTH_TRANSPORTS='443:tls'
    cloudflare_configure_plaintext_stealth_routes
    [[ "$(cat "${call_log}")" == "POST plaintext-exemption/${txn}/commit" ]]
    [[ ! -e "${WINS_EDGE_TXN_STATE_FILE}" ]]
    : > "${call_log}"
    cloudflare_configure_plaintext_stealth_routes
    [[ ! -s "${call_log}" ]]

    # 8. A repeat run whose exact exception is already committed on the hub
    #    opens no transaction: nothing is armed, no handle is recorded, and
    #    neither commit nor an EXIT rollback makes a request (Round CF Turn 5).
    STEALTH_TRANSPORTS='80:none,443:tls'
    printf 'already-committed\n' > "${mode_file}"
    : > "${call_log}"
    cloudflare_configure_plaintext_stealth_routes
    [[ "$(cat "${call_log}")" == 'POST plaintext-exemption' ]]
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" && -z "${CLOUDFLARE_REDIRECT_TXN_ID}" ]]
    [[ ! -e "${WINS_EDGE_TXN_STATE_FILE}" ]]
    cloudflare_redirect_transaction_commit
    cloudflare_redirect_transaction_on_exit 1
    [[ "$(cat "${call_log}")" == 'POST plaintext-exemption' ]]
    # A change that was NOT reported as already committed still needs a handle.
    printf 'no-handle\n' > "${mode_file}"
    edge_refute cloudflare_configure_plaintext_stealth_routes 2>/dev/null
    [[ "${CLOUDFLARE_REDIRECT_TXN_ARMED}" == "0" ]]
  )
  echo "PASS data-plane selective HTTPS redirect is hub-brokered, pre-DNS, transactional, fail-closed, durably reconciled, idempotent on repeat, and token-free in argv"
}

test_rclone_pre_mutation_contracts() {
  local script role
  for role in control data; do
    if [[ "${role}" == "control" ]]; then
      script="${CONTROL_SCRIPT}"
    else
      script="${DATA_SCRIPT}"
    fi
    (
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      export REQUIRE_REMOTE_BACKUP=1 RCLONE_REMOTE='GoogleDrive_secured'
      unset RCLONE_CONFIG_SOURCE RCLONE_CONFIG_B64 || true
      if validate_rclone_injection_contract >/dev/null 2>&1; then
        err "${role} rclone preflight accepted missing required credentials."
        exit 1
      fi
      export RCLONE_CONFIG_B64='not-valid-base64!'
      if validate_rclone_injection_contract >/dev/null 2>&1; then
        err "${role} rclone preflight accepted invalid base64."
        exit 1
      fi
      RCLONE_CONFIG_B64="$(printf '[wrong-remote]\ntype = drive\n' | base64 -w 0)"
      export RCLONE_CONFIG_B64
      if validate_rclone_injection_contract >/dev/null 2>&1; then
        err "${role} rclone preflight accepted a config without the required remote."
        exit 1
      fi
      RCLONE_CONFIG_B64="$(printf '[GoogleDrive_secured]\ntype = drive\n' | base64 -w 0)"
      export RCLONE_CONFIG_B64
      if validate_rclone_injection_contract >/dev/null 2>&1; then
        err "${role} rclone preflight accepted a non-encrypted required remote."
        exit 1
      fi
      RCLONE_CONFIG_B64="$(printf '[GoogleDrive_secured]\ntype = crypt\nremote = GoogleDrive:winsvpn\npassword = obscured-test\npassword2 = independent-obscured-test\nfilename_encryption = standard\ndirectory_name_encryption = true\nno_data_encryption = false\n' | base64 -w 0)"
      export RCLONE_CONFIG_B64
      validate_rclone_injection_contract
      export RCLONE_CONFIG_SOURCE='/tmp/ambiguous-rclone.conf'
      if validate_rclone_injection_contract >/dev/null 2>&1; then
        err "${role} rclone preflight accepted both injection mechanisms."
        exit 1
      fi
    )
  done
  echo "PASS control/data rclone credentials require client-side encrypted crypt remotes before host mutation"
}

test_secure_backup_contracts() {
  local role script needle generated restore_preflight node_restore_preflight hub_db_snapshot
  for role in control data; do
    if [[ "${role}" == "control" ]]; then
      script="${CONTROL_SCRIPT}"
      needle='cat > /usr/local/bin/wins-hub-backup'
    else
      script="${DATA_SCRIPT}"
      needle='cat > /usr/local/bin/wins-node-backup'
    fi
    generated="${work_dir}/${role}-backup.sh"
    extract_heredoc "${script}" "${needle}" EOF > "${generated}"
    bash -n "${generated}"
    grep -Fq 'umask 077' "${generated}"
    grep -Fq 'mktemp -d "${RUNTIME_ROOT}/wins-' "${generated}"
    grep -Fq 'trap cleanup EXIT HUP INT TERM' "${generated}"
    grep -Fq 'remote_type="$(rclone config dump' "${generated}"
    grep -Fq 'rclone cryptcheck "${UPLOAD_DIR}" "${REMOTE}" --one-way' "${generated}"
    grep -Fq 'gzip -t "${ARCHIVE}"' "${generated}"
    grep -Fq 'tar -tzf "${ARCHIVE}"' "${generated}"
    grep -Fq 'tar --dereference --hard-dereference --ignore-failed-read' "${generated}"
    if [[ "${role}" == "control" ]]; then
      grep -Fq -- '--transform=' "${generated}"
      # IA-CP-18 (CP-B): the archive is built from the listed sources that
      # exist on this host, and each of them is then proven to be in it.
      grep -Fq -- '-C "${SOURCE_ROOT}" -cf "${ARCHIVE_TAR}" "${present_sources[@]}"' "${generated}"
      grep -Fq 'tar --hard-dereference -C "${PAYLOAD_DIR}" -rf "${ARCHIVE_TAR}"' "${generated}"
      grep -Fq 'gzip -n -c -- "${ARCHIVE_TAR}" > "${ARCHIVE}"' "${generated}"
      if grep -Fq '| tar -C "${PAYLOAD_DIR}" -xf -' "${generated}"; then
        echo "control backup still requires CAP_CHOWN to re-stage source ownership" >&2
        exit 1
      fi
    else
      grep -Fq 'tar --hard-dereference -C "${PAYLOAD_DIR}" -czf "${ARCHIVE}" .' "${generated}"
    fi
    if grep -Fq 'TMP="/tmp/wins-' "${generated}" || grep -Fq 'rclone copy "${TMP}"' "${generated}"; then
      echo "${role} backup still leaves a plaintext legacy archive in /tmp" >&2
      exit 1
    fi
    grep -Fq 'UMask=0077' "${script}"
  done
  grep -Fq 'PREPARED_DB_SNAPSHOT="${WINS_HUB_DB_SNAPSHOT_PATH:-/run/wins-hub-db-snapshot/vpn_users.db}"' "${work_dir}/control-backup.sh"
  grep -Fq 'install -m 600 "${PREPARED_DB_SNAPSHOT}" "${DB_SNAPSHOT}"' "${work_dir}/control-backup.sh"
  grep -Fq "PRAGMA quick_check;" "${work_dir}/control-backup.sh"
  hub_db_snapshot="${work_dir}/wins-hub-db-snapshot"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /usr/local/bin/wins-hub-db-snapshot <<'EOF'" EOF > "${hub_db_snapshot}"
  bash -n "${hub_db_snapshot}"
  chmod 700 "${hub_db_snapshot}"
  grep -Fq 'sqlite3 "${DB_SOURCE}" ".timeout 30000" ".backup' "${hub_db_snapshot}"
  grep -Fq 'sqlite3 -readonly "${DB_SNAPSHOT}"' "${hub_db_snapshot}"
  grep -Fq 'Preserving existing hub fresh-install recovery contract' "${CONTROL_SCRIPT}"
  grep -Fq 'Preserving existing data-plane fresh-install recovery contract' "${DATA_SCRIPT}"
  grep -Fq 'if [[ -e "${contract}" || -L "${contract}" ]]; then' "${CONTROL_SCRIPT}"
  grep -Fq 'if [[ -e "${contract}" || -L "${contract}" ]]; then' "${DATA_SCRIPT}"
  restore_preflight="${work_dir}/wins-hub-restore-preflight"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /usr/local/bin/wins-hub-restore-preflight <<'EOF'" EOF > "${restore_preflight}"
  bash -n "${restore_preflight}"
  chmod 700 "${restore_preflight}"
  node_restore_preflight="${work_dir}/wins-node-restore-preflight"
  extract_heredoc "${DATA_SCRIPT}" "cat > /usr/local/bin/wins-node-restore-preflight <<'EOF'" EOF > "${node_restore_preflight}"
  bash -n "${node_restore_preflight}"
  chmod 700 "${node_restore_preflight}"

  local fixture_root="${work_dir}/backup-fixture"
  local runtime_root="${work_dir}/backup-runtime"
  local mock_bin="${work_dir}/backup-mock-bin"
  local mock_remote="${work_dir}/backup-mock-remote"
  local restore_dir="${work_dir}/backup-restore"
  mkdir -p "${fixture_root}/root/vpn_auth" "${fixture_root}/root/.config/rclone" \
    "${fixture_root}/etc/winsvpn" "${fixture_root}/etc/nginx" \
    "${fixture_root}/etc/systemd/system" "${fixture_root}/etc/iptables" \
    "${runtime_root}" "${mock_bin}" "${mock_remote}" "${restore_dir}"
  ssh-keygen -q -t ed25519 -N '' -C 'runtime-validator-fixture' -f "${work_dir}/backup-fixture-identity"
  cp "${work_dir}/backup-fixture-identity.pub" "${fixture_root}/etc/winsvpn/backup-recipients.age"
  chmod 600 "${fixture_root}/etc/winsvpn/backup-recipients.age"
  rm -f "${work_dir}/backup-fixture-identity.pub"
  printf '%s\n' \
    'RCLONE_REMOTE=GoogleDrive_secured' \
    'REQUIRE_REMOTE_BACKUP=1' \
    'REQUIRE_BACKUP_ENCRYPTION=1' \
    "BACKUP_AGE_RECIPIENTS_FILE=${fixture_root}/etc/winsvpn/backup-recipients.age" \
    > "${fixture_root}/etc/winsvpn/backup.env"
  printf '%s\n' \
    'WINS_HUB_RECOVERY_CONTRACT_VERSION=1' \
    'WINS_HUB_INSTALL_ID=11111111-1111-4111-8111-111111111111' \
    'WINS_HUB_INSTALL_EPOCH=100' \
    'WINS_HUB_RESTORE_ORDER=fresh-install-then-state' \
    > "${fixture_root}/etc/winsvpn/hub-install-contract.env"
  chmod 600 "${fixture_root}/etc/winsvpn/hub-install-contract.env"
  printf '%s\n' '[GoogleDrive_secured]' 'type = crypt' > "${fixture_root}/root/.config/rclone/rclone.conf"
  printf '%s\n' 'test-app' > "${fixture_root}/root/vpn_auth/main.py"
  printf '%s\n' 'core-test.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5<REDACTED_WG_KEY>' > "${fixture_root}/root/vpn_auth/managed_known_hosts"
  chmod 600 "${fixture_root}/root/vpn_auth/managed_known_hosts"
  printf '%s\n' 'stale-legacy-secret' > "${fixture_root}/root/vpn_auth/.env"
  printf '%s\n' 'stale-source-copy' > "${fixture_root}/root/vpn_auth/main.py.pre-upgrade.bak"
  install -d -m 700 "${fixture_root}/root/vpn_auth/__pycache__"
  printf '%s\n' 'stale-bytecode' > "${fixture_root}/root/vpn_auth/__pycache__/main.pyc"
  printf '%s\n' 'test-secret-env' > "${fixture_root}/root/vpn_auth.env"
  printf '%s\n' 'test-nginx' > "${fixture_root}/etc/nginx/nginx.conf"
  printf '%s\n' '*filter' 'COMMIT' > "${fixture_root}/etc/iptables/rules.v4"
  for unit in wins-hub.service wins-control-tunnel.service wins-gateway-canary.service wins-gateway-canary.timer \
    wins-security-alert-monitor.service wins-security-alert-monitor.timer wins-paypal-sync.service wins-paypal-sync.timer; do
    printf '%s\n' '[Unit]' > "${fixture_root}/etc/systemd/system/${unit}"
  done
  sqlite3 "${fixture_root}/root/vpn_auth/vpn_users.db" \
    'CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES ("consistent-snapshot");'
  chmod 600 "${fixture_root}/root/vpn_auth/vpn_users.db"
  # CP-10: the Winn3 authority ledger (a second SQLite file, in WAL mode like
  # the hub keeps it) and the charge-journal keyring are restore state too.
  sqlite3 "${fixture_root}/root/vpn_auth/winn3_authority_ledger.db" \
    'PRAGMA journal_mode=WAL; CREATE TABLE publications(slug TEXT); INSERT INTO publications VALUES ("ledger-snapshot");' >/dev/null
  chmod 644 "${fixture_root}/root/vpn_auth/winn3_authority_ledger.db"
  printf '%s\n' '{"active": "00112233445566ff", "keys": {}}' > "${fixture_root}/root/vpn_auth/winn3_charge_keys.json"
  chmod 600 "${fixture_root}/root/vpn_auth/winn3_charge_keys.json"

  cat > "${mock_bin}/rclone" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-} ${2:-}" in
  'config dump')
    jq -nc --arg type "${MOCK_RCLONE_TYPE:-crypt}" '{GoogleDrive_secured:{type:$type}}'
    ;;
  'copy '*)
    source_dir="$2"
    install -d -m 700 "${MOCK_RCLONE_REMOTE:?}"
    cp -a "${source_dir}/." "${MOCK_RCLONE_REMOTE}/"
    ;;
  'cryptcheck '*)
    diff -qr "$2" "${MOCK_RCLONE_REMOTE:?}" >/dev/null
    ;;
  *)
    echo "unexpected mock rclone command: $*" >&2
    exit 64
    ;;
esac
EOF
  chmod 700 "${mock_bin}/rclone"

  local prepared_db_dir="${work_dir}/prepared-hub-db"
  install -d -m 700 "${prepared_db_dir}"
  WINS_HUB_DB_SOURCE="${fixture_root}/root/vpn_auth/vpn_users.db" \
    WINS_HUB_DB_SNAPSHOT_DIR="${prepared_db_dir}" bash "${hub_db_snapshot}"
  [[ -s "${prepared_db_dir}/vpn_users.db" ]]
  [[ -s "${prepared_db_dir}/winn3_authority_ledger.db" ]]
  [[ "$(stat -c '%a' "${prepared_db_dir}/winn3_authority_ledger.db")" == "600" ]]
  PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=crypt MOCK_RCLONE_REMOTE="${mock_remote}" \
    WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
    WINS_HUB_DB_SNAPSHOT_PATH="${prepared_db_dir}/vpn_users.db" \
    WINS_BACKUP_MANIFEST_BIN=/bin/true WINS_BACKUP_PRUNE_BIN=/bin/true \
    bash "${work_dir}/control-backup.sh"
  [[ ! -e "${prepared_db_dir}/vpn_users.db" ]]
  [[ ! -e "${prepared_db_dir}/winn3_authority_ledger.db" ]]
  local archive checksum encrypted_archive encrypted_checksum known_hosts_digest
  known_hosts_digest="$(sha256sum "${fixture_root}/root/vpn_auth/managed_known_hosts" | awk '{print $1}')"
  encrypted_archive="$(find "${mock_remote}" -maxdepth 1 -type f -name 'wins-hub-backup-*.tar.gz.age' -print -quit)"
  [[ -n "${encrypted_archive}" && "$(stat -c '%a' "${encrypted_archive}")" == "600" ]]
  [[ -z "$(find "${mock_remote}" -maxdepth 1 -type f -name 'wins-hub-backup-*.tar.gz' -print -quit)" ]]
  encrypted_checksum="${encrypted_archive}.sha256"
  [[ -s "${encrypted_checksum}" ]]
  (cd "${mock_remote}" && sha256sum -c "$(basename "${encrypted_checksum}")" >/dev/null)
  archive="${work_dir}/decrypted-wins-hub-backup.tar.gz"
  age -d -i "${work_dir}/backup-fixture-identity" -o "${archive}" "${encrypted_archive}"
  checksum="${archive}.sha256"
  (cd "${work_dir}" && sha256sum "$(basename "${archive}")" > "$(basename "${checksum}")")
  tar -C "${restore_dir}" -xzf "${archive}"
  [[ "$(cat "${restore_dir}/root/vpn_auth/main.py")" == "test-app" ]]
  [[ "$(stat -c '%a' "${restore_dir}/root/vpn_auth/managed_known_hosts")" == "600" ]]
  [[ "$(sha256sum "${restore_dir}/root/vpn_auth/managed_known_hosts" | awk '{print $1}')" == "${known_hosts_digest}" ]]
  [[ ! -e "${restore_dir}/root/vpn_auth/.env" ]]
  [[ ! -e "${restore_dir}/root/vpn_auth/main.py.pre-upgrade.bak" ]]
  [[ ! -e "${restore_dir}/root/vpn_auth/__pycache__/main.pyc" ]]
  [[ ! -e "${restore_dir}/etc/winsvpn/hub-install-contract.env" ]]
  [[ "$(grep -c '^WINS_HUB_RESTORE_ORDER=fresh-install-then-state$' "${restore_dir}/etc/winsvpn/hub-backup-recovery.env")" == "1" ]]
  [[ "$(sqlite3 "${restore_dir}/root/vpn_auth/vpn_users.db" 'PRAGMA quick_check;')" == "ok" ]]
  [[ "$(sqlite3 "${restore_dir}/root/vpn_auth/vpn_users.db" 'SELECT value FROM proof;')" == "consistent-snapshot" ]]
  [[ "$(sqlite3 "${restore_dir}/root/vpn_auth/winn3_authority_ledger.db" 'PRAGMA quick_check;')" == "ok" ]]
  [[ "$(sqlite3 "${restore_dir}/root/vpn_auth/winn3_authority_ledger.db" 'SELECT slug FROM publications;')" == "ledger-snapshot" ]]
  [[ "$(stat -c '%a' "${restore_dir}/root/vpn_auth/winn3_authority_ledger.db")" == "600" ]]
  cmp -s "${fixture_root}/root/vpn_auth/winn3_charge_keys.json" "${restore_dir}/root/vpn_auth/winn3_charge_keys.json"
  [[ "$(stat -c '%a' "${restore_dir}/root/vpn_auth/winn3_charge_keys.json")" == "600" ]]
  [[ -z "$(find "${runtime_root}" -mindepth 1 -print -quit)" ]]

  # CP-10: without a prepared ledger snapshot the uploader refuses rather
  # than publish an archive that silently lacks the ledger.
  WINS_HUB_DB_SOURCE="${fixture_root}/root/vpn_auth/vpn_users.db" \
    WINS_HUB_DB_SNAPSHOT_DIR="${prepared_db_dir}" bash "${hub_db_snapshot}"
  rm -f "${prepared_db_dir}/winn3_authority_ledger.db"
  if PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=crypt MOCK_RCLONE_REMOTE="${work_dir}/backup-mock-remote-no-ledger" \
      WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
      WINS_HUB_DB_SNAPSHOT_PATH="${prepared_db_dir}/vpn_users.db" \
      WINS_BACKUP_MANIFEST_BIN=/bin/true WINS_BACKUP_PRUNE_BIN=/bin/true \
      bash "${work_dir}/control-backup.sh" > "${work_dir}/control-backup-no-ledger.log" 2>&1; then
    echo "control backup published an archive without the Winn3 authority ledger" >&2
    return 1
  fi
  grep -Fq 'Winn3 authority ledger snapshot is required' "${work_dir}/control-backup-no-ledger.log"
  [[ ! -e "${work_dir}/backup-mock-remote-no-ledger" ]]
  [[ ! -e "${prepared_db_dir}/vpn_users.db" ]]

  local bare_root="${work_dir}/hub-bare-restore-target"
  local fresh_root="${work_dir}/hub-fresh-restore-target"
  install -d -m 700 "${bare_root}" "${fresh_root}"
  if WINS_RESTORE_TARGET_ROOT="${bare_root}" "${restore_preflight}" "${archive}" "${checksum}" >/dev/null 2>&1; then
    err 'Hub restore preflight accepted a bare target without a fresh installer.'
    return 1
  fi
  install -d -m 700 \
    "${fresh_root}/etc/winsvpn" "${fresh_root}/etc/systemd/system" \
    "${fresh_root}/root/vpn_auth/venv/bin" "${fresh_root}/usr/bin" "${fresh_root}/usr/local/bin"
  printf '%s\n' \
    'WINS_HUB_RECOVERY_CONTRACT_VERSION=1' \
    'WINS_HUB_INSTALL_ID=22222222-2222-4222-8222-222222222222' \
    "WINS_HUB_INSTALL_EPOCH=$(( $(date +%s) + 60 ))" \
    'WINS_HUB_RESTORE_ORDER=fresh-install-then-state' \
    > "${fresh_root}/etc/winsvpn/hub-install-contract.env"
  chmod 600 "${fresh_root}/etc/winsvpn/hub-install-contract.env"
  printf '%s\n' '[Service]' 'ExecStart=/root/vpn_auth/venv/bin/python -m uvicorn main:app' > "${fresh_root}/etc/systemd/system/wins-hub.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/bin/cloudflared tunnel run' > "${fresh_root}/etc/systemd/system/wins-control-tunnel.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-gateway-canary' > "${fresh_root}/etc/systemd/system/wins-gateway-canary.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-security-alert-monitor' > "${fresh_root}/etc/systemd/system/wins-security-alert-monitor.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-paypal-sync' > "${fresh_root}/etc/systemd/system/wins-paypal-sync.service"
  chmod 644 "${fresh_root}/etc/systemd/system/"*.service
  for executable in \
    root/vpn_auth/venv/bin/python usr/bin/cloudflared usr/local/bin/wins-gateway-canary \
    usr/local/bin/wins-security-alert-monitor usr/local/bin/wins-paypal-sync; do
    printf '%s\n' '#!/bin/sh' 'exit 0' > "${fresh_root}/${executable}"
    chmod 700 "${fresh_root}/${executable}"
  done
  WINS_RESTORE_TARGET_ROOT="${fresh_root}" "${restore_preflight}" "${archive}" "${checksum}" >/dev/null

  local unsafe_archive="${work_dir}/hub-unsafe-link-backup.tar.gz"
  local unsafe_checksum="${unsafe_archive}.sha256"
  local unsafe_payload="${work_dir}/hub-unsafe-link-payload"
  install -d -m 700 "${unsafe_payload}/etc/winsvpn"
  cp "${restore_dir}/etc/winsvpn/hub-backup-recovery.env" \
    "${unsafe_payload}/etc/winsvpn/hub-backup-recovery.env"
  ln -s /etc/shadow "${unsafe_payload}/unsafe-link"
  tar -C "${unsafe_payload}" -czf "${unsafe_archive}" .
  (cd "${work_dir}" && sha256sum "$(basename "${unsafe_archive}")" > "$(basename "${unsafe_checksum}")")
  if WINS_RESTORE_TARGET_ROOT="${fresh_root}" "${restore_preflight}" \
      "${unsafe_archive}" "${unsafe_checksum}" >/dev/null 2>&1; then
    err 'Hub restore preflight accepted a symlink member which could escape the target root.'
    return 1
  fi

  local archive_attack_dir="${work_dir}/hub-archive-parser-attacks"
  local safe_pax_archive="${archive_attack_dir}/safe-pax.tar.gz"
  local duplicate_archive="${archive_attack_dir}/normalized-duplicate.tar.gz"
  local hardlink_archive="${archive_attack_dir}/hardlink.tar.gz"
  local pax_escape_archive="${archive_attack_dir}/pax-escape.tar.gz"
  install -d -m 700 "${archive_attack_dir}"
  python3 - "${restore_dir}/etc/winsvpn/hub-backup-recovery.env" \
      "${safe_pax_archive}" "${duplicate_archive}" "${hardlink_archive}" "${pax_escape_archive}" <<'PYEOF'
import io
import sys
import tarfile
from pathlib import Path

contract = Path(sys.argv[1]).read_bytes()

def add_regular(archive, name, payload):
    member = tarfile.TarInfo(name)
    member.mode = 0o600
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))

with tarfile.open(sys.argv[2], "w:gz", format=tarfile.PAX_FORMAT) as archive:
    add_regular(archive, "./etc/winsvpn/hub-backup-recovery.env", contract)

with tarfile.open(sys.argv[3], "w:gz", format=tarfile.PAX_FORMAT) as archive:
    add_regular(archive, "./etc/winsvpn/hub-backup-recovery.env", contract)
    add_regular(archive, "etc/winsvpn/hub-backup-recovery.env", b"WINS_HUB_RESTORE_ORDER=unsafe\n")

with tarfile.open(sys.argv[4], "w:gz", format=tarfile.PAX_FORMAT) as archive:
    add_regular(archive, "./etc/winsvpn/hub-backup-recovery.env", contract)
    member = tarfile.TarInfo("./unsafe-hardlink")
    member.type = tarfile.LNKTYPE
    member.linkname = "../../etc/shadow"
    archive.addfile(member)

with tarfile.open(sys.argv[5], "w:gz", format=tarfile.PAX_FORMAT) as archive:
    add_regular(archive, "./etc/winsvpn/hub-backup-recovery.env", contract)
    member = tarfile.TarInfo("./apparently-safe")
    member.pax_headers = {"path": "../pax-escape"}
    member.size = 1
    archive.addfile(member, io.BytesIO(b"x"))
PYEOF
  local candidate_archive candidate_checksum
  for candidate_archive in "${safe_pax_archive}" "${duplicate_archive}" "${hardlink_archive}" "${pax_escape_archive}"; do
    candidate_checksum="${candidate_archive}.sha256"
    (cd "${archive_attack_dir}" && sha256sum "$(basename "${candidate_archive}")" > "$(basename "${candidate_checksum}")")
  done
  WINS_RESTORE_TARGET_ROOT="${fresh_root}" "${restore_preflight}" \
    "${safe_pax_archive}" "${safe_pax_archive}.sha256" >/dev/null
  for candidate_archive in "${duplicate_archive}" "${hardlink_archive}" "${pax_escape_archive}"; do
    if WINS_RESTORE_TARGET_ROOT="${fresh_root}" "${restore_preflight}" \
        "${candidate_archive}" "${candidate_archive}.sha256" >/dev/null 2>&1; then
      err "Hub restore preflight accepted adversarial archive $(basename "${candidate_archive}")."
      return 1
    fi
  done

  local target_root_alias="${work_dir}/hub-fresh-restore-target-alias"
  ln -s "${fresh_root}" "${target_root_alias}"
  if WINS_RESTORE_TARGET_ROOT="${target_root_alias}" "${restore_preflight}" \
      "${archive}" "${checksum}" >/dev/null 2>&1; then
    err 'Hub restore preflight accepted a symlinked alternate target root.'
    return 1
  fi

  local wrong_name_checksum="${work_dir}/hub-wrong-artifact-name.sha256"
  printf '%s  %s\n' "$(sha256sum "${archive}" | awk '{print $1}')" 'different-hub-backup.tar.gz' \
    > "${wrong_name_checksum}"
  chmod 600 "${wrong_name_checksum}"
  if WINS_RESTORE_TARGET_ROOT="${fresh_root}" "${restore_preflight}" \
      "${archive}" "${wrong_name_checksum}" >/dev/null 2>&1; then
    err 'Hub restore preflight accepted a SHA-256 manifest bound to another artifact name.'
    return 1
  fi

  chmod 600 "${fresh_root}/usr/local/bin/wins-paypal-sync"
  if WINS_RESTORE_TARGET_ROOT="${fresh_root}" "${restore_preflight}" "${archive}" "${checksum}" >/dev/null 2>&1; then
    err 'Hub restore preflight accepted a non-executable generated runtime dependency.'
    return 1
  fi
  chmod 700 "${fresh_root}/usr/local/bin/wins-paypal-sync"

  chmod 644 "${fixture_root}/root/vpn_auth/managed_known_hosts"
  if PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=crypt MOCK_RCLONE_REMOTE="${mock_remote}" \
      WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
      bash "${work_dir}/control-backup.sh" >/dev/null 2>&1; then
    err 'Hub backup accepted an over-permissive managed_known_hosts file.'
    return 1
  fi
  chmod 600 "${fixture_root}/root/vpn_auth/managed_known_hosts"
  mv "${fixture_root}/root/vpn_auth/managed_known_hosts" "${fixture_root}/root/vpn_auth/managed_known_hosts.target"
  ln -s managed_known_hosts.target "${fixture_root}/root/vpn_auth/managed_known_hosts"
  if PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=crypt MOCK_RCLONE_REMOTE="${mock_remote}" \
      WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
      bash "${work_dir}/control-backup.sh" >/dev/null 2>&1; then
    err 'Hub backup accepted a symlinked managed_known_hosts file.'
    return 1
  fi
  rm -f "${fixture_root}/root/vpn_auth/managed_known_hosts"
  mv "${fixture_root}/root/vpn_auth/managed_known_hosts.target" "${fixture_root}/root/vpn_auth/managed_known_hosts"
  if [[ "${EUID}" -eq 0 ]]; then
    chown 65534:65534 "${fixture_root}/root/vpn_auth/managed_known_hosts"
    if PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=crypt MOCK_RCLONE_REMOTE="${mock_remote}" \
        WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
        bash "${work_dir}/control-backup.sh" >/dev/null 2>&1; then
      err 'Hub backup accepted a non-root-owned managed_known_hosts file.'
      return 1
    fi
    chown 0:0 "${fixture_root}/root/vpn_auth/managed_known_hosts"
  fi

  mock_remote="${work_dir}/backup-mock-remote-data"
  install -d -m 700 "${mock_remote}"
  # SYNC-13: the data-plane backup is keyed on the fleet-unique BACKUP_HOST_ID
  # the installer pins in backup.env and has no hostname fallback.
  printf '%s\n' 'BACKUP_HOST_ID=node-test' >> "${fixture_root}/etc/winsvpn/backup.env"
  install -d -m 700 "${fixture_root}/root" "${fixture_root}/etc/amnezia" \
    "${fixture_root}/usr/local/etc/xray" "${fixture_root}/opt/AdGuardHome"
  printf '%s\n' \
    'WINS_NODE_RECOVERY_CONTRACT_VERSION=1' \
    'WINS_NODE_INSTALL_ID=33333333-3333-4333-8333-333333333333' \
    'WINS_NODE_INSTALL_EPOCH=100' \
    'WINS_NODE_RESTORE_ORDER=fresh-install-then-state' \
    > "${fixture_root}/etc/winsvpn/node-install-contract.env"
  chmod 600 "${fixture_root}/etc/winsvpn/node-install-contract.env"
  printf '%s\n' 'test-node-env' > "${fixture_root}/root/node.env"
  printf '%s\n' 'test-awg' > "${fixture_root}/etc/amnezia/awg0.conf"
  ln "${fixture_root}/etc/amnezia/awg0.conf" "${fixture_root}/etc/amnezia/awg0-hardlink.conf"
  printf '%s\n' '{}' > "${fixture_root}/usr/local/etc/xray/config.json"
  printf '%s\n' 'bind_hosts:' '  - 127.0.0.1' > "${fixture_root}/opt/AdGuardHome/AdGuardHome.yaml"
  printf '%s\n' '#!/bin/sh' 'exit 0' > "${fixture_root}/opt/AdGuardHome/AdGuardHome"
  chmod 700 "${fixture_root}/opt/AdGuardHome/AdGuardHome"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-node-register' > "${fixture_root}/etc/systemd/system/wins-node-register.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/bin/cloudflared tunnel run' > "${fixture_root}/etc/systemd/system/wins-node-management-tunnel.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-node-canary' > "${fixture_root}/etc/systemd/system/wins-node-canary.service"
  PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=crypt MOCK_RCLONE_REMOTE="${mock_remote}" \
    WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
    bash "${work_dir}/data-backup.sh"
  archive="$(find "${mock_remote}" -maxdepth 1 -type f -name 'wins-node-backup-*.tar.gz' -print -quit)"
  [[ -n "${archive}" && -s "${archive}.sha256" ]]
  (cd "${mock_remote}" && sha256sum -c "$(basename "${archive}.sha256")" >/dev/null)
  local node_restore_dir="${work_dir}/node-backup-restore"
  install -d -m 700 "${node_restore_dir}"
  tar -C "${node_restore_dir}" -xzf "${archive}"
  [[ ! -e "${node_restore_dir}/etc/winsvpn/node-install-contract.env" ]]
  [[ -f "${node_restore_dir}/etc/winsvpn/node-backup-recovery.env" ]]
  [[ -f "${node_restore_dir}/opt/AdGuardHome/AdGuardHome.yaml" ]]
  [[ ! -e "${node_restore_dir}/opt/AdGuardHome/AdGuardHome" ]]
  [[ "$(stat -c '%i' "${node_restore_dir}/etc/amnezia/awg0.conf")" != \
      "$(stat -c '%i' "${node_restore_dir}/etc/amnezia/awg0-hardlink.conf")" ]]

  local node_bare_root="${work_dir}/node-bare-restore-target"
  local node_fresh_root="${work_dir}/node-fresh-restore-target"
  install -d -m 700 "${node_bare_root}" "${node_fresh_root}"
  if WINS_RESTORE_TARGET_ROOT="${node_bare_root}" "${node_restore_preflight}" \
      "${archive}" "${archive}.sha256" >/dev/null 2>&1; then
    err 'Data-plane restore preflight accepted a bare target without a fresh installer.'
    return 1
  fi
  install -d -m 700 \
    "${node_fresh_root}/etc/winsvpn" "${node_fresh_root}/etc/systemd/system" \
    "${node_fresh_root}/usr/bin" "${node_fresh_root}/usr/local/bin" \
    "${node_fresh_root}/usr/sbin" "${node_fresh_root}/opt/AdGuardHome"
  printf '%s\n' \
    'WINS_NODE_RECOVERY_CONTRACT_VERSION=1' \
    'WINS_NODE_INSTALL_ID=44444444-4444-4444-8444-444444444444' \
    "WINS_NODE_INSTALL_EPOCH=$(( $(date +%s) + 60 ))" \
    'WINS_NODE_RESTORE_ORDER=fresh-install-then-state' \
    > "${node_fresh_root}/etc/winsvpn/node-install-contract.env"
  chmod 600 "${node_fresh_root}/etc/winsvpn/node-install-contract.env"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-node-register' > "${node_fresh_root}/etc/systemd/system/wins-node-register.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/bin/cloudflared tunnel run' > "${node_fresh_root}/etc/systemd/system/wins-node-management-tunnel.service"
  printf '%s\n' '[Service]' 'ExecStart=/usr/local/bin/wins-node-canary' > "${node_fresh_root}/etc/systemd/system/wins-node-canary.service"
  chmod 644 "${node_fresh_root}/etc/systemd/system/"*.service
  for executable in \
    usr/bin/docker usr/bin/cloudflared usr/local/bin/xray usr/local/bin/wins-node-register \
    usr/local/bin/wins-node-canary usr/sbin/nginx opt/AdGuardHome/AdGuardHome; do
    printf '%s\n' '#!/bin/sh' 'exit 0' > "${node_fresh_root}/${executable}"
    chmod 700 "${node_fresh_root}/${executable}"
  done
  WINS_RESTORE_TARGET_ROOT="${node_fresh_root}" "${node_restore_preflight}" \
    "${archive}" "${archive}.sha256" >/dev/null

  local node_wrong_name_checksum="${work_dir}/node-wrong-artifact-name.sha256"
  printf '%s  %s\n' "$(sha256sum "${archive}" | awk '{print $1}')" 'different-node-backup.tar.gz' \
    > "${node_wrong_name_checksum}"
  chmod 600 "${node_wrong_name_checksum}"
  if WINS_RESTORE_TARGET_ROOT="${node_fresh_root}" "${node_restore_preflight}" \
      "${archive}" "${node_wrong_name_checksum}" >/dev/null 2>&1; then
    err 'Data-plane restore preflight accepted a SHA-256 manifest bound to another artifact name.'
    return 1
  fi

  local node_unsafe_archive="${work_dir}/node-unsafe-link-backup.tar.gz"
  local node_unsafe_checksum="${node_unsafe_archive}.sha256"
  local node_unsafe_payload="${work_dir}/node-unsafe-link-payload"
  install -d -m 700 "${node_unsafe_payload}/etc/winsvpn"
  cp "${node_restore_dir}/etc/winsvpn/node-backup-recovery.env" \
    "${node_unsafe_payload}/etc/winsvpn/node-backup-recovery.env"
  ln -s /etc/shadow "${node_unsafe_payload}/unsafe-link"
  tar -C "${node_unsafe_payload}" -czf "${node_unsafe_archive}" .
  (cd "${work_dir}" && sha256sum "$(basename "${node_unsafe_archive}")" > "$(basename "${node_unsafe_checksum}")")
  if WINS_RESTORE_TARGET_ROOT="${node_fresh_root}" "${node_restore_preflight}" \
      "${node_unsafe_archive}" "${node_unsafe_checksum}" >/dev/null 2>&1; then
    err 'Data-plane restore preflight accepted a symlink member which could escape the target root.'
    return 1
  fi
  [[ -z "$(find "${runtime_root}" -mindepth 1 -print -quit)" ]]

  if PATH="${mock_bin}:${PATH}" MOCK_RCLONE_TYPE=drive MOCK_RCLONE_REMOTE="${mock_remote}" \
      WINS_BACKUP_SOURCE_ROOT="${fixture_root}" WINS_BACKUP_RUNTIME_ROOT="${runtime_root}" \
      bash "${work_dir}/data-backup.sh" >/dev/null 2>&1; then
    echo "data backup accepted a non-crypt runtime remote" >&2
    exit 1
  fi
  [[ -z "$(find "${runtime_root}" -mindepth 1 -print -quit)" ]]
  echo "PASS control/data backups use root-only ephemeral staging, consistent SQLite snapshotting, encrypted upload verification, fresh-install restore preflight, and cleanup"
}

test_required_infrastructure_contract_when_strict_disabled() {
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export STRICT_ONE_TOUCH_SECRETS=0 REQUIRE_REMOTE_BACKUP=0
    export REQUIRE_CLOUDFLARE_AUTOMATION=1 REQUIRE_ACTIVE_GATEWAY_AUTOMATION=0
    unset CLOUDFLARE_APPCLOUD_API_TOKEN CLOUDFLARE_APPCLOUD_ZONE_ID CLOUDFLARE_WINS_API_TOKEN CLOUDFLARE_WINSVPN_ORG_ZONE_ID CLOUDFLARE_WINSVPN_COM_ZONE_ID || true
    if validate_external_secret_contract >/dev/null 2>&1; then
      err 'Control preflight accepted missing required Cloudflare automation while strict app secrets were disabled.'
      exit 1
    fi
    export REQUIRE_CLOUDFLARE_AUTOMATION=0 REQUIRE_ACTIVE_GATEWAY_AUTOMATION=1
    unset GITHUB_GIST_TOKEN || true
    if validate_external_secret_contract >/dev/null 2>&1; then
      err 'Control preflight accepted missing required Gist automation while strict app secrets were disabled.'
      exit 1
    fi
  )
  echo "PASS required infrastructure secrets remain fail-closed in simulation mode"
}

test_control_ssh_preflight_contract() {
  local key_file="${work_dir}/control-ssh-key"
  ssh-keygen -q -t ed25519 -N '' -f "${key_file}"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    export HUB_SSH_PASSWORD_AUTH=0
    HUB_SSH_PUBLIC_KEY="$(cat "${key_file}.pub")"
    export HUB_SSH_PUBLIC_KEY
    validate_hub_ssh_access_contract
    export HUB_SSH_PUBLIC_KEY='not-an-openssh-public-key'
    if validate_hub_ssh_access_contract >/dev/null 2>&1; then
      err 'Control SSH preflight accepted invalid injected key material.'
      exit 1
    fi
  )
  echo "PASS control SSH access is validated before password login is disabled"
}

test_adaptive_threat_triage() {
  local triage_dir="${work_dir}/threat-triage"
  mkdir -p "${triage_dir}"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /usr/local/lib/wins_threat_triage.py <<'PYEOF'" PYEOF > "${triage_dir}/wins_threat_triage.py"
  WINS_SECURITY_EVENTS_DB="${triage_dir}/events.db" python3 - "${triage_dir}/wins_threat_triage.py" <<'PYEOF'
import importlib.util
import sqlite3
import sys

module_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("wins_threat_triage_test", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.ABSENT_PRODUCTS = {"coldfusion", "geoserver", "apache solr", "tomcat manager"}
module.PRESENT_PRODUCTS = {"nginx", "fastapi", "cowrie", "openssh", "suricata"}
module.ADMIN_SSH_NETWORKS = tuple(module.ipaddress.ip_network(value) for value in ("198.51.100.0/24",))
module.HEALTH_USER_AGENT = "WinsVPN-Health/1.0"

expected_health = module.classify_event("suricata alert", 2, "127.0.0.1", {
    "signature_id": 2002825,
    "signature": "ET INFO curl User-Agent Outbound",
    "category": "Misc activity",
    "transport_src_ip": "127.0.0.1",
    "dest_ip": "127.0.0.1",
    "http_method": "GET",
    "http_url": "/healthz?canary=1",
    "http_user_agent": "WinsVPN-Health/1.0",
})
assert expected_health["label"] == "likely_false_positive", expected_health
assert expected_health["score"] <= 5, expected_health
assert "expected_pinned_loopback_health_probe" in expected_health["reasons"], expected_health

spoofed_or_unexpected = module.classify_event("suricata alert", 2, "127.0.0.1", {
    "signature_id": 2002825,
    "signature": "ET INFO curl User-Agent Outbound",
    "category": "Misc activity",
    "transport_src_ip": "127.0.0.1",
    "dest_ip": "127.0.0.1",
    "http_method": "GET",
    "http_url": "/admin/users",
    "http_user_agent": "WinsVPN-Health/1.0",
})
assert spoofed_or_unexpected["label"] == "needs_review", spoofed_or_unexpected

absent = module.classify_event("suricata alert", 2, "198.51.100.20", {
    "signature_id": 900001,
    "signature": "ET WEB_SERVER ColdFusion remote code execution attempt",
    "category": "Web Application Attack",
    "metadata": {"affected_product": ["ColdFusion"]},
    "action": "allowed",
})
assert absent["label"] == "likely_false_positive", absent
assert any(reason.startswith("targets_verified_absent_product") for reason in absent["reasons"]), absent

threat = module.classify_event("suricata alert", 1, "198.51.100.21", {
    "signature_id": 900002,
    "signature": "HTTP path traversal request for /etc/passwd",
    "category": "Web Application Attack",
    "action": "blocked",
})
assert threat["label"] == "likely_threat" and threat["score"] >= 65, threat

trusted_ssh = module.classify_event("successful ssh login", 2, "198.51.100.40", {
    "method": "publickey",
    "user": "root",
})
assert trusted_ssh["label"] == "likely_false_positive", trusted_ssh
assert trusted_ssh["score"] <= 30, trusted_ssh
assert "successful_ssh_from_configured_admin_cidr" in trusted_ssh["reasons"], trusted_ssh

untrusted_ssh = module.classify_event("successful ssh login", 2, "203.0.113.40", {
    "method": "publickey",
    "user": "root",
})
assert untrusted_ssh["label"] == "needs_review", untrusted_ssh
assert "successful_ssh_outside_or_unknown_admin_cidr" in untrusted_ssh["reasons"], untrusted_ssh

privilege_escalation = module.classify_event("admin privilege escalation", 2, "local", {
    "mechanism": "sudo",
})
assert privilege_escalation["label"] == "likely_threat", privilege_escalation

neutral_details = {
    "signature_id": 900003,
    "signature": "Unrecognized application probe",
    "category": "Potentially Bad Traffic",
}
before = module.classify_event("suricata alert", 2, "198.51.100.22", neutral_details)
with sqlite3.connect(module.EVENTS_DB) as conn:
    module.ensure_schema(conn)
    for index in range(4):
        conn.execute(
            "INSERT INTO security_feedback(event_id, feature_key, label, reason, confirmed_by, confirmed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"feedback-{index}", "sid:900003", "false_positive", "confirmed in controlled replay", "test", module.now_iso()),
        )
after = module.classify_event("suricata alert", 2, "198.51.100.22", neutral_details)
assert after["score"] < before["score"], (before, after)
assert after["label"] == "likely_false_positive", after

with sqlite3.connect(module.EVENTS_DB) as conn:
    module.ensure_schema(conn)
    conn.execute(
        """
        INSERT INTO security_events(
            event_id, observed_at_utc, observed_at_eastern, priority,
            event_type, source_ip, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy-unclassified",
            module.now_iso(),
            module.now_iso(),
            2,
            "suricata alert",
            "198.51.100.23",
            '{"signature_id":900001,"signature":"ColdFusion exploit probe","category":"Web Application Attack"}',
        ),
    )
backfill = module.reclassify_events(10)
assert backfill["processed"] == 1, backfill
with sqlite3.connect(module.EVENTS_DB) as conn:
    row = conn.execute(
        "SELECT triage_label, triage_model_version FROM security_events WHERE event_id=?",
        ("legacy-unclassified",),
    ).fetchone()
assert row == ("likely_false_positive", module.MODEL_VERSION), row
source = open(module_path, encoding="utf-8").read()
for forbidden in ("suricata-update", "disable.conf", "systemctl restart suricata", "iptables -"):
    assert forbidden not in source, forbidden
PYEOF
  echo "PASS adaptive threat triage, exact loopback-health context, absent-product context, and human-feedback learning"
}

test_control_host_hardening_contract() {
  local hub_unit="${work_dir}/wins-hub.service"
  local weekly="${work_dir}/wins-weekly-maintenance"
  local backup_unit="${work_dir}/wins-hub-backup.service"
  local snapshot_unit="${work_dir}/wins-hub-db-snapshot.service"
  local spa_unit="${work_dir}/wins-hub-spa-window.service"

  extract_heredoc "${CONTROL_SCRIPT}" 'cat > "${SERVICE_FILE}" <<EOF' EOF > "${hub_unit}"
  grep -Fxq 'ProtectSystem=strict' "${hub_unit}"
  grep -Fxq 'ProtectHome=read-only' "${hub_unit}"
  # H0 (D3): root's /root/.ssh is not in the hub's writable set. The app's SSH
  # working files and the non-root site-AI forwarding account's authorized keys
  # have their own directories.
  grep -Fxq 'ReadWritePaths=${APP_DIR} /var/lib/wins-hub-ssh /var/lib/wins-site-ai-tunnel /var/lib/wins-security-alerts /var/log/winsvpn' "${hub_unit}"
  if grep -Eq '^ReadWritePaths=.*/root/\.ssh' "${hub_unit}"; then
    echo 'The control API unit must not be able to write root SSH state.' >&2
    return 1
  fi
  # H0 (D4): the hub holds no capability at all. The SPA firewall window, its
  # only use of CAP_NET_ADMIN, runs in wins-hub-spa-window.service, which is
  # where that capability is now held (and held alone).
  grep -Fxq 'CapabilityBoundingSet=' "${hub_unit}"
  grep -Fxq 'AmbientCapabilities=' "${hub_unit}"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /etc/systemd/system/wins-hub-spa-window.service <<'EOF'" EOF > "${spa_unit}"
  grep -Fxq 'CapabilityBoundingSet=CAP_NET_ADMIN' "${spa_unit}"
  grep -Fxq 'AmbientCapabilities=' "${spa_unit}"
  if grep -Fq 'CAP_NET_RAW' "${spa_unit}"; then
    echo 'The SPA window helper must not hold raw-socket capability.' >&2
    return 1
  fi
  if grep -Eq '^(CapabilityBoundingSet|AmbientCapabilities)=.+' "${hub_unit}"; then
    echo 'The control API must not retain any capability.' >&2
    return 1
  fi
  if grep -Fq 'CAP_NET_RAW' "${hub_unit}"; then
    echo 'The control API must not retain raw-socket capability.' >&2
    return 1
  fi
  grep -Fxq 'MemoryDenyWriteExecute=true' "${hub_unit}"
  grep -Fxq 'RestrictNamespaces=true' "${hub_unit}"
  grep -Fxq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' "${hub_unit}"
  grep -Fxq 'PrivateDevices=true' "${hub_unit}"

  extract_heredoc "${CONTROL_SCRIPT}" "cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'" EOF > "${weekly}"
  bash -n "${weekly}"
  grep -Fq 'trap '\''maintenance_exit_handler "$?"'\'' EXIT' "${weekly}"
  grep -Fq 'restore_unattended_upgrades || true' "${weekly}"
  grep -Fq 'systemctl enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer' "${weekly}"
  grep -Fq 'curl -A "${CURL_UA}"' "${weekly}"
  grep -Fq 'APT::Periodic::Unattended-Upgrade "1";' "${CONTROL_SCRIPT}"
  grep -Fq 'Unattended-Upgrade::Automatic-Reboot "false";' "${CONTROL_SCRIPT}"
  grep -Fq "trap 'configure_unattended_security_updates || true' EXIT" "${CONTROL_SCRIPT}"

  extract_heredoc "${CONTROL_SCRIPT}" "cat > /etc/systemd/system/wins-hub-backup.service <<'EOF'" EOF > "${backup_unit}"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /etc/systemd/system/wins-hub-db-snapshot.service <<'EOF'" EOF > "${snapshot_unit}"
  grep -Fxq 'Requires=wins-hub-db-snapshot.service' "${backup_unit}"
  grep -Fxq 'After=wins-hub-db-snapshot.service' "${backup_unit}"
  grep -Fxq 'ProtectSystem=strict' "${backup_unit}"
  grep -Fxq 'ProtectHome=read-only' "${backup_unit}"
  grep -Fxq 'ReadWritePaths=/run /var/backups/winsvpn /var/backups/winsvpn-manifests /root/.config/rclone' "${backup_unit}"
  grep -Fxq 'CapabilityBoundingSet=' "${backup_unit}"
  grep -Fxq 'RestrictAddressFamilies=AF_UNIX' "${snapshot_unit}"
  grep -Fxq 'IPAddressDeny=any' "${snapshot_unit}"
  grep -Fxq 'ReadWritePaths=/root/vpn_auth /run/wins-hub-db-snapshot' "${snapshot_unit}"
  grep -Fxq 'ReadOnlyPaths=-/root/vpn_auth/main.py -/root/vpn_auth/managed_known_hosts -/root/vpn_auth/venv' "${snapshot_unit}"
  grep -Fxq 'CapabilityBoundingSet=' "${snapshot_unit}"
  grep -Fq 'harden_sensitive_artifacts' "${CONTROL_SCRIPT}"
  grep -Fq 'find "${artifact_dir}" -xdev -type f' "${CONTROL_SCRIPT}"
  grep -Fq 'cmp -s "${legacy_website_key}" "${WEBSITE_TLS_KEY}"' "${CONTROL_SCRIPT}"

  grep -Fq 'SECURITY_ALERT_NO_RECORD_SIGNATURE_IDS_DEFAULT=""' "${CONTROL_SCRIPT}"
  if grep -Eq 'SECURITY_ALERT_(NO_RECORD|SUPPRESS)_SIGNATURE_IDS_DEFAULT=.*2002825' "${CONTROL_SCRIPT}"; then
    echo "control globally suppresses the ET curl User-Agent rule" >&2
    return 1
  fi
  grep -Fq 'record_event(priority, event_type, source_ip, details, "expected_health_check")' "${CONTROL_SCRIPT}"
  grep -Fq '"http_user_agent": http.get("http_user_agent")' "${CONTROL_SCRIPT}"
  echo "PASS control unattended security updates, least-capability units, root-only artifacts, and context-aware Suricata health handling"
}

test_xray_service_hardening_contract() {
  local data_dropin="${work_dir}/data-xray-hardening.conf"
  local core_unit="${work_dir}/core-xray.service"
  local core_exit_unit="${work_dir}/core-xray-exit.service"
  local unit needle

  extract_heredoc "${DATA_SCRIPT}" \
    "cat > /etc/systemd/system/xray.service.d/20-winsvpn-user.conf <<'EOF'" EOF \
    > "${data_dropin}"
  extract_heredoc "${CORE_SCRIPT}" \
    "cat > /etc/systemd/system/xray.service <<'EOF'" EOF > "${core_unit}"
  extract_heredoc "${CORE_SCRIPT}" \
    "cat > /etc/systemd/system/wins-core-xray-exit@.service <<'EOF'" EOF \
    > "${core_exit_unit}"

  for unit in "${data_dropin}" "${core_unit}" "${core_exit_unit}"; do
    for needle in \
      'User=xray' \
      'Group=xray' \
      'StateDirectory=xray' \
      'LogsDirectory=xray' \
      'UMask=0077' \
      'NoNewPrivileges=true' \
      'PrivateTmp=true' \
      'PrivateDevices=true' \
      'ProtectSystem=strict' \
      'ProtectHome=true' \
      'ReadWritePaths=/var/log/xray /var/lib/xray' \
      'ProtectKernelTunables=true' \
      'ProtectKernelModules=true' \
      'ProtectKernelLogs=true' \
      'ProtectControlGroups=true' \
      'ProtectClock=true' \
      'ProtectHostname=true' \
      'RestrictSUIDSGID=true' \
      'RestrictNamespaces=true' \
      'LockPersonality=true' \
      'CapabilityBoundingSet=' \
      'AmbientCapabilities=' \
      'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'; do
      grep -Fxq "${needle}" "${unit}"
    done
  done
  echo "PASS data/Core primary and fallback Xray units use strict least-privilege sandboxes"
}

test_entrypoint_order_and_noninteractive_apt() {
  python3 - "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${CORE_SCRIPT}" <<'PYEOF'
import pathlib
import sys

roles = {
    "control": (pathlib.Path(sys.argv[1]), "preflight_control", "mark_control_role"),
    "data": (pathlib.Path(sys.argv[2]), "preflight_data_plane", "mark_data_role"),
    "core": (pathlib.Path(sys.argv[3]), "preflight_core", "mark_core_role"),
}
for role, (path, preflight, mark) in roles.items():
    text = path.read_text(encoding="utf-8")
    main_start = text.rfind("\nmain() {")
    if main_start < 0:
        raise SystemExit(f"{role}: outer main function missing")
    main = text[main_start:]
    if role == "control":
        positions = [main.find(preflight), main.find("install_hub_ssh_public_key"), main.find(mark), main.find("apt_install")]
        if not (positions[0] >= 0 and positions[0] < positions[1] < positions[2] < positions[3]):
            raise SystemExit(f"{role}: expected preflight -> SSH key install -> role marker -> apt_install order, got {positions}")
    else:
        positions = [main.find(preflight), main.find(mark), main.find("apt_install")]
        if not (positions[0] >= 0 and positions[0] < positions[1] < positions[2]):
            raise SystemExit(f"{role}: expected preflight -> role marker -> apt_install order, got {positions}")
    required = (
        "export DEBIAN_FRONTEND=noninteractive",
        "export DEBIAN_PRIORITY=critical",
        "export APT_LISTCHANGES_FRONTEND=none",
        "export NEEDRESTART_MODE=a",
        "export UCF_FORCE_CONFFOLD=1",
        "DPkg::Lock::Timeout=300",
        "Acquire::Retries=3",
        "Dpkg::Use-Pty=0",
        "Dpkg::Options::=--force-confdef",
        "Dpkg::Options::=--force-confold",
        "wait_for_cloud_init",
        "wait_for_package_manager",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise SystemExit(f"{role}: missing noninteractive/package-order controls: {missing}")
    direct_apt = [
        (line_number, line.strip())
        for line_number, line in enumerate(text.splitlines(), 1)
        if line.lstrip().startswith("apt-get ")
    ]
    if direct_apt:
        raise SystemExit(f"{role}: apt-get bypasses the shared retry/noninteractive wrapper: {direct_apt}")

control = roles["control"][0].read_text(encoding="utf-8")
control_preflight = control[control.index("preflight_control() {"):control.index("mark_control_role() {")]
if "validate_external_secret_contract" not in control_preflight:
    raise SystemExit("control: external secret contract is not part of immutable preflight")
if "validate_hub_ssh_access_contract" not in control_preflight:
    raise SystemExit("control: SSH access contract is not part of immutable preflight")
data = roles["data"][0].read_text(encoding="utf-8")
data_preflight = data[data.index("preflight_data_plane() {"):data.index("mark_data_role() {")]
if "validate_rclone_injection_contract" not in data_preflight:
    raise SystemExit("data: rclone injection is not validated before host mutation")
data_main = data[data.rfind("\nmain() {"):]
management_positions = [
    data_main.find("configure_node_management_tunnel"),
    data_main.find("write_register_script"),
    data_main.find("verify_hub_node_management"),
    data_main.find("write_firewall"),
    data_main.find("harden_sshd"),
    data_main.rfind("verify_hub_node_management"),
]
if data_main.count("verify_hub_node_management") != 2 or not all(
    left >= 0 and left < right for left, right in zip(management_positions, management_positions[1:])
):
    raise SystemExit(
        "data: expected tunnel -> register -> verify -> firewall -> harden SSH -> verify order, "
        f"got {management_positions}"
    )
control_text = roles["control"][0].read_text(encoding="utf-8")
if '[[ "${ADMIN_TOKEN:-}" =~ ^[^[:space:]]{32,}$ ]]' not in control_text:
    raise SystemExit("control: ADMIN_TOKEN does not enforce the shared 32-character minimum")
# L41: data planes and Cores never require, send, or persist ADMIN_TOKEN.
for role, refusal, credential in (
    ("data", "data_refuse_node_fleet_credentials || exit 1", "data_require_subject_credential || exit 1"),
    ("core", "core_refuse_node_fleet_credentials || exit 1", "core_require_subject_credential || exit 1"),
):
    text = roles[role][0].read_text(encoding="utf-8")
    if '[[ "${ADMIN_TOKEN:-}" =~ ^[^[:space:]]{32,}$ ]]' in text:
        raise SystemExit(f"{role}: preflight still requires the fleet ADMIN_TOKEN")
    if "x-admin-token" in text:
        raise SystemExit(f"{role}: installer still sends the fleet admin token")
    if refusal not in text or credential not in text:
        raise SystemExit(f"{role}: preflight lacks the fleet-credential refusal or the subject-credential check")
PYEOF
  echo "PASS role preflight ordering, control-only admin-token policy, and noninteractive apt controls"
}

test_unattended_update_restoration() {
  local role script success_log failure_log refusal_log refusal_out meta_state status
  for role in data core; do
    if [[ "${role}" == "data" ]]; then
      script="${DATA_SCRIPT}"
    else
      script="${CORE_SCRIPT}"
    fi
    success_log="${work_dir}/${role}-unattended-success.log"
    failure_log="${work_dir}/${role}-unattended-failure.log"
    # Round CS3: apt_install keeps zram across kernel upgrades by installing
    # linux-image-extra-virtual when no generic kernel metapackage is present.
    # The stubs model a linux-virtual host: nothing generic installed until the
    # metapackage install lands, with a candidate available (the pass path).
    meta_state="${work_dir}/${role}-unattended-generic-installed"
    rm -f "${meta_state}"

    (
      export WINS_DEFAULTS_FILE="${work_dir}/missing-${role}-defaults.env"
      export WINS_SECRETS_FILE="${work_dir}/missing-${role}-secrets.env"
      export NODE_ENV_FILE="${work_dir}/missing-${role}-node.env"
      export CORE_ENV_FILE="${work_dir}/missing-${role}-core.env"
      set --
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      wait_for_cloud_init() { :; }
      wait_for_package_manager() { :; }
      repair_package_state() { :; }
      ensure_bootstrap_dns() { :; }
      ensure_suricata_stable_repository() { :; }
      verify_suricata_package() { :; }
      run_yabs_benchmark() { :; }
      apt-cache() {
        [[ "$*" == 'policy linux-image-extra-virtual' ]] || return 1
        printf 'linux-image-extra-virtual:\n  Installed: (none)\n  Candidate: 6.8.0-142.142\n'
      }
      dpkg-query() {
        [[ "${*: -1}" == linux-image-generic && -e "${meta_state}" ]] || return 1
        printf 'ii '
      }
      # ensure_zram_kernel_module (Round CS3) probes the running and the
      # pending default kernel for the zram module; model a host that has it,
      # so the result does not depend on the test machine's kernels.
      modinfo() { return 0; }
      depmod() { :; }
      apt-get() { printf 'package-work:%s\n' "$*" >> "${success_log}"; }
      apt_retry() {
        printf 'package-work:%s\n' "$*" >> "${success_log}"
        [[ "$*" != *' install -y --no-install-recommends linux-image-extra-virtual' ]] || : > "${meta_state}"
      }
      systemctl() {
        case "$*" in
          'stop unattended-upgrades') printf 'stop\n' >> "${success_log}" ;;
          'unmask unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer') printf 'restore-unmask\n' >> "${success_log}" ;;
          'enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer') printf 'restore\n' >> "${success_log}" ;;
        esac
        return 0
      }
      APT_GET=(apt-get)
      apt_install
    )
    python3 - "${success_log}" <<'PYEOF'
import sys

events = open(sys.argv[1], encoding="utf-8").read().splitlines()
stop = events.index("stop")
work = [index for index, event in enumerate(events) if event.startswith("package-work:")]
restore = events.index("restore")
assert work and stop < min(work) <= max(work) < restore, events
assert events.count("restore") == 1, events
assert "package-work:apt-get install -y --no-install-recommends linux-image-extra-virtual" in events, events
PYEOF

    set +e
    (
      set -Eeuo pipefail
      export WINS_DEFAULTS_FILE="${work_dir}/missing-${role}-defaults.env"
      export WINS_SECRETS_FILE="${work_dir}/missing-${role}-secrets.env"
      export NODE_ENV_FILE="${work_dir}/missing-${role}-node.env"
      export CORE_ENV_FILE="${work_dir}/missing-${role}-core.env"
      set --
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      wait_for_cloud_init() { :; }
      wait_for_package_manager() { :; }
      repair_package_state() { :; }
      # As in the other two arms: without these, a host with no working DNS
      # runs the real resolver bootstrap, which rewrites /etc/resolv.conf and
      # exits 1 before apt_retry is reached.
      ensure_bootstrap_dns() { :; }
      ensure_suricata_stable_repository() { :; }
      verify_suricata_package() { :; }
      apt_retry() {
        printf 'package-work:%s\n' "$*" >> "${failure_log}"
        return 71
      }
      systemctl() {
        case "$*" in
          'stop unattended-upgrades') printf 'stop\n' >> "${failure_log}" ;;
          'unmask unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer') printf 'restore-unmask\n' >> "${failure_log}" ;;
          'enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer') printf 'restore\n' >> "${failure_log}" ;;
        esac
        return 0
      }
      APT_GET=(apt-get)
      apt_install
    ) >/dev/null 2>&1
    status=$?
    set -e
    [[ "${status}" == "71" ]]
    [[ "$(cat "${failure_log}")" == $'stop\npackage-work:apt-get update -y\nrestore-unmask\nrestore' ]]

    # Refusal (Round CS3): no generic metapackage and no candidate for
    # linux-image-extra-virtual, so apt_install stops before installing it and
    # the EXIT trap still restores unattended upgrades. Data plane only: the
    # Core's EXIT trap also runs its package-security rollback, which a test
    # must not drive on the host; ensure_zram_kept_across_kernel_upgrades is
    # byte-identical in both installers.
    if [[ "${role}" == "data" ]]; then
      refusal_log="${work_dir}/${role}-unattended-refusal.log"
      refusal_out="${work_dir}/${role}-unattended-refusal.out"
      set +e
      (
        set -Eeuo pipefail
        export WINS_DEFAULTS_FILE="${work_dir}/missing-${role}-defaults.env"
        export WINS_SECRETS_FILE="${work_dir}/missing-${role}-secrets.env"
        export NODE_ENV_FILE="${work_dir}/missing-${role}-node.env"
        export CORE_ENV_FILE="${work_dir}/missing-${role}-core.env"
        set --
        # shellcheck disable=SC1090
        source <(sed '/^main "\$@"$/d' "${script}")
        wait_for_cloud_init() { :; }
        wait_for_package_manager() { :; }
        repair_package_state() { :; }
        ensure_bootstrap_dns() { :; }
        ensure_suricata_stable_repository() { :; }
        verify_suricata_package() { :; }
        run_yabs_benchmark() { :; }
        apt-cache() {
          [[ "$*" == 'policy linux-image-extra-virtual' ]] || return 1
          printf 'linux-image-extra-virtual:\n  Installed: (none)\n  Candidate: (none)\n'
        }
        dpkg-query() { return 1; }
        apt-get() { printf 'package-work:%s\n' "$*" >> "${refusal_log}"; }
        apt_retry() { printf 'package-work:%s\n' "$*" >> "${refusal_log}"; }
        systemctl() {
          case "$*" in
            'stop unattended-upgrades') printf 'stop\n' >> "${refusal_log}" ;;
            'unmask unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer') printf 'restore-unmask\n' >> "${refusal_log}" ;;
            'enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer') printf 'restore\n' >> "${refusal_log}" ;;
          esac
          return 0
        }
        APT_GET=(apt-get)
        apt_install
      ) > "${refusal_out}" 2>&1
      status=$?
      set -e
      [[ "${status}" == "1" ]]
      grep -Fq 'Ubuntu package linux-image-extra-virtual is unavailable; a later kernel upgrade would drop the zram module.' "${refusal_out}"
      python3 - "${refusal_log}" <<'PYEOF'
import sys

events = open(sys.argv[1], encoding="utf-8").read().splitlines()
assert events[0] == "stop", events
assert not any("linux-image-extra-virtual" in event for event in events), events
assert events[-2:] == ["restore-unmask", "restore"], events
PYEOF
    fi
  done

  # Exercise the generated data-plane weekly job's EXIT path with safe command
  # stubs. The injected failure happens after package work but before its normal
  # restore call, so only the exact generated trap can produce the final event.
  local weekly="${work_dir}/data-weekly-unattended"
  local weekly_failure="${work_dir}/data-weekly-unattended-failure"
  local fake_bin="${work_dir}/weekly-fake-bin"
  local weekly_events="${work_dir}/weekly-unattended-events.log"
  extract_heredoc "${DATA_SCRIPT}" "cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'" EOF > "${weekly}"
  sed \
    -e "s#LOG_FILE=\"/var/log/winsvpn/weekly-maintenance.log\"#LOG_FILE=\"${work_dir}/weekly-maintenance.log\"#" \
    -e "s#mkdir -p /var/log/winsvpn#mkdir -p \"${work_dir}\"#" \
    -e 's#if \[\[ -f /root/node.env \]\]; then#if false; then#' \
    -e '/run_step "apt update"/a exit 71' \
    "${weekly}" > "${weekly_failure}"
  chmod 700 "${weekly_failure}"
  mkdir -p "${fake_bin}"
  cat > "${fake_bin}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl:%s\n' "$*" >> "${WINS_TEST_EVENT_FILE}"
exit 0
EOF
  cat > "${fake_bin}/apt-get" <<'EOF'
#!/usr/bin/env bash
printf 'package-work:apt-get %s\n' "$*" >> "${WINS_TEST_EVENT_FILE}"
exit 0
EOF
  cat > "${fake_bin}/dpkg" <<'EOF'
#!/usr/bin/env bash
printf 'package-work:dpkg %s\n' "$*" >> "${WINS_TEST_EVENT_FILE}"
exit 0
EOF
  for command_name in fuser pgrep; do
    cat > "${fake_bin}/${command_name}" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  done
  chmod 700 "${fake_bin}/"*
  set +e
  PATH="${fake_bin}:${PATH}" WINS_TEST_EVENT_FILE="${weekly_events}" bash "${weekly_failure}" >/dev/null 2>&1
  status=$?
  set -e
  [[ "${status}" == "71" ]]
  python3 - "${weekly_events}" <<'PYEOF'
import sys

events = open(sys.argv[1], encoding="utf-8").read().splitlines()
stop = events.index("systemctl:stop unattended-upgrades")
work = next(index for index, event in enumerate(events) if event.startswith("package-work:"))
restore = events.index("systemctl:enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer")
assert stop < work < restore, events
PYEOF
  grep -Fq 'trap '\''maintenance_exit_handler "$?"'\'' EXIT' "${weekly}"
  grep -Fq 'restore_unattended_upgrades' "${weekly}"
  grep -Fq 'trap - EXIT' "${weekly}"
  echo "PASS data/Core package work restores unattended upgrades on success and EXIT failure paths"
}

test_suricata_stable_package_contract() {
  local script role
  for role in control data core; do
    if [[ "${role}" == "control" ]]; then
      script="${CONTROL_SCRIPT}"
    elif [[ "${role}" == "data" ]]; then
      script="${DATA_SCRIPT}"
    else
      script="${CORE_SCRIPT}"
    fi
    (
      # Load function definitions without executing the deployment entrypoint.
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      local removal_seen=0
      suricata_repository_present() { return 0; }
      apt-cache() {
        printf '500 https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu noble/main amd64 Packages\n'
      }
      dpkg-query() {
        if [[ "$*" == *'-W'* ]]; then
          printf 'ii '
        else
          command dpkg-query "$@"
        fi
      }
      fake_apt() { printf 'Remv suricata-update [1.3.0-2]\n'; }
      apt_retry() {
        if [[ "$*" == *'remove -y suricata-update'* ]]; then
          removal_seen=1
        fi
        return 0
      }
      APT_GET=(fake_apt)
      ensure_suricata_stable_repository
      [[ "${removal_seen}" == "1" ]]
    )
    (
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      suricata_repository_present() { return 0; }
      apt-cache() {
        printf '500 https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu noble/main amd64 Packages\n'
      }
      dpkg-query() { printf 'ii '; }
      fake_apt() {
        printf 'Remv suricata-update [1.3.0-2]\n'
        printf 'Remv suricata [1:7.0.3-1build3]\n'
      }
      apt_retry() { return 0; }
      # shellcheck disable=SC2034
      APT_GET=(fake_apt)
      negative_log="${work_dir}/${role}-suricata-migration-negative.log"
      if ensure_suricata_stable_repository >"${negative_log}" 2>&1; then
        err "${role} accepted a Suricata migration plan that removes another package."
        exit 1
      fi
      grep -Fq 'Unexpected Suricata migration removal plan' "${negative_log}" \
        || {
          err "${role} did not explain why the collateral-removal plan was rejected."
          exit 1
        }
    )
  done

  (
    # The local runtime validator must exercise the same current stable package.
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    verify_suricata_package
  )
  echo "PASS official Suricata stable package and exact migration-removal contract"
}

test_core_transport_contract() {
  local raw_origin_log="${work_dir}/core-raw-origin-negative.log"
  local sync_agent="${work_dir}/wins-core-sync-origin-guard"
  [[ "$(grep -Fc 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-90}"' "${CORE_SCRIPT}")" == "2" ]]
  if grep -Fq 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-45}"' "${CORE_SCRIPT}"; then false; fi
  grep -Fq '"${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS}" -ge 5' "${CORE_SCRIPT}"
  grep -Fq '"${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS}" -le 120' "${CORE_SCRIPT}"
  (
    unset CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CORE_SCRIPT}")
    [[ "${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS}" == "90" ]]
    [[ "$(normalize_core_stealth_transports '18080:none,18443:tls' 18080 none)" == '18080:none,18443:tls' ]]
    [[ "$(normalize_core_stealth_transports '18443:tls,18080:none' 18443 tls)" == '18443:tls,18080:none' ]]
    if normalize_core_stealth_transports '18080:tls' 18080 none >/dev/null 2>&1; then
      err 'Core transport normalization accepted plaintext and TLS on the same public port.'
      exit 1
    fi
    HUB_API_BASE='https://sync.winsvpn.org'
    if hub_api_uses_raw_origin; then false; fi
    HUB_API_BASE='https://192.0.2.10'
    hub_api_uses_raw_origin
    HUB_API_BASE='https://[2001:db8::10]:443'
    hub_api_uses_raw_origin
  )
  extract_heredoc "${CORE_SCRIPT}" 'cat > "${sync_tmp}" <<'\''EOF'\''' EOF > "${sync_agent}"
  grep -Fqx 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-90}"' "${sync_agent}"
  if grep -Fq 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-45}"' "${sync_agent}"; then false; fi
  chmod 700 "${sync_agent}"
  # The agent's main runs here. Before it refuses, it sources CORE_ENV_FILE,
  # takes the sync lock and adds a blackhole policy rule for the client pool,
  # and its EXIT trap reports to the hub. Keep all of that off the host: a
  # private network namespace, and the env file and lock in this test's
  # work directory (on a real Core the defaults are the live ones).
  if HUB_API_BASE='https://192.0.2.10' \
      CORE_TOKEN='runtime-validator-scoped-core-token' \
      CORE_ENV_FILE="${work_dir}/missing-core-sync-origin-guard.env" \
      CORE_SYNC_LOCK_FILE="${work_dir}/core-sync-origin-guard.lock" \
      unshare -n bash "${sync_agent}" >"${raw_origin_log}" 2>&1; then
    echo 'Core sync agent accepted a raw hidden-hub origin.' >&2
    exit 1
  fi
  grep -Fq 'Refusing to send the Core token to a raw control-hub IP' "${raw_origin_log}" \
    || {
      echo 'Core sync agent did not explain its raw hidden-hub rejection.' >&2
      exit 1
    }
  echo "PASS core dynamic Xray transport ordering, conflict rejection, and hidden-origin guard"
}

test_core_exit_xray_fallback_contract() {
  local agent="${work_dir}/wins-core-sync-xray-fallback"
  local ports_file="${work_dir}/core-xray-fallback-ports.json"
  local server_log="${work_dir}/core-xray-fallback-server.log"
  local server_pid item selected selected_port selected_security attempt
  extract_heredoc "${CORE_SCRIPT}" 'cat > "${sync_tmp}" <<'\''EOF'\''' EOF > "${agent}"
  chmod 700 "${agent}"

  python3 - "${ports_file}" >"${server_log}" 2>&1 <<'PYEOF' &
import json
import os
import pathlib
import socket
import sys
import threading

listeners = []
for _ in range(2):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listeners.append(listener)

pathlib.Path(sys.argv[1]).write_text(
    json.dumps([listener.getsockname()[1] for listener in listeners]),
    encoding="utf-8",
)

def serve(listener, status):
    connection, _ = listener.accept()
    connection.settimeout(5)
    connection.recv(4096)
    connection.sendall((status + "\r\nConnection: close\r\n\r\n").encode("ascii"))
    connection.close()
    listener.close()

threads = [
    threading.Thread(target=serve, args=(listeners[0], "HTTP/1.1 301 Moved Permanently")),
    threading.Thread(target=serve, args=(listeners[1], "HTTP/1.1 101 Switching Protocols")),
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
PYEOF
  server_pid=$!
  for attempt in {1..50}; do
    [[ -s "${ports_file}" ]] && break
    sleep 0.1
  done
  [[ -s "${ports_file}" ]] || {
    kill "${server_pid}" >/dev/null 2>&1 || true
    echo 'Core Xray fallback test server did not start.' >&2
    exit 1
  }
  item="$(jq -n \
    --argjson ports "$(cat "${ports_file}")" \
    '{
      exit_stealth_endpoint:("127.0.0.1:" + ($ports[0] | tostring)),
      exit_xray_uuid:"11111111-1111-4111-8111-111111111111",
      exit_xray_path:"/wins-test",
      exit_xray_sni:"fallback.example.test",
      exit_wg_port:9110,
      exit_xray_transports:[
        {port:$ports[0],security:"none"},
        {port:$ports[1],security:"none"}
      ]
    }')"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${agent}")
    selected="$(select_reachable_xray_transport "${item}")"
    selected_port="$(jq -r '.port' <<<"${selected}")"
    selected_security="$(jq -r '.security' <<<"${selected}")"
    [[ "${selected_port}" == "$(jq -r '.[1]' "${ports_file}")" ]]
    [[ "${selected_security}" == "none" ]]
  )
  wait "${server_pid}"

  python3 - "${CONTROL_SCRIPT}" "${CORE_SCRIPT}" <<'PYEOF'
import pathlib
import sys

control = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
core = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
for field in (
    '"exit_stealth_endpoint"',
    '"exit_xray_uuid"',
    '"exit_xray_transports"',
    '"exit_direct_awg_enabled"',
):
    if field not in control:
        raise SystemExit(f"Core assignment feed omits {field}")
for needle in (
    'select_reachable_xray_transport',
    'wins-core-xray-exit@.service',
    'direct AWG handshake stale; switched to verified Xray fallback',
    'CORE_EXIT_TRANSPORT_MODE="${CORE_EXIT_TRANSPORT_MODE:-auto}"',
    'protocol:"tunnel"',
    'network:"udp"',
    'address:"127.0.0.1"',
    'port:$remote_awg_port',
    'mux:{enabled:false,concurrency:0,xudpConcurrency:0,xudpProxyUDP443:"skip"}',
    'xray -test -config "${tmp}"',
    'existing_stealth_transport_is_healthy',
    'Core exit setup transition class=healthy_stealth_preserved',
    'Core exit setup transition class=direct_fallback_persisted',
):
    if needle not in core:
        raise SystemExit(f"Core Xray fallback contract omits {needle}")
if 'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}' in core:
    raise SystemExit('Core Xray fallback must not re-enable XUDP aggregation')
if 'dokodemo-door' in core:
    raise SystemExit('Core Xray fallback must not use the legacy dokodemo-door inbound')
for incompatible_field in ('allowedNetwork', 'rewriteAddress', 'rewritePort'):
    if incompatible_field in core:
        raise SystemExit(
            f'Core Xray fallback uses prerelease field {incompatible_field} with pinned 26.9.30'
        )
PYEOF
  echo "PASS core ordered Xray WebSocket preflight and automatic direct-to-stealth fallback contract"
}

test_core_stale_assignment_cleanup() {
  local agent="${work_dir}/wins-core-sync"
  local wrapper="${work_dir}/core-cleanup-selftest.sh"
  local state_dir="${work_dir}/core-cleanup-state"
  local docker_log="${work_dir}/core-cleanup-docker.log"
  extract_heredoc "${CORE_SCRIPT}" 'cat > "${sync_tmp}" <<'\''EOF'\''' EOF > "${agent}"
  chmod 700 "${agent}"
  mkdir -p "${state_dir}"
  cat > "${wrapper}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
state_dir="$2"
docker_log="$3"
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "${agent}")
trap '[[ $- == *e* ]] && echo "FAIL core-cleanup-selftest.sh:${LINENO}: ${BASH_COMMAND}" >&2' ERR

CORE_EXIT_IFACE_PREFIX=corex
CORE_SYNC_STATE_DIR="${state_dir}"
# The agent keeps its public-address cache and retry marker under the host's
# /run. Keep them in this test's state: on a real Core the test would reset
# that Core's marker, and a rerun inside 60 s would be rate-limited here.
CORE_PUBLIC_IP_CACHE_FILE="${state_dir}/public-ipv4"
ASSIGNMENTS_JSON='{"assignments":[{"iface":"corex3","client_ip":"10.9.0.3","table_id":52003}]}'
CORE_TOKEN=runtime-validator-scoped-core-token
CORE_INGRESS_PUBLIC_KEY=test-ingress-public
CORE_EXIT_PUBLIC_KEY=test-exit-public
CORE_EXIT_PRIVATE_KEY=test-exit-private
CORE_PUBLIC_INGRESS_ENDPOINT=198.51.100.10:9210
CORE_PUBLIC_STEALTH_ENDPOINT=core.example.test:80

# The lookup answer must be globally routable: core_ipv4_is_public refuses
# 198.51.100.0/24 (RFC 5737 documentation space), as it must.
printf '%s\n' 203.0.114.25 > "${state_dir}/lookup-answer"
curl() {
  cat "${state_dir}/lookup-answer"
}
fresh_lookup() {
  rm -f -- "${CORE_PUBLIC_IP_CACHE_FILE}" "${CORE_PUBLIC_IP_CACHE_FILE}.attempt"
}

# Endpoint modes are core_endpoint_should_follow_public_ipv4's contract.
# Mode 0: persisted endpoints are advertised exactly as stored (a floating IP
# or NAT ingress can differ from the probed egress address).
CORE_PUBLIC_ENDPOINT_AUTODETECT=0
fresh_lookup
require_ready
[[ "${CORE_PUBLIC_INGRESS_ENDPOINT}" == "198.51.100.10:9210" ]]
[[ "${CORE_PUBLIC_STEALTH_ENDPOINT}" == "core.example.test:80" ]]
# Mode auto, the shipped default: an IPv4-literal endpoint follows the detected
# public address, a DNS-named one is kept, and an empty one is filled.
CORE_PUBLIC_ENDPOINT_AUTODETECT=auto
fresh_lookup
require_ready
[[ "${CORE_PUBLIC_INGRESS_ENDPOINT}" == "203.0.114.25:9210" ]]
[[ "${CORE_PUBLIC_STEALTH_ENDPOINT}" == "core.example.test:80" ]]
CORE_PUBLIC_INGRESS_ENDPOINT=''
fresh_lookup
require_ready
[[ "${CORE_PUBLIC_INGRESS_ENDPOINT}" == "203.0.114.25:9210" ]]
[[ "${CORE_PUBLIC_STEALTH_ENDPOINT}" == "core.example.test:80" ]]
# With no public answer, an empty endpoint never becomes a LAN address or
# ":9210"; it stays empty and the cause is named. A globally routable
# interface address is still used, even when it is not the first one listed.
printf '%s\n' 198.51.100.25 > "${state_dir}/lookup-answer"
ip link add corelan0 type dummy
ip addr add 192.168.50.10/24 dev corelan0
ip link set corelan0 up
CORE_PUBLIC_INGRESS_ENDPOINT=''
fresh_lookup
require_ready 2> "${state_dir}/require-ready.err"
[[ -z "${CORE_PUBLIC_INGRESS_ENDPOINT}" ]]
grep -Fq 'class=public_ip_unavailable' "${state_dir}/require-ready.err"
ip addr add 203.0.114.77/24 dev corelan0
fresh_lookup
require_ready 2> "${state_dir}/require-ready.err"
[[ "${CORE_PUBLIC_INGRESS_ENDPOINT}" == "203.0.114.77:9210" ]]
[[ "${CORE_PUBLIC_STEALTH_ENDPOINT}" == "core.example.test:80" ]]
ip link del corelan0

docker() {
  if [[ "${1:-}" == "ps" && "${2:-}" == "-a" ]]; then
    printf '%s\n' wins-core-exit-corex2 wins-core-exit-corex3
    return 0
  fi
  if [[ "${1:-}" == "rm" && "${2:-}" == "-f" ]]; then
    printf '%s\n' "${3:-}" >> "${docker_log}"
    return 0
  fi
  return 1
}

for iface in corex2 corex3; do
  ip link add "${iface}" type dummy
  ip link set "${iface}" up
done
ip route replace default dev corex2 table 52002
ip route replace default dev corex3 table 52003
ip rule add from 10.9.0.2/32 table 52002 priority 11002
ip rule add from 10.9.0.3/32 table 52003 priority 11003
# A stale client can share a route table and priority with an active sibling.
# Cleanup must remove only the stale source, never every rule at that priority.
ip rule add from 10.9.0.4/32 table 52003 priority 11003
cat > "${state_dir}/corex2.conf" <<'CFG'
PostUp = ip route replace default dev corex2 table 52002
CFG
  cat > "${state_dir}/corex3.conf" <<'CFG'
PostUp = ip route replace default dev corex3 table 52003
CFG
  printf '1\n' > "${state_dir}/corex2.recovery"
  printf '1\n' > "${state_dir}/corex3.recovery"

remove_stale_assignment_state

if ip link show corex2 >/dev/null 2>&1; then false; fi
ip link show corex3 >/dev/null
[[ -z "$(ip route show table 52002 2>/dev/null)" ]]
grep -q 'default dev corex3' <<<"$(ip route show table 52003)"
if grep -q '^11002:' <<<"$(ip rule show)"; then false; fi
grep -Eq '^11003:.*from 10\.9\.0\.3 .*lookup 52003' <<<"$(ip rule show)"
if grep -Eq '^11003:.*from 10\.9\.0\.4 .*lookup 52003' <<<"$(ip rule show)"; then false; fi
  [[ ! -e "${state_dir}/corex2.conf" ]]
  [[ ! -e "${state_dir}/corex2.recovery" ]]
  [[ -e "${state_dir}/corex3.conf" ]]
  [[ -e "${state_dir}/corex3.recovery" ]]
grep -qxF wins-core-exit-corex2 "${docker_log}"
if grep -qxF wins-core-exit-corex3 "${docker_log}"; then false; fi
EOF
  chmod 700 "${wrapper}"
  : > "${docker_log}"
  unshare -n bash "${wrapper}" "${agent}" "${state_dir}" "${docker_log}"
  echo "PASS core stale exit, route-table, and client-rule cleanup"
}

test_core_stale_stealth_recovery() {
  local agent="${work_dir}/wins-core-sync-recovery"
  local wrapper="${work_dir}/core-recovery-selftest.sh"
  local state_dir="${work_dir}/core-recovery-state"
  local event_file="${work_dir}/core-recovery-events.log"
  extract_heredoc "${CORE_SCRIPT}" 'cat > "${sync_tmp}" <<'\''EOF'\''' EOF > "${agent}"
  chmod 700 "${agent}"
  mkdir -p "${state_dir}"
  # ea4817b: exit configs carry a fail-closed unreachable route (metric 1024)
  # beneath the interface default route (metric 100).
  cat > "${state_dir}/corex3.conf" <<'CFG'
PostUp = ip route replace unreachable default metric 1024 table 52003 2>/dev/null || true
PostUp = ip route replace default dev corex3 metric 100 table 52003
CFG
  cat > "${wrapper}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
state_dir="$2"
event_file="$3"
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "${agent}")

CORE_SYNC_STATE_DIR="${state_dir}"
CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS=5
CORE_EXIT_HANDSHAKE_MAX_AGE_SECONDS=150
CORE_EXIT_RECOVERY_COOLDOWN_SECONDS=300
real_mktemp="$(command -v mktemp)"
real_chmod="$(command -v chmod)"
real_mv="$(command -v mv)"
fault_mode=""
stamp_write_pending=0
interface_probe_count=0
restarted=0
: > "${event_file}"

printf() {
  if [[ "${fault_mode}" == "stamp_write" && "${stamp_write_pending}" == "1" &&
        "${1:-}" == '%s\n' && "${2:-}" =~ ^[0-9]+$ ]]; then
    stamp_write_pending=0
    return 1
  fi
  builtin printf "$@"
}
mktemp() {
  [[ "${fault_mode}" != "stamp_create" ]] || return 1
  command "${real_mktemp}" "$@"
}
chmod() {
  [[ "${fault_mode}" != "stamp_permissions" ]] || return 1
  command "${real_chmod}" "$@"
}
mv() {
  [[ "${fault_mode}" != "stamp_install" ]] || return 1
  command "${real_mv}" "$@"
}
sleep() {
  return 0
}
systemctl() {
  printf 'systemctl:%s\n' "$*" >> "${event_file}"
  if [[ "${1:-}" == "restart" && "${fault_mode}" == "xray_restart" ]]; then
    return 1
  fi
  if [[ "${1:-}" == "is-active" && "${fault_mode}" == "xray_inactive" ]]; then
    return 1
  fi
  return 0
}
docker() {
  if [[ "${1:-}" == "ps" ]]; then
    printf '%s\n' wins-core-exit-corex3
    return 0
  fi
  if [[ "${1:-}" == "restart" ]]; then
    printf 'docker:%s\n' "$*" >> "${event_file}"
    [[ "${fault_mode}" != "container_restart" ]] || return 1
    restarted=1
    return 0
  fi
  if [[ "${1:-}" == "exec" && "${6:-}" == "latest-handshakes" ]]; then
    if ((restarted == 1)) && [[ "${fault_mode}" != "timeout" ]]; then
      printf 'peer %s\n' "$(date +%s)"
    else
      printf 'peer 0\n'
    fi
    return 0
  fi
  return 1
}
ip() {
  printf 'ip:%s\n' "$*" >> "${event_file}"
  if [[ "$*" == 'link show dev corex3' ]]; then
    interface_probe_count=$((interface_probe_count + 1))
    [[ "${fault_mode}" != "interface_missing" ]] || return 1
    if [[ "${fault_mode}" == "delayed_interface" && "${interface_probe_count}" -lt 3 ]]; then
      return 1
    fi
    return 0
  fi
  if [[ "${1:-}" == "route" && "${fault_mode}" == "route_restore" ]]; then
    return 1
  fi
  return 0
}

expect_failure_class() {
  local mode="$1" expected="$2" state_mode="${3:-stealth}"
  local error_file="${state_dir}/recovery-error.log"
  rm -f -- "${state_dir}/corex3.recovery" "${error_file}"
  fault_mode="${mode}"
  stamp_write_pending=1
  interface_probe_count=0
  restarted=0
  : > "${event_file}"
  if recover_stale_exit_handshake corex3 wins-core-exit-corex3 "${state_mode}" \
      >/dev/null 2>"${error_file}"; then
    echo "Core stale-exit recovery unexpectedly succeeded for ${mode}." >&2
    exit 1
  fi
  grep -qxF "[CORE-SYNC][WARN] Core handshake recovery failed class=${expected}" "${error_file}"
  fault_mode=""
}

expect_delayed_interface_recovery() {
  local error_file="${state_dir}/recovery-error.log"
  rm -f -- "${state_dir}/corex3.recovery" "${error_file}"
  fault_mode="delayed_interface"
  stamp_write_pending=1
  interface_probe_count=0
  restarted=0
  : > "${event_file}"
  recover_stale_exit_handshake corex3 wins-core-exit-corex3 stealth \
    >/dev/null 2>"${error_file}"
  [[ "${interface_probe_count}" == "3" ]]
  grep -qxF 'ip:route replace unreachable default metric 1024 table 52003' "${event_file}"
  grep -qxF 'ip:route replace default dev corex3 metric 100 table 52003' "${event_file}"
  [[ ! -s "${error_file}" ]]
  fault_mode=""
}

recover_stale_exit_handshake corex3 wins-core-exit-corex3 stealth
mapfile -t events < "${event_file}"
[[ "${events[0]}" == 'systemctl:restart wins-core-xray-exit@corex3.service' ]]
[[ "${events[1]}" == 'systemctl:is-active --quiet wins-core-xray-exit@corex3.service' ]]
[[ "${events[2]}" == 'docker:restart wins-core-exit-corex3' ]]
[[ "${events[3]}" == 'ip:link show dev corex3' ]]
# ea4817b: the unreachable fallback is installed before the interface route so
# the client table never falls through to table main while the exit cycles.
[[ "${events[4]}" == 'ip:route replace unreachable default metric 1024 table 52003' ]]
[[ "${events[5]}" == 'ip:route replace default dev corex3 metric 100 table 52003' ]]
[[ -s "${state_dir}/corex3.recovery" ]]

event_count="${#events[@]}"
if recover_stale_exit_handshake corex3 wins-core-exit-corex3 stealth \
    >/dev/null 2>"${state_dir}/recovery-error.log"; then
  echo 'Core stale-exit recovery ignored its persisted cooldown.' >&2
  exit 1
fi
grep -qxF '[CORE-SYNC][WARN] Core handshake recovery failed class=exit_handshake_recovery_cooldown' \
  "${state_dir}/recovery-error.log"
[[ "$(wc -l < "${event_file}")" -eq "${event_count}" ]]

expect_failure_class direct_transport exit_handshake_recovery_non_stealth direct
expect_failure_class stamp_create exit_handshake_recovery_stamp_create_failed
expect_failure_class stamp_write exit_handshake_recovery_stamp_write_failed
expect_failure_class stamp_permissions exit_handshake_recovery_stamp_permissions_failed
expect_failure_class stamp_install exit_handshake_recovery_stamp_install_failed
expect_failure_class xray_restart exit_handshake_recovery_xray_restart_failed
expect_failure_class xray_inactive exit_handshake_recovery_xray_inactive
expect_failure_class container_restart exit_handshake_recovery_container_restart_failed
expect_delayed_interface_recovery
expect_failure_class interface_missing exit_handshake_recovery_interface_missing_after_restart
if grep -Fq 'ip:route replace ' "${event_file}"; then false; fi

command "${real_mv}" "${state_dir}/corex3.conf" "${state_dir}/corex3.conf.saved"
expect_failure_class route_metadata exit_handshake_recovery_route_metadata_invalid
command "${real_mv}" "${state_dir}/corex3.conf.saved" "${state_dir}/corex3.conf"

expect_failure_class route_restore exit_handshake_recovery_route_restore_failed
expect_failure_class timeout exit_handshake_recovery_timeout
EOF
  chmod 700 "${wrapper}"
  bash "${wrapper}" "${agent}" "${state_dir}" "${event_file}"
  echo "PASS core stale stealth recovery order and exact fail-closed diagnostics"
}

test_core_exit_handshake_guard() {
  local state_dir="${work_dir}/core-exit-handshake"
  local stale_log="${work_dir}/core-exit-handshake-stale.log"
  local key_log="${work_dir}/core-exit-handshake-key.log"
  mkdir -p "${state_dir}"
  : > "${state_dir}/corex3.conf"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CORE_SCRIPT}")
    CORE_SYNC_STATE_DIR="${state_dir}"
    CORE_EXIT_IFACE_PREFIX=corex
    CORE_EXIT_PUBLIC_KEY=test-exit-public
    CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS=5
    CORE_EXIT_HANDSHAKE_MAX_AGE_SECONDS=90
    docker_mode=fresh

    docker() {
      if [[ "${1:-}" == "inspect" ]]; then
        printf '%s\n' true
        return 0
      fi
      if [[ "${1:-}" == "exec" && "${6:-}" == "public-key" ]]; then
        if [[ "${docker_mode}" == "wrong-key" ]]; then
          printf '%s\n' wrong-exit-public
        else
          printf '%s\n' test-exit-public
        fi
        return 0
      fi
      if [[ "${1:-}" == "exec" && "${6:-}" == "latest-handshakes" ]]; then
        if [[ "${docker_mode}" == "fresh" ]]; then
          printf 'peer %s\n' "$(( $(date +%s) - 1 ))"
        else
          printf '%s\n' 'peer 0'
        fi
        return 0
      fi
      return 1
    }

    validate_core_exit_runtime
    docker_mode=stale
    if validate_core_exit_runtime >"${stale_log}" 2>&1; then
      err 'Core exit guard accepted an interface without a handshake.'
      exit 1
    fi
    grep -Fq 'Double VPN exit handshake did not become healthy: corex3.' "${stale_log}"
    docker_mode=wrong-key
    if validate_core_exit_runtime >"${key_log}" 2>&1; then
      err 'Core exit guard accepted a mismatched runtime public key.'
      exit 1
    fi
    grep -Fq 'does not use the persisted Core exit key' "${key_log}"
  )
  echo "PASS core exit runtime key and fresh-handshake fail-closed guard"
}

test_core_readiness_registration_order() {
  local agent="${work_dir}/wins-core-sync-readiness"
  local wrapper="${work_dir}/core-readiness-selftest.sh"
  extract_heredoc "${CORE_SCRIPT}" 'cat > "${sync_tmp}" <<'\''EOF'\''' EOF > "${agent}"
  chmod 700 "${agent}"
  cat > "${wrapper}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "${agent}")

sync_result=0
runtime_result=0
management_result=0
authority_result=0
event_file="$(mktemp)"
trap 'rm -f "${event_file}"' EXIT
require_ready() { :; }
register_core() { printf 'register:%s,' "${1}" >> "${event_file}"; }
acknowledge_assignments() { printf 'acknowledge,' >> "${event_file}"; }
curl() { printf '%s\n' '{"ok":true,"assignments":[{"iface":"corex1"}]}'; }
verify_management_runtime() { printf 'management,' >> "${event_file}"; ((management_result == 0)); }
sync_assignment() { ((sync_result == 0)); }
remove_stale_ingress_peers() { :; }
remove_stale_assignment_state() { :; }
validate_synced_runtime() {
  printf 'validate,' >> "${event_file}"
  ((runtime_result == 0))
}
# The agent now publishes per-client packet authority after runtime validation
# and before acknowledging or advertising readiness.
publish_core_authority_rules() {
  printf 'authority,' >> "${event_file}"
  ((authority_result == 0))
}

: > "${event_file}"
sync_result=0
runtime_result=0
management_result=0
(main)
[[ "$(<"${event_file}")" == "management,validate,authority,acknowledge,register:true," ]]

: > "${event_file}"
authority_result=1
if (main); then
  echo "authority publication failure unexpectedly advertised the Core ready" >&2
  exit 1
fi
[[ "$(<"${event_file}")" == "management,validate,authority,register:false," ]]
authority_result=0

: > "${event_file}"
sync_result=1
runtime_result=0
management_result=0
if (main); then
  echo "assignment failure unexpectedly advertised the Core ready" >&2
  exit 1
fi
[[ "$(<"${event_file}")" == "management,register:false," ]]

: > "${event_file}"
sync_result=0
runtime_result=1
management_result=0
if (main); then
  echo "runtime validation failure unexpectedly advertised the Core ready" >&2
  exit 1
fi
[[ "$(<"${event_file}")" == "management,validate,register:false," ]]

: > "${event_file}"
sync_result=0
runtime_result=0
management_result=1
if (main); then
  echo "management failure unexpectedly advertised the Core ready" >&2
  exit 1
fi
[[ "$(<"${event_file}")" == "management,register:false," ]]
EOF
  chmod 700 "${wrapper}"
  # main() installs policy routes (table 5299 blackhole, rule 32765) before
  # require_ready; keep them in a private network namespace.
  unshare -n bash "${wrapper}" "${agent}"
  echo "PASS core readiness registration is ordered and fail-closed"
}

test_core_assignment_ack_contract() {
  local agent="${work_dir}/wins-core-sync-assignment-ack"
  local sourced_agent="${work_dir}/wins-core-sync-assignment-ack-sourced"
  local wrapper="${work_dir}/core-assignment-ack-selftest.sh"
  extract_heredoc "${CORE_SCRIPT}" 'cat > "${sync_tmp}" <<'\''EOF'\''' EOF > "${agent}"
  sed '/^main "\$@"$/d' "${agent}" > "${sourced_agent}"
  chmod 700 "${agent}"
  cat > "${wrapper}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
agent="$1"
# shellcheck disable=SC1090
source "${agent}"

payload_file="$(mktemp)"
ack_log="$(mktemp)"
advertised_state_dir="$(mktemp -d)"
trap 'rm -f "${payload_file}" "${ack_log}"; rm -rf "${advertised_state_dir}"' EXIT
CORE_ADVERTISED_STATE_FILE="${advertised_state_dir}/promoted-state.json"
CORE_ADVERTISED_STATE_LOCK="${advertised_state_dir}/promoted-state.lock"
hub_curl() {
  # Like the real curl the agent calls, the body arrives on stdin through
  # --data-binary @- (IA-CORE-10, CORE-B). A body on argv is refused.
  local previous="" arg payload="" endpoint="" runtime_ready stdin_body=0
  for arg in "$@"; do
    case "${previous}" in
      --data-binary|-d|--data|--data-raw|--data-ascii|--data-urlencode|--json)
        [[ "${previous}" == --data-binary && "${arg}" == "@-" ]] || {
          echo "hub_curl stub: request body passed on argv (${previous})" >&2
          return 1
        }
        stdin_body=1
        ;;
    esac
    [[ "${arg}" == http* ]] && endpoint="${arg}"
    previous="${arg}"
  done
  ((stdin_body == 1)) || return 1
  payload="$(cat)"
  [[ -n "${payload}" ]] || return 1
  if [[ "${endpoint}" == */api/v1/core/assignments/ack ]]; then
    jq -r '.acknowledgements | length' <<<"${payload}" >> "${ack_log}"
    jq -cn --argjson count "$(jq '.acknowledgements | length' <<<"${payload}")" \
      '{ok:true,acknowledged_assignment_count:$count}'
  else
    printf '%s\n' "${payload}" > "${payload_file}"
    runtime_ready="$(jq -r '.runtime_ready' <<<"${payload}")"
    jq -cn --arg core_id "${CORE_ID}" --argjson runtime_ready "${runtime_ready}" \
      '{ok:true,core_id:$core_id,runtime_ready:$runtime_ready,promoted:false,pending_promotion_id:"",active_promotion_id:""}'
  fi
}

CORE_INGRESS_PUBLIC_KEY='ingress-public-key'
CORE_EXIT_PUBLIC_KEY='exit-public-key'
CORE_EXIT_PRIVATE_KEY='exit-private-key'
CORE_PUBLIC_INGRESS_ENDPOINT='core.example:9210'
CORE_PUBLIC_STEALTH_ENDPOINT='core.example:80'
CORE_REGIONAL_ALIASES='alias-b.example,alias-a.example,alias-a.example'
CORE_DIRECT_AWG_ENABLED=0
revision="$(printf 'a%.0s' {1..64})"
ASSIGNMENTS_JSON="$(jq -cn --arg revision "${revision}" '{ok:true,assignments:[{device_id:"device-1",assignment_revision:$revision}]}')"
acknowledge_assignments
register_core true
jq -e --arg revision "${revision}" '
  .runtime_ready == true and
  .direct_awg_enabled == false and
  .regional_aliases == ["alias-a.example", "alias-b.example"] and
  .applied_assignment_revisions == []
' "${payload_file}" >/dev/null
[[ "$(<"${ack_log}")" == "1" ]]

ASSIGNMENTS_JSON='{"ok":true,"assignments":[{"device_id":"device-1"}]}'
if acknowledge_assignments >/dev/null 2>&1; then
  echo "assignment acknowledgement accepted a missing revision" >&2
  exit 1
fi
register_core false
jq -e '.runtime_ready == false and .applied_assignment_revisions == []' "${payload_file}" >/dev/null

# Readiness acknowledgements are request-bounded, not capacity-bounded. A Core
# with more than 4096 active assignments must complete multiple 512-item calls.
: > "${ack_log}"
ASSIGNMENTS_JSON="$(jq -cn --arg revision "${revision}" '
  {ok:true,assignments:[range(0;4097) | {device_id:("device-" + tostring),assignment_revision:$revision}]}
')"
acknowledge_assignments
[[ "$(wc -l < "${ack_log}" | tr -d '[:space:]')" == "9" ]]
[[ "$(awk '{sum += $1} END {print sum + 0}' "${ack_log}")" == "4097" ]]
[[ "$(tail -n 1 "${ack_log}")" == "1" ]]

client_pub='client-public-key'
client_ip='10.9.1.9'
stub_runtime_client_pub='client-public-key'
stub_runtime_client_ip='10.9.1.9'
stub_runtime_psk='(none)'
runtime_rule_ok=1
runtime_route_ok=1
table_id=52003
iface='corex3'
docker() {
  printf 'private\tpublic\t9210\t0\n'
  printf '%s\t%s\t(none)\t%s/32\t0\t0\t0\t0\n' "${stub_runtime_client_pub}" "${stub_runtime_psk}" "${stub_runtime_client_ip}"
  # Keep enough incumbent rows after the requested peer to reproduce the
  # pipefail/SIGPIPE false-negative caused by an early-exiting consumer.
  local index
  for index in $(seq 1 512); do
    printf 'incumbent-%04d\t(none)\t(none)\t10.9.2.%d/32\t0\t0\t0\t0\n' \
      "${index}" "$((index % 250 + 1))"
  done
}
ip() {
  if [[ "$#" -eq 5 && "$1" == "-4" && "$2" == "rule" && "$3" == "show" \
      && "$4" == "priority" && "$5" == "11003" ]]; then
    ((runtime_rule_ok == 1)) || return 0
    printf '11003: from %s lookup %s\n' "${stub_runtime_client_ip}" "${table_id}"
    return 0
  fi
  if [[ "$#" -eq 6 && "$1" == "-4" && "$2" == "route" && "$3" == "show" \
      && "$4" == "table" && "$5" == "52003" && "$6" == "default" ]]; then
    ((runtime_route_ok == 1)) || return 0
    printf 'default dev %s scope link\n' "${iface}"
    return 0
  fi
  return 1
}
item="$(jq -cn --arg pub "${client_pub}" --arg ip "${client_ip}" --arg iface "${iface}" --arg revision "${revision}" --argjson table "${table_id}" '{client_public_key:$pub,client_ip:$ip,preshared_key:"",table_id:$table,iface:$iface,assignment_revision:$revision}')"
validate_assignment_runtime "${item}"

assert_runtime_failure_class() {
  local expected_class="$1" candidate="$2" log_file
  log_file="$(mktemp)"
  if validate_assignment_runtime "${candidate}" >/dev/null 2>"${log_file}"; then
    echo "runtime validation accepted failure class=${expected_class}" >&2
    rm -f -- "${log_file}"
    exit 1
  fi
  grep -Fq "Core runtime validation failed class=${expected_class}" "${log_file}"
  if grep -Fq -e 'client-public-key' -e '10.9.1.9' -e '10.9.1.10' \
      -e 'expected-secret-do-not-log' -e 'runtime-secret-do-not-log' "${log_file}"; then
    echo "runtime validation diagnostic leaked assignment material" >&2
    rm -f -- "${log_file}"
    exit 1
  fi
  rm -f -- "${log_file}"
}

assert_runtime_failure_class assignment_revision_invalid \
  "$(jq '.assignment_revision=""' <<<"${item}")"

stub_runtime_client_pub='different-client-public-key'
assert_runtime_failure_class ingress_peer_missing "${item}"
stub_runtime_client_pub='client-public-key'

stub_runtime_client_ip='10.9.1.10'
assert_runtime_failure_class ingress_allowed_ip_mismatch "${item}"
stub_runtime_client_ip='10.9.1.9'

stub_runtime_psk='runtime-secret-do-not-log'
assert_runtime_failure_class ingress_psk_mismatch \
  "$(jq '.preshared_key="expected-secret-do-not-log"' <<<"${item}")"
stub_runtime_psk='(none)'

runtime_rule_ok=0
assert_runtime_failure_class client_policy_rule_mismatch "${item}"
runtime_rule_ok=1

runtime_route_ok=0
assert_runtime_failure_class exit_default_route_mismatch "${item}"
runtime_route_ok=1
EOF
  chmod 700 "${wrapper}"
  bash "${wrapper}" "${sourced_agent}"
  echo "PASS revision-bound Core assignment acknowledgement and runtime validation"
}

test_control_availability_contract() {
  python3 - "${CONTROL_SCRIPT}" "${CORE_SCRIPT}" "${ROOT_DIR}/lib/main.dart" <<'PYEOF'
import ast
import hashlib
import hmac
import json
import os
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
core = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
client = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
required = (
    'NODE_HEARTBEAT_STALE_SECONDS_DEFAULT="${NODE_HEARTBEAT_STALE_SECONDS:-600}"',
    'DOUBLE_VPN_CORE_STALE_SECONDS_DEFAULT="${DOUBLE_VPN_CORE_STALE_SECONDS:-180}"',
    'DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS_DEFAULT="${DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS:-5}"',
    "last_heartbeat IS NOT NULL AND last_heartbeat >= ?",
    "runtime_ready INTEGER NOT NULL DEFAULT 0",
    "applied_revision TEXT",
    "runtime_validated_at TEXT",
    "AND runtime_ready = 1",
    "AND management_status = 'ok'",
    "management_checked_at IS NOT NULL AND management_checked_at >= ?",
    "runtime_checked_at IS NOT NULL AND runtime_checked_at >= ?",
    'runtime_ready: bool = Field(default=False',
    "AND EXISTS (",
    "n.management_status = 'ok'",
    'core["tunnel_gateway_ipv4"]',
    "AND tunnel_gateway_ipv4 IS NOT NULL AND tunnel_gateway_ipv4 != ''",
    'detail="Double VPN core is missing a valid tunnel gateway registration."',
    'detail="Selected VPN route is missing a valid tunnel gateway registration."',
    "def mark_stale_nodes_offline(conn: sqlite3.Connection) -> None:",
    "async def wait_for_core_assignment_ready(",
    'current_assignment["assignment_revision"], expected_revision',
    "hmac.compare_digest(row[\"applied_revision\"] or \"\", expected_revision)",
    # d20b5db: the verify path runs in a worker thread, so the readiness wait
    # is a synchronous poll there; the async wrapper offloads the same poll.
    "time.sleep(min(0.5, remaining))",
    "conn.commit()",
    "if not _wait_for_core_assignment_ready_sync(",
    "return await asyncio.to_thread(\n        _wait_for_core_assignment_ready_sync,",
    "return await asyncio.to_thread(\n        _verify_account_sync,",
    'detail="Double VPN Core assignment is still being prepared. Please try again."',
    '"X-Wins-Error-Code": "double_vpn_assignment_preparing"',
    '"Retry-After": "5"',
    'applied_assignment_revisions: list[dict[str, str]]',
    "def apply_core_registration_runtime_state(",
    "runtime_ready = bool(payload.runtime_ready)",
    "acknowledged_count = apply_core_registration_runtime_state(",
    '@app.post("/api/v1/core/assignments/ack")',
    'payload.acknowledgements, maximum=1024',
    'detail="Core assignment revision changed; resynchronize."',
    '"acknowledged_assignment_count": acknowledged_count',
)
missing = [needle for needle in required if needle not in source]
if missing:
    raise SystemExit(f"control availability contract missing: {missing}")
# The blocking poll must stay off the event loop: it may only live in the
# synchronous helper, which runs from _verify_account_sync (a to_thread worker).
ready_sync_at = source.index("def _wait_for_core_assignment_ready_sync(")
ready_sync_body = source[ready_sync_at:source.index("\ndef ", ready_sync_at + 1)]
if "time.sleep(min(0.5, remaining))" not in ready_sync_body or "await " in ready_sync_body:
    raise SystemExit("Core assignment readiness poll is not a synchronous worker-thread helper")
verify_sync_at = source.index("\ndef _verify_account_sync(")
ready_call_at = source.index("if not _wait_for_core_assignment_ready_sync(")
if not verify_sync_at < ready_call_at < source.index("\ndef ", verify_sync_at + 1):
    raise SystemExit("Core assignment readiness poll is called outside the worker-thread verify path")
if "core.get(" in source:
    raise SystemExit("Double VPN verify path calls dict.get on sqlite3.Row")
core_required = (
    '--argjson runtime_ready "${runtime_ready}"',
    '--argjson applied_assignment_revisions "${applied_revisions_json}"',
    'acknowledge_assignments()',
    '/api/v1/core/assignments/ack',
    'CORE_SYNC_FAILURE_STAGE="assignment-acknowledgement"',
    'validate_assignment_runtime()',
    '[[ "${revision}" =~ ^[0-9a-f]{64}$ ]]',
    'preshared-key /dev/null',
    'OnUnitActiveSec=1s',
    'AccuracySec=100ms',
    'CORE_INGRESS_ADDR="${CORE_INGRESS_ADDR:-10.9.1.1/16}"',
    'CORE_SYNC_FAILURE_STAGE="prerequisites"',
    'warn "Core sync failed during stage=${CORE_SYNC_FAILURE_STAGE}"',
    'CORE_SYNC_FAILURE_STAGE="ready-registration"',
    'verify_management_runtime',
    'validate_synced_runtime',
    'register_core true',
    'trap - EXIT',
    # Per-assignment failure isolation (S-1): a parseable failed assignment is
    # withheld from authority on its own; an unparseable one still keeps the
    # whole Core unavailable, and partial authority never registers ready.
    'withholding authority for that assignment only',
    'Core remains unavailable because an assignment with an unparseable identity could not be synchronized',
    'Core published partial authority;',
)
core_missing = [needle for needle in core_required if needle not in core]
if core_missing:
    raise SystemExit(f"core runtime-readiness contract missing: {core_missing}")
timeout_match = re.search(
    r'DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS_DEFAULT="\$\{DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS:-([0-9]+)\}"',
    source,
)
if not timeout_match or int(timeout_match.group(1)) > 6:
    raise SystemExit("Core assignment readiness wait can exceed the client HTTP timeout")
# The client's Double VPN assignment request is the call the hub's readiness
# wait must fit inside; its bound is pollDoubleVpnAssignment's requestTimeout.
client_poll_at = client.find("await pollDoubleVpnAssignment<")
client_poll = re.search(
    r"requestTimeout: const Duration\(seconds: ([0-9]+)\),",
    client[client_poll_at:client_poll_at + 600] if client_poll_at >= 0 else "",
)
if (
    ".timeout(const Duration(seconds: 8))" not in client
    or client_poll is None
    or int(client_poll.group(1)) <= int(timeout_match.group(1))
    or int(client_poll.group(1)) > 8
):
    raise SystemExit("Expected activation/config client timeout contract changed")
# The hub's own fallback, used when its env file lacks the key, must be the
# installer's default too (OI-E2E-9, N-6). Evaluate the hub's statement with
# the key absent rather than matching its text.
requested_defaults = []

class _EnvKeyAbsent:
    @staticmethod
    def getenv(_key, default=None):
        requested_defaults.append(default)
        return default

def _env_with(name, value):
    class _Env:
        @staticmethod
        def getenv(key, default=None):
            return value if key == name else default
    return _Env

def hub_fallback(name, explicit=None):
    anchor = f"\n{name} = "
    if source.count(anchor) != 1:
        raise SystemExit(f"hub assignment of {name} not found exactly once")
    start = source.index(anchor) + 1
    end = source.index("\n", start)
    while True:
        try:
            statement = ast.parse(source[start:end])
            break
        except SyntaxError:
            end = source.index("\n", end + 1)
    namespace = {"os": _EnvKeyAbsent if explicit is None else _env_with(name, explicit)}
    exec(compile(statement, name, "exec"), namespace)
    return namespace[name]

class _LogCapture:
    def __init__(self):
        self.warnings = []

    def getLogger(self, _name):
        return self

    def warning(self, message, *args):
        self.warnings.append(message % args if args else message)

class _EnvQuiet:
    @staticmethod
    def getenv(_key, default=None):
        return default

def hub_ready_wait_run(explicit):
    """Run the hub's readiness-wait assignment, plus the `if` that logs a clamp
    when one follows it, with the key set to `explicit` (absent for None).
    Returns (value, warnings logged)."""
    name = "DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS"
    anchor = f"\n{name} = "
    if source.count(anchor) != 1:
        raise SystemExit(f"hub assignment of {name} not found exactly once")
    lines = source[source.index(anchor) + 1:].split("\n")
    block, at = [], 0
    while True:
        block.append(lines[at])
        at += 1
        try:
            ast.parse("\n".join(block))
            break
        except SyntaxError:
            continue
    if lines[at].startswith("if ") and name in lines[at]:
        block.append(lines[at])
        at += 1
        while lines[at].startswith((" ", ")")):
            block.append(lines[at])
            at += 1
    log = _LogCapture()
    namespace = {"os": _EnvQuiet if explicit is None else _env_with(name, explicit), "logging": log}
    exec(compile("\n".join(block), name, "exec"), namespace)
    return namespace[name], log.warnings

requested_defaults.clear()
hub_ready_wait = hub_fallback("DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS")
# The literal default itself must be the installer's, not one the clamp hides.
if requested_defaults != [timeout_match.group(1)]:
    raise SystemExit(f"hub readiness-wait fallback literal {requested_defaults} is not the installer default {timeout_match.group(1)}")
if hub_ready_wait != int(timeout_match.group(1)) or hub_ready_wait >= int(client_poll.group(1)):
    raise SystemExit(
        f"hub fallback readiness wait {hub_ready_wait}s differs from the installer default "
        f"{timeout_match.group(1)}s or does not fit the client's {client_poll.group(1)}s request timeout"
    )
stale_match = re.search(
    r'NODE_HEARTBEAT_STALE_SECONDS_DEFAULT="\$\{NODE_HEARTBEAT_STALE_SECONDS:-([0-9]+)\}"',
    source,
)
hub_stale = hub_fallback("NODE_HEARTBEAT_STALE_SECONDS")
if not stale_match or hub_stale != int(stale_match.group(1)):
    raise SystemExit(
        f"hub fallback node heartbeat staleness {hub_stale}s differs from the installer default"
    )
# Round 3 (OI-E2E-13): an explicit readiness wait is bounded too. The installer
# refuses anything outside 1..MAX, the hub clamps to the same MAX, and MAX
# leaves the client's request timeout a margin for the work outside the wait.
client_timeout = int(client_poll.group(1))
max_match = re.search(r"^DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_MAX_SECONDS=([0-9]+)$", source, re.M)
if not max_match or source.count("\nDOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_MAX_SECONDS=") != 1:
    raise SystemExit("installer readiness-wait bound DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_MAX_SECONDS not found exactly once")
ready_max = int(max_match.group(1))
if not int(timeout_match.group(1)) <= ready_max <= client_timeout - 2:
    raise SystemExit(f"readiness-wait bound {ready_max}s leaves less than 2 s of the client's {client_timeout}s timeout")
for explicit in ("6", "7", "30", "3600"):
    clamped, warned = hub_ready_wait_run(explicit)
    if clamped != ready_max:
        raise SystemExit(f"hub runs an explicit readiness wait of {explicit}s as {clamped}s, not the {ready_max}s bound")
    if len(warned) != 1 or explicit not in warned[0] or str(ready_max) not in warned[0]:
        raise SystemExit(f"hub did not log exactly one clamp warning for an explicit readiness wait of {explicit}s: {warned}")
for explicit in (None, "1", "5"):
    value, warned = hub_ready_wait_run(explicit)
    if value != (int(timeout_match.group(1)) if explicit is None else int(explicit)):
        raise SystemExit(f"hub changed an in-range readiness wait of {explicit}s to {value}s")
    if warned:
        raise SystemExit(f"hub logged a clamp warning for an in-range readiness wait of {explicit}s: {warned}")
validator_at = source.index("\nvalidate_double_vpn_ready_timeout() {\n") + 1
validator_fn = source[validator_at:source.index("\n}\n", validator_at) + 3]
preflight_at = source.index("\npreflight_control() {\n")
preflight_body = source[preflight_at:source.index("\n}\n", preflight_at)]
if "\n  validate_double_vpn_ready_timeout || exit 1\n" not in preflight_body:
    raise SystemExit("preflight_control does not refuse an out-of-range readiness wait")
import subprocess
# 18446744073709551617 is 2**64 + 1: bash arithmetic wraps it to 1, so only the
# digit-count cap in the validator refuses it.
for value, want in (("1", 0), ("5", 0), ("0", 1), ("6", 1), ("7", 1), ("30", 1), ("05", 1), ("5s", 1),
                    ("18446744073709551617", 1)):
    run = subprocess.run(
        ["bash", "-c", 'set -u; err() { printf "%s\\n" "$*" >&2; }; '
         f"DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_MAX_SECONDS={ready_max}; "
         'DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS_DEFAULT="$1"; eval "$2"; validate_double_vpn_ready_timeout',
         "_", value, validator_fn],
        capture_output=True, text=True,
    )
    if (run.returncode != 0) != bool(want) or (want and "DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS must be" not in run.stderr):
        raise SystemExit(f"installer readiness-wait check gave rc={run.returncode} for {value!r}: {run.stderr.strip()}")

revision_source = source[
    source.index("CORE_ASSIGNMENT_REVISION_FIELDS = ("):
    source.index("async def wait_for_core_assignment_ready(")
]
revision_namespace = {
    "Any": object,
    "sqlite3": sqlite3,
    "json": json,
    "hmac": hmac,
    "hashlib": hashlib,
    "RATE_LIMIT_SECRET": "unit-test-revision-secret",
    "MANAGEMENT_NAME_HMAC_KEY": "unit-test-revision-secret",
    "ADMIN_SECRET_TOKEN": "fallback-secret",
}
exec(revision_source, revision_namespace)
fields = revision_namespace["CORE_ASSIGNMENT_REVISION_FIELDS"]
base_assignment = {field: f"value-{field}" for field in fields}
base_assignment.update({
    "table_id": 52003,
    "exit_wg_port": 9110,
    "exit_xray_transports": [{"port": 80, "security": "none"}],
    "exit_direct_awg_enabled": True,
})
revision = revision_namespace["core_assignment_revision"]
first = revision(base_assignment)
if not re.fullmatch(r"[0-9a-f]{64}", first):
    raise SystemExit("Core assignment revision is not a bounded HMAC digest")
cosmetic = dict(base_assignment, updated_at="later", exit_name="renamed")
if revision(cosmetic) != first:
    raise SystemExit("Cosmetic assignment metadata invalidated the runtime revision")
changed = dict(base_assignment, exit_endpoint="replacement.example:9110")
if revision(changed) == first:
    raise SystemExit("Runtime assignment change did not invalidate the revision")

app_marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'\n'
app_source = source.split(app_marker, 1)[1].split("\nPYEOF\n", 1)[0]
tree = ast.parse(app_source)

def http_exception_keywords(detail):
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "HTTPException":
            continue
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        detail_node = keywords.get("detail")
        if isinstance(detail_node, ast.Constant) and detail_node.value == detail:
            matches.append(keywords)
    return matches

preparing_exceptions = http_exception_keywords(
    "Double VPN Core assignment is still being prepared. Please try again."
)
if len(preparing_exceptions) != 1:
    raise SystemExit("assignment preparation must have one stable 503 response")
headers_node = preparing_exceptions[0].get("headers")
if not isinstance(headers_node, ast.Dict):
    raise SystemExit("assignment preparation response is missing retry signaling headers")
headers = {
    key.value: value.value
    for key, value in zip(headers_node.keys, headers_node.values)
    if isinstance(key, ast.Constant) and isinstance(value, ast.Constant)
}
if headers != {
    "X-Wins-Error-Code": "double_vpn_assignment_preparing",
    "Retry-After": "5",
}:
    raise SystemExit(f"assignment preparation retry headers changed: {headers}")
general_unavailable = http_exception_keywords("Double VPN core is not available yet.")
if len(general_unavailable) != 1 or "headers" in general_unavailable[0]:
    raise SystemExit("general Core unavailability must not be marked as retryable preparation")

runtime_state_function = next(
    node for node in tree.body
    if isinstance(node, ast.FunctionDef)
    and node.name == "apply_core_registration_runtime_state"
)
runtime_state_module = ast.Module(body=[runtime_state_function], type_ignores=[])
ast.fix_missing_locations(runtime_state_module)

def active_assignment_payloads(conn, core_id):
    return [
        {"device_id": row["device_id"], "assignment_revision": row["expected_revision"]}
        for row in conn.execute(
            "SELECT device_id, expected_revision FROM double_vpn_assignments "
            "WHERE core_id=? AND status='active' ORDER BY device_id",
            (core_id,),
        ).fetchall()
    ]

runtime_state_namespace = {
    "sqlite3": sqlite3,
    "hmac": hmac,
    "active_core_assignment_payloads": active_assignment_payloads,
}
exec(compile(runtime_state_module, sys.argv[1], "exec"), runtime_state_namespace)
apply_runtime_state = runtime_state_namespace["apply_core_registration_runtime_state"]

runtime_conn = sqlite3.connect(":memory:")
runtime_conn.row_factory = sqlite3.Row
runtime_conn.executescript("""
CREATE TABLE core_servers (core_id TEXT PRIMARY KEY, runtime_ready INTEGER NOT NULL);
CREATE TABLE double_vpn_assignments (
  device_id TEXT PRIMARY KEY, core_id TEXT NOT NULL, status TEXT NOT NULL,
  expected_revision TEXT NOT NULL, applied_revision TEXT, runtime_validated_at TEXT
);
INSERT INTO core_servers VALUES ('test-core', 0);
""")
revision_a = "a" * 64
revision_b = "b" * 64
runtime_conn.execute(
    "INSERT INTO double_vpn_assignments VALUES (?,?,?,?,?,?)",
    ("device-a", "test-core", "active", revision_a, None, None),
)
# The Core took its synchronization snapshot with only A. Assignment B then
# arrived before register_core(true), reproducing the stale-snapshot race.
core_snapshot = {"device-a": revision_a}
runtime_conn.execute(
    "INSERT INTO double_vpn_assignments VALUES (?,?,?,?,?,?)",
    ("device-b", "test-core", "active", revision_b, None, None),
)
validated_at = utcnow().isoformat()
count = apply_runtime_state(
    runtime_conn, "test-core", core_snapshot, validated_at, runtime_ready=True
)
if count != 1:
    raise SystemExit("Core snapshot acknowledgement count changed")
if runtime_conn.execute(
    "SELECT runtime_ready FROM core_servers WHERE core_id='test-core'"
).fetchone()[0] != 1:
    raise SystemExit("a post-snapshot assignment incorrectly made the healthy Core unavailable")
ack_rows = {
    row["device_id"]: row
    for row in runtime_conn.execute(
        "SELECT device_id, applied_revision, runtime_validated_at FROM double_vpn_assignments"
    ).fetchall()
}
if ack_rows["device-a"]["applied_revision"] != revision_a or ack_rows["device-a"]["runtime_validated_at"] != validated_at:
    raise SystemExit("the exact snapshot assignment was not freshly acknowledged")
if ack_rows["device-b"]["applied_revision"] is not None or ack_rows["device-b"]["runtime_validated_at"] is not None:
    raise SystemExit("a post-snapshot assignment bypassed its exact acknowledgement gate")

runtime_conn.execute(
    "UPDATE double_vpn_assignments SET applied_revision=NULL, runtime_validated_at=NULL WHERE device_id='device-a'"
)
if apply_runtime_state(
    runtime_conn, "test-core", {"device-a": revision_b}, validated_at, runtime_ready=True
) != 0:
    raise SystemExit("a mismatched assignment revision was acknowledged")
if runtime_conn.execute(
    "SELECT runtime_validated_at FROM double_vpn_assignments WHERE device_id='device-a'"
).fetchone()[0] is not None:
    raise SystemExit("a mismatched assignment revision bypassed freshness validation")

runtime_conn.execute(
    "UPDATE double_vpn_assignments SET runtime_validated_at=?", (validated_at,)
)
apply_runtime_state(runtime_conn, "test-core", {}, validated_at, runtime_ready=False)
if runtime_conn.execute(
    "SELECT runtime_ready FROM core_servers WHERE core_id='test-core'"
).fetchone()[0] != 0:
    raise SystemExit("register_core(false) did not clear global runtime readiness")
if runtime_conn.execute(
    "SELECT COUNT(*) FROM double_vpn_assignments WHERE runtime_validated_at IS NOT NULL"
).fetchone()[0] != 0:
    raise SystemExit("register_core(false) did not clear assignment validation freshness")

double_block = source[
    source.index("if double_vpn_requested and core and double_assignment:", source.index("config_client_ip =")):
    source.index("xray_config = {", source.index("config_client_ip ="))
]
if 'regional_aliases = parse_aliases(core["regional_aliases"] or "[]")' not in double_block:
    raise SystemExit("Double VPN response does not switch to Core first-hop aliases")
if 'config_direct_awg_enabled = bool(' not in double_block or 'core["direct_awg_enabled"]' not in double_block:
    raise SystemExit("Double VPN response does not switch to Core direct-AWG availability")
if '"direct_awg_enabled": config_direct_awg_enabled' not in source:
    raise SystemExit("VPN response bypasses the selected first-hop direct-AWG metadata")
seed = source[
    source.index("if DOUBLE_VPN_CORE_INGRESS_ENDPOINT and DOUBLE_VPN_CORE_INGRESS_PUBLIC_KEY"):
    source.index('conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_account_number')
]
if "last_heartbeat=excluded.last_heartbeat" in seed or "status='online'" in seed:
    raise SystemExit("static Core configuration still fabricates a live runtime heartbeat")

selector_source = source[
    source.index("CORE_SELF_READY_SQL ="):
    source.index("def mark_stale_nodes_offline(")
]
availability_nodes = [
    node for node in tree.body
    if isinstance(node, ast.Assign)
    and any(
        isinstance(target, ast.Name)
        and target.id in {"DATA_PLANE_HARD_STALE_MINUTES", "DATA_PLANE_AVAILABLE_SQL_N"}
        for target in node.targets
    )
]
availability_module = ast.Module(body=availability_nodes, type_ignores=[])
ast.fix_missing_locations(availability_module)
availability_namespace = {"os": os}
exec(compile(availability_module, sys.argv[1], "exec"), availability_namespace)
namespace = {
    "sqlite3": sqlite3,
    "datetime": datetime,
    "timedelta": timedelta,
    "utcnow": utcnow,
    "Optional": Optional,
    "DOUBLE_VPN_ENABLED": True,
    "DOUBLE_VPN_CORE_ID": "test-core",
    "DOUBLE_VPN_CORE_STALE_SECONDS": 180,
    "DATA_PLANE_AVAILABLE_SQL_N": availability_namespace["DATA_PLANE_AVAILABLE_SQL_N"],
}
exec(selector_source, namespace)
conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row
conn.executescript("""
CREATE TABLE core_servers (
  core_id TEXT PRIMARY KEY, status TEXT, runtime_ready INTEGER, promoted INTEGER,
  active_promotion_id TEXT, deployment_withdrawal_id TEXT,
  management_status TEXT, management_checked_at TEXT,
  last_heartbeat TEXT, runtime_checked_at TEXT, ingress_endpoint TEXT,
  ingress_public_key TEXT, exit_public_key TEXT, tunnel_gateway_ipv4 TEXT,
  regional_aliases TEXT, direct_awg_enabled INTEGER
);
CREATE TABLE nodes (
  status TEXT, management_status TEXT, endpoint TEXT, public_key TEXT,
  operator_enabled INTEGER DEFAULT 0, retired_at TEXT,
  data_plane_status TEXT DEFAULT 'unknown', data_plane_ok_at TEXT
);
""")
now = utcnow().isoformat()
conn.execute(
    "INSERT INTO nodes (status,management_status,endpoint,public_key,operator_enabled) "
    "VALUES ('online','ok','node.test:9110','node-key',1)"
)
conn.execute(
    "INSERT INTO core_servers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    (
        "test-core", "online", 0, 0, None, None, "ok", now, now, now,
        "core.test:9210", "ingress-key", "exit-key", "10.255.0.1", "[]", 1,
    ),
)
select_core = namespace["select_double_vpn_core"]
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted runtime_ready=0")
conn.execute("UPDATE core_servers SET runtime_ready=1")
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted a ready but operator-dark Core")
conn.execute("UPDATE core_servers SET promoted=1, active_promotion_id=?", ("a" * 32,))
selected_core = select_core(conn)
if selected_core is None:
    raise SystemExit("Core selector rejected fresh, explicitly ready runtime")
if selected_core["tunnel_gateway_ipv4"] != "10.255.0.1":
    raise SystemExit("Core sqlite3.Row lost its registered tunnel gateway")
conn.execute("UPDATE nodes SET operator_enabled=0")
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted an operator-dark only exit")
conn.execute("UPDATE nodes SET operator_enabled=1, retired_at=?", (now,))
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted a retired only exit")
conn.execute("UPDATE nodes SET retired_at=NULL")
if select_core(conn) is None:
    raise SystemExit("Core selector did not recover after restoring an eligible exit")
conn.execute("UPDATE core_servers SET tunnel_gateway_ipv4='' WHERE core_id='test-core'")
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted a blank tunnel gateway")
conn.execute(
    "UPDATE core_servers SET tunnel_gateway_ipv4='10.255.0.1' WHERE core_id='test-core'"
)
conn.execute("UPDATE core_servers SET management_status='failed'")
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted a failed management path")
conn.execute("UPDATE core_servers SET management_status='ok'")
stale = (utcnow() - timedelta(seconds=181)).isoformat()
conn.execute("UPDATE core_servers SET management_checked_at=?", (stale,))
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted a stale management verification")
conn.execute("UPDATE core_servers SET management_checked_at=?", (now,))
conn.execute("UPDATE core_servers SET runtime_checked_at=?", (stale,))
if select_core(conn) is not None:
    raise SystemExit("Core selector accepted stale runtime validation")
# Node advertisement ends NODE_HEARTBEAT_STALE_SECONDS after heartbeat loss.
# The only 24-hour window the hub may keep is the per-node automatic-reopen
# rate limit, which counts reopen events and never advertises a node.
stale_start = source.index("def mark_stale_nodes_offline(")
stale_expiry = source[stale_start:source.index("\ndef ", stale_start + 1)]
if "utcnow() - timedelta(seconds=NODE_HEARTBEAT_STALE_SECONDS)" not in stale_expiry:
    raise SystemExit("control node expiry is not bound to NODE_HEARTBEAT_STALE_SECONDS")
# Asserted as a property, not a literal: the window must feed a count of
# reopen latch events and the per-day reopen limit. (A literal
# `cause = 'auto_reopen'` broke when the reopen causes became a tuple,
# `cause IN (?, ?)` with NODE_AUTO_REOPEN_CAUSES, in the IA-SYNC merge.)
day_windows = list(re.finditer(r"timedelta\((?:hours=24|days=1)\)", source))
if not day_windows:
    raise SystemExit("no 24-hour window found at all: the automatic-reopen rate limit anchor moved")
for day_window in day_windows:
    after = source[day_window.end():day_window.end() + 600]
    counts_reopens = "SELECT COUNT(*) FROM node_latch_events WHERE slug = ? AND cause " in after and (
        "cause = 'auto_reopen' " in after
        or ("cause IN (" in after and "*NODE_AUTO_REOPEN_CAUSES, day_ago)" in after)
    )
    if not counts_reopens or "if reopened >= NODE_AUTO_REOPEN_MAX_PER_DAY:" not in after:
        raise SystemExit("control still advertises nodes for 24 hours after heartbeat loss")
nodes_handler = source[source.index('@app.get("/nodes")'):source.index('@app.get("/pay/{option_key}")')]
free_handler = source[source.index('@app.get("/free/status")'):source.index('@app.post("/free/verify")')]
for name, handler in (("nodes", nodes_handler), ("free", free_handler)):
    if "mark_stale_nodes_offline(conn)" not in handler:
        raise SystemExit(f"{name} handler does not expire stale nodes")
PYEOF
  echo "PASS heartbeat-bounded node and Double VPN availability contract"
}

test_origin_hiding_contract() {
  python3 - "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${CORE_SCRIPT}" <<'PYEOF'
import pathlib
import sys

control = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
data = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
core = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
required_control = (
    'HIDE_CONTROL_ORIGIN_DEFAULT="${HIDE_CONTROL_ORIGIN:-1}"',
    'record="${gateway_base}"',
    'local name="$1" url="$2" expected="${3:-}" required="${4:-0}" body record host',
    'optional-stale-record expected=${expected%/}',
    '"${REQUIRE_ACTIVE_GATEWAY_AUTOMATION:-0}"',
    '"${ACTIVE_GATEWAY_BASE:-https://sync.winsvpn.org}"',
    'dns_type="CNAME"',
    '.cfargotunnel.com',
    'listen_http="127.0.0.1:80"',
    'wins-control-tunnel.service',
    '/admin/nodes/bootstrap-management-tunnel',
    '/admin/core/bootstrap-management-tunnel',
    '/admin/core/verify-management',
    '"service": "ssh://127.0.0.1:22"',
    'ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h',
    'REQUIRE_CLOUDFLARE_ACCESS_DEFAULT="${REQUIRE_CLOUDFLARE_ACCESS:-1}"',
    'CLOUDFLARE_ACCESS_API_TOKEN',
    'CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID',
    'TUNNEL_SERVICE_TOKEN_ID',
    'TUNNEL_SERVICE_TOKEN_SECRET',
    'def ensure_cloudflare_access_application(ssh_hostname: str) -> str:',
    '"decision": "non_identity"',
    '"service_token": {"token_id": CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID}',
    'wins-cloudflare-access-refresh',
    'def install_management_known_hosts(hostname: str, values: list[str]) -> None:',
    'StrictHostKeyChecking=yes',
    'UserKnownHostsFile={MANAGEMENT_KNOWN_HOSTS_PATH}',
    'GlobalKnownHostsFile=/dev/null',
    'UpdateHostKeys=no',
    'CF-Connecting-IP',
    'Cloudflare Tunnel Edit',
    'tunnel Edit permission rejected',
    'invalid tunnel-create probe unexpectedly mutated provider state',
    'External credential/permission preflight failed:',
    'External credential/permission preflight passed',
    'CONTROL_DIRECT_CLOUDFLARE_ONLY_DEFAULT="${CONTROL_DIRECT_CLOUDFLARE_ONLY:-1}"',
    'CONTROL_LEGACY_SPA_UDP_DEFAULT="${CONTROL_LEGACY_SPA_UDP:-0}"',
    'https://www.cloudflare.com/ips-v4',
    'Cloudflare-only recovery ingress has no validated IPv4 allowlist; firewall was not changed.',
    'Cloudflare-only recovery must not contain a source-unrestricted HTTP/HTTPS accept rule.',
    'iptables -A WINVPN-HUB-INPUT -i lo -p tcp --dport 8000',
    'drop http $EXTERNAL_NET any -> $HOME_NET [80,443,8000]',
    '"filename": "/var/run/suricata/suricata-command.socket"',
    'ExecStartPre=/bin/rm -f /var/run/suricata/suricata-command.socket',
    'iptables -N WINVPN-HUB-OUTPUT',
    'iptables -A WINVPN-HUB-OUTPUT -o lo -p tcp --sport 8000',
    'local -a nfqueue_target=(-j NFQUEUE --queue-num 0)',
    'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-0}"',
    'def management_tunnel_hostname(kind: str, identifier: str) -> str:',
    'ssh_hostname = f"{normalized_kind}-{slug}-{opaque_tag}.{NODE_MANAGEMENT_TUNNEL_ZONE_NAME}"',
    'def core_ssh_command(',
    'expected_management_host = node_management_hostname(payload.slug)',
    'legacy_ssh_hostname',
    'local desired_public_payment_base="${PUBLIC_PAYMENT_BASE:-$PUBLIC_PAYMENT_BASE_DEFAULT}"',
    'PUBLIC_PAYMENT_BASE="${desired_public_payment_base}"',
    'write_env_kv PUBLIC_PAYMENT_BASE "${desired_public_payment_base}"',
    '"awg_rx_bytes", "awg_tx_bytes", "wan_rx_bytes", "wan_tx_bytes",',
    '"rx_mbps", "tx_mbps", "peer_count", "max_peers",',
    'n.pop(operational_key, None)',
)
missing = [item for item in required_control if item not in control]
if missing:
    raise SystemExit(f"control origin-hiding contract missing: {missing}")
if "Read-only external credential preflight passed" in control:
    raise SystemExit("control mislabels its Tunnel Edit authorization probe as read-only")
if 'ssh_hostname = f"node-{slug}-{opaque_tag}.mgmt.' in control:
    raise SystemExit("control management hostname uses two labels below the zone and cannot use the standard wildcard edge certificate")
if 'record="${gateway_base}|${IONOS_HUB_IP}"' in control:
    raise SystemExit("control still publishes its public IP in the gateway record")
if "StrictHostKeyChecking=no" in control or "StrictHostKeyChecking=accept-new" in control:
    raise SystemExit("control SSH does not require a pre-provisioned host-key pin")
for role, role_source in (("data", data), ("core", core)):
    if '${response:-{}}' in role_source:
        raise SystemExit(f"{role} uses an ambiguous Bash JSON fallback that corrupts nonempty responses")
main = control[control.rfind("\nmain() {"):]
if not (main.find("write_nginx") < main.find("configure_control_origin_tunnel") < main.find("write_cloudflare_hub_dns")):
    raise SystemExit("control tunnel must be active before its CNAMEs are published")
cutover_order = (
    "postflight_control",
    "run_initial_backup",
    "verify_external_integrations",
    "write_cloudflare_hub_dns",
    "run_prepublication_gateway_canary",
    "publish_active_gateway_record",
)
positions = [main.find(item) for item in cutover_order]
if any(position < 0 for position in positions) or positions != sorted(positions):
    raise SystemExit(f"control public cutover is not fail-closed: {cutover_order}")
if not (main.find("validate_external_secret_contract") < main.find("ensure_cloudflare_access_service_token") < main.find("write_app")):
    raise SystemExit("Access service credentials must exist before the hub app is generated")
if not (main.find("write_cloudflare_access_refresh") < main.find("write_weekly_maintenance")):
    raise SystemExit("Access expiry refresh helper must exist before weekly maintenance is installed")
required_nginx_bucket = (
    "longest_server_name_length",
    "server_name_bucket_size",
    "/etc/nginx/conf.d/wins-server-names-hash.conf",
    "server_names_hash_bucket_size %s;",
)
missing = [item for item in required_nginx_bucket if item not in control]
if missing:
    raise SystemExit(f"control Nginx dynamic server-name bucket contract missing: {missing}")

required_data = (
    'NODE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT="${NODE_MANAGEMENT_TUNNEL_ENABLED:-1}"',
    'wins-node-management-tunnel.service',
    'Do not inject IONOS_HUB_IP when node management tunneling is enabled',
    'the control origin IP is not stored on this data plane',
    'data_resolve_management_tunnel_material',
    'NODE_MGMT_TUNNEL_TOKEN',
    'data_scrub_consumed_subject_material',
    "cloudflared tunnel run --help 2>&1 | grep -F -- '--token-file' >/dev/null",
)
missing = [item for item in required_data if item not in data]
if missing:
    raise SystemExit(f"data origin-hiding contract missing: {missing}")
if 'write_env_kv IONOS_HUB_IP' in data:
    raise SystemExit("data-plane runtime environment still stores the control public IP")
main = data[data.rfind("\nmain() {"):]
if not (main.find("collect_inputs") < main.find("configure_node_management_tunnel") < main.find("setup_sysctl")):
    raise SystemExit("data management tunnel bootstrap is in the wrong command order")

required_core = (
    'CORE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT="${CORE_MANAGEMENT_TUNNEL_ENABLED:-1}"',
    'wins-core-management-tunnel.service',
    'fetch_hub_management_pubkey',
    'prepare_core_ssh_authorized_keys',
    'configure_core_management_tunnel',
    'verify_hub_core_management',
    'CORE_MANAGEMENT_VERIFY_ATTEMPTS_DEFAULT="${CORE_MANAGEMENT_VERIFY_ATTEMPTS:-120}"',
    'CORE_MANAGEMENT_VERIFY_INTERVAL_SECONDS_DEFAULT="${CORE_MANAGEMENT_VERIFY_INTERVAL_SECONDS:-5}"',
    'CORE_MANAGEMENT_REUSE_PROBE_ATTEMPTS_DEFAULT="${CORE_MANAGEMENT_REUSE_PROBE_ATTEMPTS:-12}"',
    'attempt ${attempt}/${attempts}',
    'probe_hub_core_management',
    'verify_existing_core_management_connector',
    'CORE_MGMT_TUNNEL_TOKEN',
    'core_scrub_consumed_subject_material',
    'systemctl reload ssh',
    'Reusing the already-verified outbound Core management connector',
    'verify_management_runtime',
    'AllowTcpForwarding no',
    'DisableForwarding yes',
    "printf 'restrict %s\\n'",
    "\"${install_path}\" tunnel run --help 2>&1 | grep -F -- '--token-file' >/dev/null",
    'the control origin IP is not stored on this Core',
)
missing = [item for item in required_core if item not in core]
if missing:
    raise SystemExit(f"Core origin-hiding management contract missing: {missing}")
core_main = core[core.rfind("\nmain() {"):]
positions = [
    core_main.find("load_or_create_env"),
    core_main.find("fetch_hub_management_pubkey"),
    core_main.find("prepare_core_ssh_authorized_keys"),
    core_main.find("configure_core_management_tunnel"),
    core_main.find("verify_hub_core_management"),
    core_main.find("write_firewall"),
    core_main.find("harden_sshd"),
    core_main.rfind("verify_hub_core_management"),
]
if any(position < 0 for position in positions) or positions != sorted(positions):
    raise SystemExit(f"Core management bootstrap/lockdown order is unsafe: {positions}")
if 'IONOS_HUB_IP=' in core[core.find('load_or_create_env()'):core.find('install_awg_ingress()')]:
    raise SystemExit("Core persisted environment stores the hidden control origin IP")
if 'systemctl restart ssh' in core:
    raise SystemExit("Core SSH hardening restarts the daemon and can terminate its own tunnel deployment session")
PYEOF
  echo "PASS outbound-only control origin and data/Core management tunnel contract"
}

test_atomic_firewall_rebuild_contract() {
  python3 - "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${CORE_SCRIPT}" <<'PYEOF'
from dataclasses import dataclass
from pathlib import Path
import re
import sys

control = Path(sys.argv[1]).read_text(encoding="utf-8")
data = Path(sys.argv[2]).read_text(encoding="utf-8")
core = Path(sys.argv[3]).read_text(encoding="utf-8")


def section(source: str, start_name: str, end_name: str) -> str:
    start = source.index(f"\n{start_name}() {{")
    end = source.index(f"\n{end_name}() {{", start + 2)
    return source[start:end]


control_fw = section(control, "write_iptables", "write_suricata_noise_pruner")
core_fw = section(core, "write_firewall", "sshd_effective_value_is")
data_fw = section(data, "write_edge_hardening_script", "write_firewall")

if "trap cleanup_core_firewall_transaction RETURN" in core_fw:
    raise SystemExit("Core firewall cleanup still uses a nested-function RETURN trap")
if 'CORE_NFQUEUE_PROC_PATH:-/proc/net/netfilter/nfnetlink_queue' not in core_fw:
    raise SystemExit("Core firewall precommit health gate does not verify a bound queue 0")
for required in (
    '-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN',
    '-X WINVPN-CORE-FAILURE-HOLD-IN',
    '-D FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD',
    '-X WINVPN-CORE-FAILURE-HOLD-FWD',
):
    if required not in core_fw:
        raise SystemExit(f"Core successful firewall replacement does not retire degraded hold: {required}")

for role, body in (("control", control_fw), ("data", data_fw), ("core", core_fw)):
    for required in (
        'restore_bin="${IPTABLES_RESTORE_BIN:-iptables-restore}"',
        '"${restore_bin}" --wait 10 --test --noflush',
        '"${restore_bin}" --wait 10 --noflush',
        '"${restore_bin}" --wait 10 < "${snapshot}"',
    ):
        if required not in body:
            raise SystemExit(f"{role} atomic firewall contract missing {required}")
    if "ESTABLISHED,RELATED" not in body and "RELATED,ESTABLISHED" not in body:
        raise SystemExit(f"{role} atomic firewall contract lacks established-session continuity")
    if re.search(r"while\s+(?:ipt|iptables)\s+(?:-t\s+\S+\s+)?-D\s+(?:INPUT|FORWARD|OUTPUT)", body):
        raise SystemExit(f"{role} still removes live base-chain jumps non-atomically")
    test_at = body.index('"${restore_bin}" --wait 10 --test --noflush')
    apply_at = body.index('"${restore_bin}" --wait 10 --noflush', test_at + 1)
    rollback_at = body.index('"${restore_bin}" --wait 10 < "${snapshot}"')
    if not test_at < apply_at < rollback_at:
        raise SystemExit(f"{role} validate/apply/rollback order changed")

core_client_return_order = (
    'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -o "${CORE_EXIT_IFACE}" -s "${CORE_INGRESS_CIDR}" -j ACCEPT',
    'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -o "${CORE_EXIT_IFACE_PREFIX}+" -s "${CORE_INGRESS_CIDR}" -j ACCEPT',
    'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -j DROP',
    'iptables -t nat -C POSTROUTING -j WINVPN-CORE-NAT 2>/dev/null || core_restore_rule "${nat_body}" -I POSTROUTING 1 -j WINVPN-CORE-NAT',
    'core_restore_rule "${nat_body}" -A WINVPN-CORE-NAT -s "${CORE_INGRESS_CIDR}" -o "${CORE_EXIT_IFACE}" -j MASQUERADE',
    'core_restore_rule "${nat_body}" -A WINVPN-CORE-NAT -s "${CORE_INGRESS_CIDR}" -o "${CORE_EXIT_IFACE_PREFIX}+" -j MASQUERADE',
)
# e8d3df3 made the core clamp lower-only (-m tcpmss --mss N+1:65535). The MSS
# is now computed from CORE_AWG_MTU by core_tcp_mss_for_mtu, so match that
# shape here, require every core AWG interface to render the same
# ${CORE_AWG_MTU}, and let the write_firewall run below check the rendered
# numbers (MSS = MTU - 40 at the shipped default MTU).
core_mss_rule = re.search(
    r'core_restore_rule "\$\{mangle_body\}" -A WINVPN-CORE-MANGLE -p tcp --tcp-flags SYN,RST SYN '
    r'-m tcpmss --mss "\$\(\(core_tcp_mss \+ 1\)\):65535" -j TCPMSS --set-mss "\$\{core_tcp_mss\}"',
    core_fw,
)
core_mtus = set(re.findall(r'^MTU = (.*)$', core, re.M))
if (
    core_mss_rule is None
    or 'core_tcp_mss="$(core_tcp_mss_for_mtu "${CORE_AWG_MTU}")"' not in core_fw
    or core_mtus != {"${CORE_AWG_MTU}"}
):
    raise SystemExit(f"Core MSS clamp is not a lower-only clamp within the tunnel MTU: {core_mtus}")
core_client_return_positions = [core_fw.find(item) for item in core_client_return_order]
core_client_return_positions.append(core_mss_rule.start())
if (
    any(position < 0 for position in core_client_return_positions)
    or core_client_return_positions != sorted(core_client_return_positions)
):
    raise SystemExit(
        "Core client forward/NAT/MSS return-path order changed: "
        f"{core_client_return_positions}"
    )


@dataclass(frozen=True)
class FilterState:
    public_tcp: frozenset[int]
    established_management: bool
    trusted_ssh: bool


def assert_safe(role: str, state: FilterState, intended_public: frozenset[int]) -> None:
    if not state.established_management:
        raise SystemExit(f"{role} firewall boundary dropped the active management session")
    if not state.trusted_ssh:
        raise SystemExit(f"{role} firewall boundary removed the trusted recovery SSH path")
    unexpected = state.public_tcp - intended_public
    if unexpected:
        raise SystemExit(f"{role} firewall boundary transiently exposed {sorted(unexpected)}")
    for port in (22, 80, 443, 8000):
        if port not in intended_public and port in state.public_tcp:
            raise SystemExit(f"{role} firewall boundary transiently exposed TCP {port}")


roles = {
    # Hidden-origin control must expose none of the audited ports directly.
    "control": (frozenset(), 34),
    # Data/Core intentionally expose their censorship transports in the tested
    # public-ingress profile; the transaction must never add anything else.
    "data": (frozenset({80, 443}), 52),
    "core": (frozenset({80, 443}), 28),
}
for role, (intended, build_boundaries) in roles.items():
    old = FilterState(intended, True, True)
    candidate = FilterState(intended, True, True)

    # Every rule-generation failure is off-path: the live state remains old.
    for _boundary in range(build_boundaries + 1):
        assert_safe(role, old, intended)

    # Validation failure and a failure before filter COMMIT leave old active.
    assert_safe(role, old, intended)
    assert_safe(role, old, intended)

    # Failure after filter COMMIT but before NAT/mangle completion can expose
    # only the complete candidate filter, never an empty or half-built chain.
    for _later_table in ("nat", "mangle", "persistence"):
        assert_safe(role, candidate, intended)
        # Successful rollback returns to old. If rollback itself fails, the
        # complete candidate is still fail-closed and management-safe.
        assert_safe(role, old, intended)
        assert_safe(role, candidate, intended)

    assert_safe(role, candidate, intended)
PYEOF
  local probe="${work_dir}/core-firewall-nested-return.sh"
  local runner="${work_dir}/core-firewall-probe-run.sh"
  local bin="${work_dir}/core-firewall-bin"
  local receipt="${work_dir}/core-firewall-applied.rules"
  local queue="${work_dir}/core-firewall-queue0"
  local hold_present="${work_dir}/core-firewall-hold-present"
  local core_mtu core_mss
  sed -n '/^cleanup_core_firewall_transaction_workspace() {$/,/^}$/p' "${CORE_SCRIPT}" > "${probe}"
  sed -n '/^write_firewall() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${probe}"
  # write_firewall derives its MSS clamp through this helper.
  sed -n '/^core_tcp_mss_for_mtu() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${probe}"
  grep -Fxq 'core_tcp_mss_for_mtu() {' "${probe}"
  # Render at the MTU the Core ships (installer and sync agent must agree) and
  # expect the clamp at MTU - 40: IPv4 and TCP headers, the Core relays IPv4.
  core_mtu="$(sed -n 's/^CORE_AWG_MTU="\${CORE_AWG_MTU:-\([0-9][0-9]*\)}"$/\1/p' "${CORE_SCRIPT}" | sort -u)"
  [[ "${core_mtu}" =~ ^[0-9]{4}$ ]]
  core_mss=$((core_mtu - 40))
  # write_firewall also writes /usr/local/sbin/winsvpn-core-hardening.sh and
  # its unit, runs that script and adds ip rules. Run it in private mount and
  # network namespaces so none of that reaches the host running this suite.
  cat > "${runner}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
probe="$1" bin="$2" err_log="$3"
for dir in /usr/local/sbin /etc/systemd/system; do
  mount -t tmpfs -o mode=0755 tmpfs "${dir}"
done
PATH="${bin}:${PATH}"
log() { :; }; warn() { :; }
err() { printf '%s\n' "$*" >> "${err_log}"; printf '%s\n' "$*" >&2; }
# shellcheck disable=SC1090
source "${probe}"
trap 'cleanup_core_firewall_transaction_workspace' ERR
write_firewall 1 1
EOF
  chmod 700 "${runner}"
  printf '%s\n' '0 0 0 0 0 0 0 0 0' > "${queue}"
  touch "${hold_present}"
  install -d -m 755 "${bin}"
  cat > "${bin}/iptables" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *'-C INPUT -j WINVPN-CORE-FAILURE-HOLD-IN'* || "$*" == *'-C FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD'* ]]; then exit 0; fi
if [[ "$*" == *'-m hashlimit --help'* ]]; then exit 1; fi
# The base chains as the iptables-save stub below lists them (the Core reads
# them before it re-places its owned-chain jumps).
if [[ "$*" == '-S INPUT' ]]; then printf '%s\n' '-P INPUT DROP' '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN'; exit 0; fi
if [[ "$*" == '-S FORWARD' ]]; then printf '%s\n' '-P FORWARD DROP' '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD'; exit 0; fi
exit 1
EOF
  cat > "${bin}/iptables-save" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' \
 ':WINVPN-CORE-FAILURE-HOLD-IN - [0:0]' ':WINVPN-CORE-FAILURE-HOLD-FWD - [0:0]' \
 '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD' \
 '-A WINVPN-CORE-FAILURE-HOLD-IN -j DROP' '-A WINVPN-CORE-FAILURE-HOLD-FWD -j DROP' COMMIT
EOF
  cat > "${bin}/iptables-restore" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
payload="$(cat)"
if [[ " $* " == *' --test '* ]]; then
  [[ -e "${CORE_FIREWALL_HOLD_PRESENT:?}" ]]
  grep -Fq -- '-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' <<<"${payload}"
  grep -Fq -- '-X WINVPN-CORE-FAILURE-HOLD-FWD' <<<"${payload}"
else
  printf '%s\n' "${payload}" > "${CORE_FIREWALL_TEST_RECEIPT:?}"
fi
EOF
  cat > "${bin}/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == is-active ]] && exit 0
[[ "${1:-}" == show ]] && { echo 'ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml'; exit 0; }
exit 0
EOF
  cat > "${bin}/suricata" <<'EOF'
#!/usr/bin/env bash
echo 'NFQ support: yes'
EOF
  cat > "${bin}/suricatasc" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == '-c uptime' ]]
EOF
  # `ip` is stubbed too, so the probe never adds policy rules on the suite host.
  for name in netfilter-persistent ip6tables ip6tables-save ip; do
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "${bin}/${name}"
  done
  chmod 700 "${bin}"/*
  : > "${receipt}.err"
  CORE_FIREWALL_TEST_RECEIPT="${receipt}" CORE_FIREWALL_HOLD_PRESENT="${hold_present}" \
    SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT=0 CORE_INGRESS_PORT=9210 \
    CORE_STEALTH_TRANSPORTS='80:none,443:tls' CORE_ADMIN_CIDR=127.0.0.1/32 \
    CORE_OPEN_PUBLIC_INGRESS=1 CORE_INGRESS_IFACE=core0 CORE_INGRESS_CIDR=10.0.0.0/24 \
    CORE_INGRESS_ADDR=10.0.0.1/24 CORE_AWG_MTU="${core_mtu}" \
    CORE_EXIT_IFACE=corex3 CORE_EXIT_IFACE_PREFIX=corex CORE_UDP_RATE_LIMIT=off \
    CORE_INSTALLER_RERUN_ACTIVE=0 \
    CORE_NFQUEUE_PROC_PATH="${queue}" \
    CORE_IPTABLES_RULES_V4_PATH="${work_dir}/core-firewall-persisted.v4" \
    CORE_IPTABLES_RULES_V6_PATH="${work_dir}/core-firewall-persisted.v6" \
    IPTABLES_RESTORE_BIN="${bin}/iptables-restore" IPTABLES_SAVE_BIN="${bin}/iptables-save" \
    unshare -m -n bash "${runner}" "${probe}" "${bin}" "${receipt}.err"
  [[ ! -s "${receipt}.err" ]]
  grep -Fxq -- "-A WINVPN-CORE-MANGLE -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss $((core_mss + 1)):65535 -j TCPMSS --set-mss ${core_mss}" "${receipt}"
  # 27faafd: only the two TCP stealth transports are queued; encrypted
  # AmneziaWG UDP 9210 is admitted directly and must never reach NFQUEUE.
  [[ "$(grep -c -- '--queue-num 0' "${receipt}")" == 2 ]]
  grep -Fq -- '-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' "${receipt}"
  grep -Fq -- '-X WINVPN-CORE-FAILURE-HOLD-IN' "${receipt}"
  grep -Fq -- '-D FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD' "${receipt}"
  grep -Fq -- '-X WINVPN-CORE-FAILURE-HOLD-FWD' "${receipt}"
  grep -Fxq -- '-A WINVPN-CORE-INPUT -p udp --dport 9210 -j ACCEPT' "${receipt}"
  # Capture, then match: a `grep | grep -q` pipeline under pipefail read a
  # receipt with 50,000 queued 9210 rules as clean (the writer's SIGPIPE).
  local udp_9210_rules
  udp_9210_rules="$(grep -F -- '--dport 9210' "${receipt}")" || [[ $? == 1 ]]
  if grep -Fq -- 'NFQUEUE' <<<"${udp_9210_rules}"; then
    echo 'core firewall receipt queues encrypted AmneziaWG UDP 9210 to NFQUEUE' >&2
    return 1
  fi
  grep -Fq -- '-A WINVPN-CORE-INPUT -p tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0' "${receipt}"
  grep -Fq -- '-A WINVPN-CORE-INPUT -p tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0' "${receipt}"
  local before_workspaces after_workspaces forced_rc
  before_workspaces="$(find /tmp -maxdepth 1 -type d -name 'winsvpn-core-firewall.*' | sort)"
  : > "${receipt}.forced.err"
  set +e
  CORE_FIREWALL_TEST_RECEIPT="${receipt}.forced" CORE_FIREWALL_HOLD_PRESENT="${hold_present}" \
    SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT=0 CORE_INGRESS_PORT=9210 \
    CORE_STEALTH_TRANSPORTS='80:none,443:tls' CORE_ADMIN_CIDR=127.0.0.1/32 \
    CORE_OPEN_PUBLIC_INGRESS=1 CORE_INGRESS_IFACE='unsafe iface' CORE_INGRESS_CIDR=10.0.0.0/24 \
    CORE_INGRESS_ADDR=10.0.0.1/24 CORE_AWG_MTU="${core_mtu}" \
    CORE_EXIT_IFACE=corex3 CORE_EXIT_IFACE_PREFIX=corex CORE_UDP_RATE_LIMIT=off \
    CORE_INSTALLER_RERUN_ACTIVE=0 \
    CORE_NFQUEUE_PROC_PATH="${queue}" \
    CORE_IPTABLES_RULES_V4_PATH="${work_dir}/core-firewall-forced.v4" \
    CORE_IPTABLES_RULES_V6_PATH="${work_dir}/core-firewall-forced.v6" \
    IPTABLES_RESTORE_BIN="${bin}/iptables-restore" IPTABLES_SAVE_BIN="${bin}/iptables-save" \
    unshare -m -n bash "${runner}" "${probe}" "${bin}" "${receipt}.forced.err" 2> "${receipt}.forced.stderr"
  forced_rc=$?
  set -e
  # The run must be refused for the unsafe interface name itself, before any
  # rule is applied, and not by an unrelated crash.
  [[ "${forced_rc}" != 0 ]]
  [[ "$(cat "${receipt}.forced.err")" == 'Refusing unsafe whitespace in generated Core firewall argument.' ]]
  [[ ! -e "${receipt}.forced" ]]
  if grep -Fq 'unbound variable' "${receipt}.forced.stderr"; then false; fi
  after_workspaces="$(find /tmp -maxdepth 1 -type d -name 'winsvpn-core-firewall.*' | sort)"
  [[ "${after_workspaces}" == "${before_workspaces}" ]]
  echo "PASS control/data/Core firewall replacement is atomic, rollback-safe, and management-session preserving at every mutation boundary"
}

# write_edge_output_chain_stubs DIR: the live OUTPUT chain for the generated
# wins-edge-hardening's apply_firewall run against stubbed tools. Since
# FU-KEYSDP (F-DPHIGH-2) apply_firewall reads `iptables -S OUTPUT` live, stages
# the WINVPN-OUTPUT jump at position 1 in its transaction, and reads the chain
# back after the commit; a read that fails stops the build (fail closed).
# DIR/iptables answers `[-w N] [-t filter] -S OUTPUT` from the chain in
# ${EDGE_OUTPUT_CHAIN_STATE} (absent: a fresh host, policy line only) and
# fails every other call, as the earlier stub did. The fake iptables-restore
# passes each committed payload to DIR/edge-output-chain-apply, which changes
# that chain as the kernel would: with --noflush the filter table's OUTPUT
# -F/-D/-I/-A lines in order (a -D without an exact match, an out-of-range
# -I or any other OUTPUT operation fails the restore and changes nothing);
# without --noflush (the rollback to the snapshot) the chain becomes the
# payload's OUTPUT.
write_edge_output_chain_stubs() {
  local dir="$1"
  cat > "${dir}/iptables" <<'EOF'
#!/usr/bin/env bash
args=("$@")
while [[ "${args[0]:-}" == -w ]]; do args=("${args[@]:2}"); done
if [[ "${args[0]:-}" == -t && "${args[1]:-}" == filter ]]; then args=("${args[@]:2}"); fi
if [[ "${#args[@]}" == 2 && "${args[0]}" == -S && "${args[1]}" == OUTPUT ]]; then
  if [[ -s "${EDGE_OUTPUT_CHAIN_STATE:?}" ]]; then
    cat "${EDGE_OUTPUT_CHAIN_STATE}"
  else
    printf '%s\n' '-P OUTPUT ACCEPT'
  fi
  exit 0
fi
# A fresh host's INPUT chain: the policy and no WINVPN-LOCAL-SERVING jump, so
# the rebuild finds no stale latch jump to delete.
if [[ "${#args[@]}" == 2 && "${args[0]}" == -S && "${args[1]}" == INPUT ]]; then
  printf '%s\n' '-P INPUT DROP'
  exit 0
fi
exit 1
EOF
  cat > "${dir}/edge-output-chain-apply" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
state="${EDGE_OUTPUT_CHAIN_STATE:?}"
noflush=0
if [[ " $* " == *' --noflush '* ]]; then noflush=1; fi
[[ -s "${state}" ]] || printf '%s\n' '-P OUTPUT ACCEPT' > "${state}"
awk -v noflush="${noflush}" '
  FNR == NR { if ($1 == "-P") policy = $0; else if ($1 == "-A") rule[++n] = $0; next }
  /^\*/ { table = substr($0, 2); if (table == "filter" && noflush == 0) n = 0; next }
  table != "filter" { next }
  $1 == ":OUTPUT" { policy = "-P OUTPUT " $2; next }
  $2 != "OUTPUT" { next }
  $1 == "-F" && NF == 2 { n = 0; next }
  $1 == "-A" { rule[++n] = $0; next }
  $1 == "-D" {
    want = "-A OUTPUT" substr($0, length("-D OUTPUT") + 1)
    for (i = 1; i <= n && rule[i] != want; i++) ;
    if (i > n) { bad = 1; exit }
    for (; i < n; i++) rule[i] = rule[i + 1]
    n--
    next
  }
  $1 == "-I" {
    pos = 1
    rest = substr($0, length("-I OUTPUT") + 1)
    if ($3 ~ /^[0-9]+$/) { pos = $3 + 0; rest = substr(rest, length($3) + 2) }
    if (pos < 1 || pos > n + 1) { bad = 1; exit }
    for (i = n; i >= pos; i--) rule[i + 1] = rule[i]
    rule[pos] = "-A OUTPUT" rest
    n++
    next
  }
  { bad = 1; exit }
  END {
    if (bad) exit 1
    print policy
    for (i = 1; i <= n; i++) print rule[i]
  }
' "${state}" - > "${state}.next"
mv -f -- "${state}.next" "${state}"
EOF
  chmod 700 "${dir}/iptables" "${dir}/edge-output-chain-apply"
}

# Round EX2 queue-before-accept gate. ex2_queue_gate RULES MODE checks the
# WINVPN-INPUT rules in RULES (an iptables-restore payload or `iptables -S`;
# `-m tcp`/`-m udp` are ignored). For every queued TCP port except 443, no
# rule that can ACCEPT TCP to that port (same --dport, a portless accept such
# as conntrack, or a multiport list naming it) may precede its queue rule.
# MODE:
#   final   443 is queued and accepted above its queue rule by exactly
#           "-A WINVPN-INPUT -p tcp --dport 443 -j ACCEPT", directly above the
#           NFQUEUE 80 rule and after any 443 WINVPN-CF-STEALTH jump; every
#           queued port, 443 included, keeps an accept below its queue rule.
#   closed  nothing but the RELATED,ESTABLISHED accept admits TCP 443.
#   no443   no rule names --dport 443.
ex2_queue_gate() {
  python3 - "$1" "$2" <<'PYEOF'
import re
import sys
from pathlib import Path

path, mode = sys.argv[1], sys.argv[2]
EARLY = "-A WINVPN-INPUT -p tcp --dport 443 -j ACCEPT"
chain = [
    line.replace(" -m tcp ", " ").replace(" -m udp ", " ")
    for line in Path(path).read_text(encoding="utf-8").splitlines()
    if line.startswith("-A WINVPN-INPUT ")
]


def fail(why):
    sys.exit(f"EX2 queue gate ({mode}, {path}): {why}\n" + "\n".join(chain))


def dport(line):
    match = re.search(r" --dport (\S+)", line)
    return match.group(1) if match else None


def admits_tcp(line, port):
    """True if this rule could ACCEPT a TCP packet to port."""
    if not re.search(r" -j ACCEPT( |$)", line):
        return False
    if " -i lo " in line or re.search(r" -p (udp|icmp) ", line):
        return False
    single = dport(line)
    if single is not None:
        return single == port
    multi = re.search(r" --dports (\S+)", line)
    if multi:
        return port in multi.group(1).split(",")
    return True


queue_at = {}
for index, line in enumerate(chain):
    if " -j NFQUEUE " in line:
        port = dport(line)
        if port is None or port in queue_at:
            fail(f"queue rule without one distinct --dport: {line}")
        queue_at[port] = index
if not queue_at:
    fail("no NFQUEUE rule")
if mode == "no443":
    if any(dport(line) == "443" for line in chain):
        fail("443 is not a stealth port here, yet a rule names --dport 443")
if mode == "closed":
    # An established-only accept cannot open a new 443 connection.
    bad = [line for line in chain if admits_tcp(line, "443") and " --ctstate RELATED,ESTABLISHED " not in line]
    if bad:
        fail(f"443 must stay closed, but these rules accept it: {bad}")
for port, at in queue_at.items():
    above = [chain[i] for i in range(at) if admits_tcp(chain[i], port)]
    below = [chain[i] for i in range(at + 1, len(chain)) if admits_tcp(chain[i], port) and dport(chain[i]) == port]
    if port == "443" and mode == "final":
        if above != [EARLY]:
            fail(f"443 must be accepted above its queue rule by exactly '{EARLY}', found {above}")
        early = chain.index(EARLY)
        first_queue = min(queue_at.values())
        if early + 1 != first_queue or dport(chain[first_queue]) != "80":
            fail("the 443 accept is not directly above the NFQUEUE 80 rule")
        if any(i > early for i, line in enumerate(chain) if line == "-A WINVPN-INPUT -p tcp --dport 443 -j WINVPN-CF-STEALTH"):
            fail("the 443 accept precedes the Cloudflare-only restriction")
    elif above:
        fail(f"queued port {port} is accepted before its queue rule: {above}")
    if mode == "final" and not below:
        fail(f"queued port {port} has no accept below its queue rule")
if mode == "final" and "443" not in queue_at:
    fail("the NFQUEUE 443 rule must stay in the chain")
PYEOF
}

test_public_ingress_admission_runtime() {
  local edge_full="${work_dir}/data-edge-admission-full.sh"
  local edge_probe="${work_dir}/data-edge-admission-probe.sh"
  local bin="${work_dir}/data-edge-admission-bin"
  local queue="${work_dir}/data-edge-admission-queue0"
  local receipt="${work_dir}/data-edge-admission.rules"
  extract_edge_hardening "${DATA_SCRIPT}" "${edge_full}"
  sed '/^apply_rps$/,$d' "${edge_full}" > "${edge_probe}"
  install -d -m 755 "${bin}"
  printf '%s\n' '0 0 0 0 0 0 0 0 0' > "${queue}"
  cat > "${bin}/ip" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *'route show default'* ]]; then
  printf 'default via 192.0.2.1 dev eth0\n'
fi
EOF
  write_edge_output_chain_stubs "${bin}"
  cat > "${bin}/iptables-save" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
EOF
  cat > "${bin}/iptables-restore" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
payload="$(cat)"
if [[ " $* " != *' --test '* ]]; then
  printf '%s\n' "${payload}" > "${DATA_EDGE_TEST_RECEIPT:?}"
  "${0%/*}/edge-output-chain-apply" "$@" <<<"${payload}"
fi
EOF
  cat > "${bin}/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${WINS_SURICATA_READY:-1}" != "1" && "${1:-}" == "is-active" ]]; then
  exit 1
fi
if [[ "${1:-}" == "show" ]]; then
  printf 'ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml\n'
fi
exit 0
EOF
  cat > "${bin}/suricata" <<'EOF'
#!/usr/bin/env bash
printf 'NFQ support: yes\n'
EOF
  cat > "${bin}/netfilter-persistent" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 700 "${bin}"/*

  run_edge_admission() {
    local admission="$1" ids="$2" ready="$3" target_receipt="$4"
    local winn3_env="${5:-${work_dir}/missing-winn3-gateway.env}"
    (
      set -Eeuo pipefail
      PATH="${bin}:${PATH}"
      export PATH DATA_EDGE_TEST_RECEIPT="${target_receipt}" WINS_SURICATA_READY="${ready}"
      # Each build starts on a fresh host: OUTPUT holds only its policy.
      export EDGE_OUTPUT_CHAIN_STATE="${target_receipt}.output-chain"
      rm -f -- "${EDGE_OUTPUT_CHAIN_STATE}"
      export WINN3_GATEWAY_ENV_FILE="${winn3_env}"
      export WINSVPN_TEST_ROOT="${work_dir}/data-edge-admission-root"
      export NODE_ENV_FILE="${work_dir}/missing-node.env"
      export PUBLIC_VPN_INGRESS_ADMISSION_FILE="${work_dir}/missing-admission.env"
      export PUBLIC_VPN_INGRESS_ADMISSION="${admission}" INSTALL_DATA_IDS_IPS="${ids}"
      export DATA_NFQUEUE_PROC_PATH="${queue}" IPTABLES_BIN="${bin}/iptables"
      export IPTABLES_SAVE_BIN="${bin}/iptables-save" IPTABLES_RESTORE_BIN="${bin}/iptables-restore"
      export NODE_MANAGEMENT_TUNNEL_ENABLED=1 WG_PORT=9110 STEALTH_ORIGIN_PORT=80
      export STEALTH_TRANSPORTS="${EX2_STEALTH_TRANSPORTS:-80:none,443:tls}" COMPANION_TCP_PORT=8000
      export ALLOW_PUBLIC_STEALTH_HTTP="${EX2_ALLOW_PUBLIC_STEALTH_HTTP:-1}"
      export CLOUDFLARE_ONLY_STEALTH="${EX2_CLOUDFLARE_ONLY_STEALTH:-0}" VPN_INTERFACES=awg0
      source "${edge_probe}"
      apply_firewall
    )
  }

  run_edge_admission 0 0 0 "${receipt}.bootstrap"
  if grep -Eq -- '--dport (80|443|8000|9110) .* -j ACCEPT' "${receipt}.bootstrap"; then
    echo 'data bootstrap admission exposed a public VPN/Xray/Nginx listener' >&2
    return 1
  fi
  if grep -Fq -- '--queue-num 0' "${receipt}.bootstrap"; then
    echo 'data bootstrap admission queued traffic before Suricata readiness' >&2
    return 1
  fi
  # The pattern above needs text between the port and "-j ACCEPT", so it
  # cannot see a bare port accept such as Round EX2's 443 rule.
  if grep -Eq -- '--dport (80|443|8000|9110) -j ACCEPT' "${receipt}.bootstrap"; then
    echo 'data bootstrap admission exposed a public VPN/Xray/Nginx listener' >&2
    return 1
  fi

  run_edge_admission 1 1 1 "${receipt}.final"
  # F-DPHIGH-2: the committed OUTPUT chain starts with the one guard jump.
  [[ "$(cat "${receipt}.final.output-chain")" == $'-P OUTPUT ACCEPT\n-A OUTPUT -j WINVPN-OUTPUT' ]]
  python3 - "${receipt}.final" <<'PYEOF'
from pathlib import Path
import sys

rules = Path(sys.argv[1]).read_text(encoding="utf-8")
# 45e7224: encrypted AmneziaWG UDP is admitted directly, never queued (Suricata
# cannot inspect it and queueing caused drops). Final admission must open it.
if "-p udp --dport 9110 -j ACCEPT" not in rules:
    raise SystemExit("final admission does not admit encrypted AmneziaWG UDP 9110")
if "-p udp --dport 9110 -m mark" in rules or any(
    "--dport 9110" in line and "NFQUEUE" in line for line in rules.splitlines()
):
    raise SystemExit("final admission queues encrypted AmneziaWG UDP 9110 to NFQUEUE")
# Owner ruling, incident CS2 / Round SU: data planes fail open, so every
# production queue rule carries --queue-bypass (no listener bound: accept).
queue_lines = [line for line in rules.splitlines() if "-j NFQUEUE" in line]
if not queue_lines:
    raise SystemExit("final admission emitted no NFQUEUE rule")
for line in queue_lines:
    if not line.endswith(" --queue-num 0 --queue-bypass"):
        raise SystemExit(f"final admission queue rule is not fail-open (--queue-bypass): {line}")
for queue_rule in (
    "-A WINVPN-INPUT -p tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass",
    "-A WINVPN-INPUT -p tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass",
    "-A WINVPN-INPUT -p tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass",
):
    if rules.splitlines().count(queue_rule) != 1:
        raise SystemExit(f"final admission does not queue exactly once: {queue_rule}")
PYEOF
  # Round EX2: 443 is accepted directly above the NFQUEUE 80 rule and keeps
  # its (unreached) queue rule; every other queued port still queues first.
  ex2_queue_gate "${receipt}.final" final
  # Cloudflare-only: the 443 accept sits behind the pre-queue restriction.
  local ex2_bin="${work_dir}/data-edge-admission-ex2-bin"
  install -d -m 755 "${ex2_bin}"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "${ex2_bin}/curl"
  chmod 700 "${ex2_bin}/curl"
  EX2_CLOUDFLARE_ONLY_STEALTH=1 PATH="${ex2_bin}:${PATH}" run_edge_admission 1 1 1 "${receipt}.ex2-cf"
  grep -Fxq -- '-A WINVPN-INPUT -p tcp --dport 443 -j WINVPN-CF-STEALTH' "${receipt}.ex2-cf"
  ex2_queue_gate "${receipt}.ex2-cf" final
  # 443 admitted by no accept below the queue: the early accept is not emitted.
  EX2_ALLOW_PUBLIC_STEALTH_HTTP=0 run_edge_admission 1 1 1 "${receipt}.ex2-closed"
  ex2_queue_gate "${receipt}.ex2-closed" closed
  # 443 is not a stealth port: no 443 rule at all.
  EX2_STEALTH_TRANSPORTS='80:none' run_edge_admission 1 1 1 "${receipt}.ex2-no443"
  ex2_queue_gate "${receipt}.ex2-no443" no443
  # --expects-443-bypass (the postflight's expectation) agrees with what the
  # build emitted, for every configuration above and for bootstrap.
  edge_expects() {  # edge_expects ADMISSION: the edge script's answer
    (
      PATH="${bin}:${PATH}"
      export PATH NODE_ENV_FILE="${work_dir}/missing-node.env"
      export PUBLIC_VPN_INGRESS_ADMISSION_FILE="${work_dir}/missing-admission.env"
      export PUBLIC_VPN_INGRESS_ADMISSION="$1" STEALTH_ORIGIN_PORT=80
      export STEALTH_TRANSPORTS="${EX2_STEALTH_TRANSPORTS:-80:none,443:tls}"
      export ALLOW_PUBLIC_STEALTH_HTTP="${EX2_ALLOW_PUBLIC_STEALTH_HTTP:-1}"
      export CLOUDFLARE_ONLY_STEALTH="${EX2_CLOUDFLARE_ONLY_STEALTH:-0}"
      bash "${edge_full}" --expects-443-bypass
    )
  }
  [[ "$(edge_expects 1)" == 1 ]]
  grep -Fxq -- '-A WINVPN-INPUT -p tcp --dport 443 -j ACCEPT' "${receipt}.final"
  [[ "$(EX2_CLOUDFLARE_ONLY_STEALTH=1 edge_expects 1)" == 1 ]]
  [[ "$(EX2_ALLOW_PUBLIC_STEALTH_HTTP=0 edge_expects 1)" == 0 ]]
  [[ "$(EX2_STEALTH_TRANSPORTS='80:none' edge_expects 1)" == 0 ]]
  [[ "$(edge_expects 0)" == 0 ]]

  if grep -Fq -- '9111' "${receipt}.final"; then
    echo 'data final admission emitted Winn v3 gateway rules without a gateway env file' >&2
    return 1
  fi

  cp "${receipt}.final" "${receipt}.before-failed-readiness"
  if run_edge_admission 1 1 0 "${receipt}.failed-readiness"; then
    echo 'data final admission ignored failed Suricata readiness' >&2
    return 1
  fi
  [[ ! -e "${receipt}.failed-readiness" ]]
  cmp -s "${receipt}.final" "${receipt}.before-failed-readiness"
  echo "PASS data bootstrap admission is closed, final queue-before-accept is ordered, and failed readiness leaves the prior firewall unchanged"
  test_winn3_udp_policy_runtime "${edge_full}" "${receipt}"
}

# Winn v3 gateway UDP (lane L8): accepted behind both guards, never queued.
# Every check runs the generated wins-edge-hardening itself: the firewall build
# (apply_firewall) and --check-winn3-udp-policy, the mode the installer's
# postflight runs after its final rebuild. Both call the script's one resolver
# (winn3_gateway_resolve) and one parser (winn3_udp_policy_check); the only
# stub is the iptables binary that serves a WINVPN-INPUT fixture to -S.
test_winn3_udp_policy_runtime() {
  local edge_full="$1" receipt="$2"
  local fx="${work_dir}/winn3-policy"
  local policy_bin="${fx}/bin" kernel="${fx}/kernel-accept-first.rules"
  local guard_serving='-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING'
  local udp_accept='-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT'
  local name want env_file line policy_log env_default env_9222 env_export env_quoted
  install -d -m 755 "${fx}" "${policy_bin}" "${fx}/override dir"
  cat > "${policy_bin}/iptables" <<'EOF'
#!/usr/bin/env bash
[[ " $* " == *' -S WINVPN-INPUT '* ]] || exit 2
[[ -r "${WINN3_POLICY_FIXTURE:-}" ]] || exit 3
cat "${WINN3_POLICY_FIXTURE}"
EOF
  chmod 700 "${policy_bin}/iptables"
  # Verbatim `iptables -S WINVPN-INPUT` from a kernel loaded with the patched
  # installer's generated filter table (Ubuntu 24.04, iptables 1.8.10 nft).
  cat > "${kernel}" <<'EOF'
-N WINVPN-INPUT
-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY
-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING
-A WINVPN-INPUT -i lo -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A WINVPN-INPUT -i awg0 -p tcp -m tcp --dport 8080 -j DROP
-A WINVPN-INPUT -i awg0 -p udp -m udp --dport 53 -j ACCEPT
-A WINVPN-INPUT -i awg0 -p tcp -m tcp --dport 53 -j ACCEPT
-A WINVPN-INPUT -i awg0 -p tcp -m multiport --dports 853,8853 -j REJECT --reject-with tcp-reset
-A WINVPN-INPUT -i awg0 -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp-port-unreachable
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 8080 -j DROP
-A WINVPN-INPUT -p icmp -m icmp --icmp-type 8 -j DROP
-A WINVPN-INPUT -p udp -m udp --dport 6881:6889 -j DROP
-A WINVPN-INPUT -p tcp -m tcp --dport 6881:6889 -j DROP
-A WINVPN-INPUT -p tcp -m tcp --dport 6969 -j DROP
-A WINVPN-INPUT -j DROP
EOF
  [[ "$(id -u)" == 0 ]] || {
    echo 'Winn v3 UDP policy checks need root-owned gateway env fixtures (run the validator as root)' >&2
    return 1
  }
  write_winn3_env() {
    printf '%s\n' "$2" > "$1"
    chown 0:0 "$1"
    chmod 600 "$1"
  }
  env_default="${fx}/gateway.env"
  env_9222="${fx}/override dir/gateway-9222.env"
  env_export="${fx}/gateway-export.env"
  env_quoted="${fx}/gateway-quoted.env"
  write_winn3_env "${env_default}" 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111'
  write_winn3_env "${env_9222}" 'WINN3_GATEWAY_LISTEN=0.0.0.0:9222'
  write_winn3_env "${env_export}" 'export WINN3_GATEWAY_LISTEN=0.0.0.0:9333'
  write_winn3_env "${env_quoted}" 'WINN3_GATEWAY_LISTEN="0.0.0.0:9444" # local cover port'
  write_winn3_env "${fx}/gateway-clobber.env" $'WINN3_GATEWAY_LISTEN=0.0.0.0:9111\nWINN3_GATEWAY_ENABLED=0\nWINN3_GATEWAY_LISTEN_PORT=1\nPUBLIC_VPN_INGRESS_ADMISSION=0\nIPT=false'
  write_winn3_env "${fx}/gateway-mode.env" 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111'
  chmod 644 "${fx}/gateway-mode.env"
  write_winn3_env "${fx}/gateway-owner.env" 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111'
  chown 65534:65534 "${fx}/gateway-owner.env"
  ln -s "${env_default}" "${fx}/gateway-symlink.env"

  policy_check() {
    (
      export PATH="${policy_bin}:${PATH}" IPTABLES_BIN="${policy_bin}/iptables"
      export WINN3_POLICY_FIXTURE="$1" WINN3_GATEWAY_ENV_FILE="$2"
      export NODE_ENV_FILE="${work_dir}/missing-node.env"
      export PUBLIC_VPN_INGRESS_ADMISSION_FILE="${work_dir}/missing-admission.env"
      bash "${edge_full}" --check-winn3-udp-policy
    ) > "${policy_log}" 2>&1
  }
  # expect_policy pass|fail NAME FIXTURE ENV [REASON]: a rejection only counts
  # when the check names the expected reason, so a crash is never a catch.
  expect_policy() {
    local expected="$1" label="$2" fixture="$3" env_path="$4" reason="${5:-}" rc=0
    policy_log="${fx}/${label}.log"
    policy_check "${fixture}" "${env_path}" || rc=$?
    if [[ "${expected}" == pass && "${rc}" != 0 ]]; then
      echo "Winn v3 UDP policy rejected valid fixture ${label}:" >&2
      cat "${policy_log}" >&2
      return 1
    fi
    if [[ "${expected}" == fail ]]; then
      if [[ "${rc}" == 0 ]]; then
        echo "Winn v3 UDP policy accepted hostile fixture ${label}" >&2
        return 1
      fi
      grep -Fq -- "${reason}" "${policy_log}" || {
        echo "Winn v3 UDP policy rejected ${label} for the wrong reason (want: ${reason}):" >&2
        cat "${policy_log}" >&2
        return 1
      }
    fi
  }
  # mutate NAME AFTER-LINE NEW-LINE [before] writes ${fx}/NAME.rules: the
  # kernel fixture with NEW-LINE inserted after (or, with `before`, ahead of)
  # the first exact AFTER-LINE; '' puts it just before the final DROP. Lines
  # travel through ENVIRON, never awk -v, so kernel quoting (\" and \\)
  # reaches the fixture byte for byte. It fails unless exactly one more copy
  # of the line is present than in the kernel fixture.
  mutate() {
    local copies
    copies="$(grep -c -Fx -- "$3" "${kernel}" || true)"
    L8_AFTER="$2" L8_ADD="$3" L8_BEFORE="${4:-}" awk '
      BEGIN { after = ENVIRON["L8_AFTER"]; add = ENVIRON["L8_ADD"]; before = ENVIRON["L8_BEFORE"] == "before" }
      !done && after != "" && $0 == after && before { print add; print; done = 1; next }
      !done && after != "" && $0 == after { print; print add; done = 1; next }
      !done && after == "" && $0 == "-A WINVPN-INPUT -j DROP" { print add; done = 1 }
      { print }
      END { if (!done) exit 1 }' "${kernel}" > "${fx}/$1.rules"
    [[ "$(grep -c -Fx -- "$3" "${fx}/$1.rules")" == "$((copies + 1))" ]]
  }

  # Positive: the kernel-normalised dump (explicit -m udp / -m tcp), and lane
  # L8's recorded a_accept_rules.txt (a grep of the same kind of dump for
  # `--dport 9111|NFQUEUE`) verbatim, behind the two guard jumps that grep left
  # out.
  expect_policy pass kernel-accept-first "${kernel}" "${env_default}"
  {
    printf '%s\n' '-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY' "${guard_serving}"
    cat <<'EOF'
-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT
EOF
  } > "${fx}/a-accept-extract.rules"
  [[ "$(grep -c -Fx -- "${udp_accept}" "${fx}/a-accept-extract.rules")" == 1 ]]
  expect_policy pass a-accept-extract "${fx}/a-accept-extract.rules" "${env_default}"
  # Round EX2: the live shape with TCP 443 accepted directly above the
  # NFQUEUE 80 rule keeps the v3 UDP policy valid, and the EX2 gate reads the
  # kernel form (the kernel fixture above predates EX2, so it fails "final").
  mutate ex2-early-443 '-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0' \
    '-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT' before
  expect_policy pass ex2-early-443 "${fx}/ex2-early-443.rules" "${env_default}"
  ex2_queue_gate "${fx}/ex2-early-443.rules" final
  if ex2_queue_gate "${kernel}" final 2>/dev/null; then
    echo 'EX2 queue gate accepted a chain without the early 443 accept' >&2
    return 1
  fi

  # Negation is modelled, not blanket-rejected: none of these can see public
  # UDP 9111, so the chain stays valid.
  name=0
  for line in \
      '-A WINVPN-INPUT -p udp -m udp ! --dport 9111 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -i lo -p udp -m udp --dport 9111 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT ! -p udp -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m multiport --dports 9100:9110,9112:9200 -j NFQUEUE --queue-num 0'; do
    name=$((name + 1))
    mutate "negation-${name}" "${guard_serving}" "${line}"
    expect_policy pass "negation-${name}" "${fx}/negation-${name}.rules" "${env_default}"
  done

  # Hostile: every way public UDP 9111 can still reach queue 0, in kernel form.
  name=0
  for line in \
      '-A WINVPN-INPUT -p udp -m udp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m multiport --dports 9100:9200 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m multiport --dports 53,9111,9999 -j NFQUEUE --queue-num 0 --queue-bypass' \
      '-A WINVPN-INPUT -p udp -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT ! -i lo -p udp -m udp --dport 9111 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m udp ! --dport 9000 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p 17 -m udp --dport 9111 -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT ! -p tcp -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m udp --dport domain-s -j NFQUEUE --queue-num 0'; do
    name=$((name + 1))
    mutate "queue-${name}" "${guard_serving}" "${line}"
    expect_policy fail "queue-${name}" "${fx}/queue-${name}.rules" "${env_default}" \
      'winn3-udp-policy: NFQUEUE can match UDP 9111'
  done
  # A queue rule after the ACCEPT is still rejected outright.
  mutate queue-late '' '-A WINVPN-INPUT -p udp -m multiport --dports 9000:9999 -j NFQUEUE --queue-num 0'
  expect_policy fail queue-late "${fx}/queue-late.rules" "${env_default}" \
    'winn3-udp-policy: NFQUEUE can match UDP 9111'
  # Ordering: diverted ahead of the ACCEPT, ACCEPT missing, ACCEPT above a guard.
  mutate divert-drop "${guard_serving}" '-A WINVPN-INPUT -p udp -m udp --dport 9111 -j DROP'
  expect_policy fail divert-drop "${fx}/divert-drop.rules" "${env_default}" \
    'winn3-udp-policy: rule ahead of the UDP 9111 ACCEPT can divert it'
  mutate divert-chain "${guard_serving}" '-A WINVPN-INPUT -p udp -j WINS-UNREVIEWED'
  expect_policy fail divert-chain "${fx}/divert-chain.rules" "${env_default}" \
    'winn3-udp-policy: rule ahead of the UDP 9111 ACCEPT can divert it'
  grep -vFx -- "${udp_accept}" "${kernel}" > "${fx}/accept-missing.rules"
  expect_policy fail accept-missing "${fx}/accept-missing.rules" "${env_default}" \
    'winn3-udp-policy: no -p udp --dport 9111 -j ACCEPT'
  awk -v accept="${udp_accept}" -v serving="${guard_serving}" '
    $0 == accept { next } $0 == serving { print accept } { print }' "${kernel}" > "${fx}/accept-above-guard.rules"
  expect_policy fail accept-above-guard "${fx}/accept-above-guard.rules" "${env_default}" \
    'winn3-udp-policy: second WINVPN-INPUT rule must be the unconditional -j WINVPN-LOCAL-SERVING'

  # Guard contract (Round G Turn 2): the first two rules are exactly the
  # unconditional jumps, so no broader ACCEPT and no goto can stand in front
  # of either guard. Every rule line below is the kernel-normalised form
  # `iptables -S` printed for it (lane L8 netns capture, 2026-09-23).
  local guard_recovery='-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY'
  mutate guard-udp-accept "${guard_recovery}" '-A WINVPN-INPUT -p udp -j ACCEPT' before
  expect_policy fail guard-udp-accept "${fx}/guard-udp-accept.rules" "${env_default}" \
    'winn3-udp-policy: first WINVPN-INPUT rule must be the unconditional -j WINVPN-SSH-RECOVERY'
  mutate guard-range-accept "${guard_serving}" '-A WINVPN-INPUT -p udp -m multiport --dports 9100:9200 -j ACCEPT' before
  expect_policy fail guard-range-accept "${fx}/guard-range-accept.rules" "${env_default}" \
    'winn3-udp-policy: second WINVPN-INPUT rule must be the unconditional -j WINVPN-LOCAL-SERVING'
  mutate guard-conntrack-accept "${guard_serving}" '-A WINVPN-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' before
  expect_policy fail guard-conntrack-accept "${fx}/guard-conntrack-accept.rules" "${env_default}" \
    'winn3-udp-policy: second WINVPN-INPUT rule must be the unconditional -j WINVPN-LOCAL-SERVING'
  sed 's/^-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY$/-A WINVPN-INPUT -g WINVPN-SSH-RECOVERY/' "${kernel}" > "${fx}/guard-goto.rules"
  [[ "$(grep -c -Fx -- '-A WINVPN-INPUT -g WINVPN-SSH-RECOVERY' "${fx}/guard-goto.rules")" == 1 ]]
  expect_policy fail guard-goto "${fx}/guard-goto.rules" "${env_default}" \
    'winn3-udp-policy: first WINVPN-INPUT rule must be the unconditional -j WINVPN-SSH-RECOVERY'
  # Live fleet layout (UK and most gateways, 2026-09-23): the gateway's own
  # boot unit inserted both 9111 ACCEPTs above the guards. It fails on the
  # guard contract, names where the UDP ACCEPT is, and never calls it missing.
  {
    printf '%s\n' '-N WINVPN-INPUT' \
      '-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT' \
      "${udp_accept}" "${guard_recovery}" "${guard_serving}" \
      '-A WINVPN-INPUT -i lo -j ACCEPT'
    awk 'seen && $0 !~ /--dport 9111 / { print } $0 == "-A WINVPN-INPUT -i lo -j ACCEPT" { seen = 1 }' "${kernel}"
  } > "${fx}/live-uk-layout.rules"
  [[ "$(grep -c -- '--dport 9111 ' "${fx}/live-uk-layout.rules")" == 2 ]]
  [[ "$(tail -n 1 "${fx}/live-uk-layout.rules")" == '-A WINVPN-INPUT -j DROP' ]]
  expect_policy fail live-uk-layout "${fx}/live-uk-layout.rules" "${env_default}" \
    'winn3-udp-policy: first WINVPN-INPUT rule must be the unconditional -j WINVPN-SSH-RECOVERY'
  grep -Fq 'winn3-udp-policy: second WINVPN-INPUT rule must be the unconditional -j WINVPN-LOCAL-SERVING' "${policy_log}"
  grep -Fq 'winn3-udp-policy: the UDP 9111 ACCEPT is at position 2, above the guard jumps' "${policy_log}"
  if grep -Fq 'no -p udp --dport 9111 -j ACCEPT' "${policy_log}"; then
    echo 'Winn v3 UDP policy called the above-guard ACCEPT missing on the live fleet layout' >&2
    return 1
  fi

  # Quoted operands (Round G Turn 2): comment text that spells an option can
  # never become the protocol or the target, including kernel escapes and a
  # bare `--comment -p`.
  for line in \
      '-A WINVPN-INPUT -p udp -m udp --dport 9111 -m comment --comment "note -p tcp note" -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m udp --dport 9111 -m comment --comment "note -j ACCEPT note" -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m udp --dport 9111 -m comment --comment "q\"uote \\back -j ACCEPT" -j NFQUEUE --queue-num 0' \
      '-A WINVPN-INPUT -p udp -m udp --dport 9111 -m comment --comment -p -j NFQUEUE --queue-num 0'; do
    name=$((name + 1))
    mutate "comment-${name}" "${guard_serving}" "${line}"
    expect_policy fail "comment-${name}" "${fx}/comment-${name}.rules" "${env_default}" \
      'winn3-udp-policy: NFQUEUE can match UDP 9111'
  done
  # ...and comment text that spells a queue rule is not mistaken for one.
  for line in \
      '-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m comment --comment "-p udp --dport 9111 -j NFQUEUE" -j ACCEPT' \
      '-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m comment --comment "q\"uote \\back -j NFQUEUE" -j ACCEPT'; do
    name=$((name + 1))
    mutate "comment-${name}" "${guard_serving}" "${line}"
    expect_policy pass "comment-${name}" "${fx}/comment-${name}.rules" "${env_default}"
  done
  # The kernel escapes a single quote inside a comment as \'; that parses.
  name=$((name + 1))
  mutate "comment-${name}" "${guard_serving}" "-A WINVPN-INPUT -p udp -m comment --comment \"\\'x\\'\" -j ACCEPT"
  expect_policy pass "comment-${name}" "${fx}/comment-${name}.rules" "${env_default}"
  # Syntax the parser does not model is rejected, never guessed. The recent
  # rule is the kernel form; the other three are hand-written inputs that
  # iptables -S never prints (bare single quotes, an open quote, and a match
  # after the target), kept so malformed input fails closed.
  for line in \
      '-A WINVPN-INPUT -p udp -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource -j ACCEPT' \
      "-A WINVPN-INPUT -p udp -m comment --comment 'x' -j ACCEPT" \
      '-A WINVPN-INPUT -p udp -m comment --comment "open -j ACCEPT' \
      '-A WINVPN-INPUT -p udp -j ACCEPT -p tcp'; do
    name=$((name + 1))
    mutate "syntax-${name}" "${guard_serving}" "${line}"
    expect_policy fail "syntax-${name}" "${fx}/syntax-${name}.rules" "${env_default}" \
      'winn3-udp-policy: unsupported rule syntax'
  done
  # A failed read fails the check.
  expect_policy fail read-failure "${fx}/no-such-dump.rules" "${env_default}" 'Could not read WINVPN-INPUT'

  # Resolver: the firewall build and the check resolve the same port from the
  # same file. Non-default port at an overridden path, `export`, and a quoted
  # value with a trailing comment.
  for want in "9222:${env_9222}" "9333:${env_export}" "9444:${env_quoted}"; do
    env_file="${want#*:}"
    want="${want%%:*}"
    run_edge_admission 1 1 1 "${receipt}.winn3-${want}" "${env_file}"
    [[ "$(grep -c -Fx -- "-A WINVPN-INPUT -p udp --dport ${want} -j ACCEPT" "${receipt}.winn3-${want}")" == 1 ]]
    [[ "$(grep -c -- '--dport 9111' "${receipt}.winn3-${want}")" == 0 ]]
    expect_policy pass "build-${want}" "${receipt}.winn3-${want}" "${env_file}"
    expect_policy fail "port-${want}-vs-9111-dump" "${kernel}" "${env_file}" \
      "winn3-udp-policy: no -p udp --dport ${want} -j ACCEPT"
    sed "s/--dport 9111 -j ACCEPT\$/--dport ${want} -j ACCEPT/" "${kernel}" \
      | awk -v serving="${guard_serving}" -v port="${want}" '
          { print } $0 == serving { print "-A WINVPN-INPUT -p udp -m multiport --dports " (port - 5) ":" (port + 5) " -j NFQUEUE --queue-num 0" }' \
      > "${fx}/queue-${want}.rules"
    expect_policy fail "queue-range-${want}" "${fx}/queue-${want}.rules" "${env_file}" \
      "winn3-udp-policy: NFQUEUE can match UDP ${want}"
  done

  # Default port through the firewall build, restore form, and the unpatched
  # kernel layout (queue ahead of a late ACCEPT) rejected.
  run_edge_admission 1 1 1 "${receipt}.winn3" "${env_default}"
  expect_policy pass build-9111 "${receipt}.winn3" "${env_default}"
  # Round EX2 with the gateway enabled: the v3 TCP cover (9111) still queues
  # before its accept, and 443 keeps its early accept.
  ex2_queue_gate "${receipt}.winn3" final
  grep -Fxq -- '-A WINVPN-INPUT -p tcp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass' "${receipt}.winn3"
  awk -v accept="${udp_accept}" '
    $0 == accept { next }
    $0 == "-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0" {
      print "-A WINVPN-INPUT -p udp -m udp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0"
    }
    $0 == "-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT" { print accept }
    { print }' "${kernel}" > "${fx}/unpatched-layout.rules"
  [[ "$(grep -c -- '--dport 9111' "${fx}/unpatched-layout.rules")" == 4 ]]
  expect_policy fail unpatched-layout "${fx}/unpatched-layout.rules" "${env_default}" \
    'winn3-udp-policy: NFQUEUE can match UDP 9111'

  # The listener file cannot clobber the script: its extra assignments stay in
  # the resolver's subshell, so admission and the port are still the caller's.
  run_edge_admission 1 1 1 "${receipt}.winn3-clobber" "${fx}/gateway-clobber.env"
  grep -Fxq -- '-A WINVPN-INPUT -p udp --dport 9111 -j ACCEPT' "${receipt}.winn3-clobber"
  grep -Fxq -- '-A WINVPN-INPUT -p tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass' \
    "${receipt}.winn3-clobber"
  # Round SU fail-open: no production queue rule without --queue-bypass.
  if grep -E -- '-j NFQUEUE --queue-num 0$' "${receipt}.winn3-clobber"; then
    echo 'data final admission emitted a fail-closed queue rule (no --queue-bypass)' >&2
    return 1
  fi
  expect_policy pass clobber "${receipt}.winn3-clobber" "${fx}/gateway-clobber.env"

  # Absent file: gateway disabled, no v3 rules, and the default port must
  # still never be queued.
  run_edge_admission 1 1 1 "${receipt}.winn3-absent" "${fx}/absent.env"
  [[ "$(grep -c -- '9111' "${receipt}.winn3-absent")" == 0 ]]
  expect_policy pass absent "${receipt}.winn3-absent" "${fx}/absent.env"
  mutate absent-queued "${guard_serving}" '-A WINVPN-INPUT -p udp -m udp --dport 9111 -j NFQUEUE --queue-num 0'
  expect_policy fail absent-queued "${fx}/absent-queued.rules" "${fx}/absent.env" \
    'winn3-udp-policy: NFQUEUE can match UDP 9111'

  # Unsafe listener files are refused by both the build and the check.
  for name in symlink owner mode; do
    env_file="${fx}/gateway-${name}.env"
    if run_edge_admission 1 1 1 "${receipt}.winn3-${name}" "${env_file}" > "${fx}/build-${name}.log" 2>&1; then
      echo "data edge firewall accepted an unsafe Winn v3 gateway env (${name})" >&2
      return 1
    fi
    grep -Fq 'must be a root-owned regular 0600 file' "${fx}/build-${name}.log"
    [[ ! -e "${receipt}.winn3-${name}" ]]
    expect_policy fail "unsafe-${name}" "${kernel}" "${env_file}" 'must be a root-owned regular 0600 file'
  done

  # Bootstrap with the gateway: UDP accepted, nothing queued, check passes.
  run_edge_admission 0 0 0 "${receipt}.winn3-bootstrap" "${env_default}"
  grep -Fxq -- '-A WINVPN-INPUT -p udp --dport 9111 -j ACCEPT' "${receipt}.winn3-bootstrap"
  if grep -Fq -- '--queue-num 0' "${receipt}.winn3-bootstrap"; then
    echo 'data bootstrap admission queued Winn v3 traffic before Suricata readiness' >&2
    return 1
  fi
  expect_policy pass bootstrap "${receipt}.winn3-bootstrap" "${env_default}"

  # Failed readiness with the gateway enabled leaves the prior firewall as is.
  cp "${receipt}.winn3" "${receipt}.winn3.before-failed-readiness"
  if run_edge_admission 1 1 0 "${receipt}.winn3" "${env_default}"; then
    echo 'data final admission with the Winn v3 gateway ignored failed Suricata readiness' >&2
    return 1
  fi
  cmp -s "${receipt}.winn3" "${receipt}.winn3.before-failed-readiness"

  # Postflight runs this exact check as the next command after its final rebuild.
  # One awk reads the file itself: a `sed | awk '{...; exit}'` pipeline let awk
  # exit while sed was still writing, and under pipefail sed's SIGPIPE (141)
  # failed this section in about 3 runs of 4.
  local postflight_tail
  postflight_tail="$(awk '
    !in_function && $0 == "postflight_data_plane() {" {in_function = 1}
    !in_function {next}
    armed && $0 !~ /^  #/ {print; exit}
    $0 == "  /usr/local/bin/wins-edge-hardening" {armed = 1}
    $0 == "}" {exit}
  ' "${DATA_SCRIPT}")"
  [[ "${postflight_tail}" == '  /usr/local/bin/wins-edge-hardening --check-winn3-udp-policy || {' ]] || {
    echo 'data postflight does not run --check-winn3-udp-policy right after its final rebuild' >&2
    return 1
  }
  echo "PASS Winn v3 gateway UDP is accepted behind both guards and never queued: one resolver, one rule parser, kernel and restore forms, negation, ranges, unsafe files, and gateway-enabled failed readiness"
}

# Round G follow-up OI-G3.3: the Winn v3 gateway boot unit
# (/usr/local/sbin/winn3-gateway-firewall, generated by the gateway installer)
# used to `iptables -I` its 9111 ACCEPTs at position 1 of WINVPN-INPUT, above
# both guard jumps; all 8 production gateways were found that way. Every case
# runs the generated helper itself against real iptables in a private network
# namespace, with the data plane's own --check-winn3-udp-policy (Round G's one
# resolver and one parser) as its acceptance gate.
test_winn3_gateway_boot_firewall_runtime() {
  local fx="${work_dir}/winn3-boot-firewall" helper edge old_edge real_iptables name
  local recovery='-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY'
  local serving='-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING'
  local loopback='-A WINVPN-INPUT -i lo -j ACCEPT'
  local udp_accept='-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT'
  local tcp_accept='-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT'
  [[ "$(id -u)" == 0 ]] || {
    echo 'Winn v3 gateway boot firewall checks need root for a private netns and a root-owned env file' >&2
    return 1
  }
  for name in iptables iptables-save iptables-restore nsenter timeout; do
    command -v "${name}" >/dev/null 2>&1 || {
      echo "Winn v3 gateway boot firewall checks need ${name}" >&2
      return 1
    }
  done
  real_iptables="$(command -v iptables)"
  install -d -m 755 "${fx}" "${fx}/snapbin"
  helper="${fx}/winn3-gateway-firewall"
  # Slice S6: the boot helper lives in the data-plane installer's gateway block
  # (design v17 2.2); the standalone installer is a tombstone.
  extract_heredoc "${DATA_SCRIPT}" "cat <<'EOF' # the boot helper: /usr/local/sbin/winn3-gateway-firewall" EOF > "${helper}"
  [[ -s "${helper}" ]]
  bash -n "${helper}"
  chmod 700 "${helper}"
  edge="${fx}/wins-edge-hardening"
  extract_edge_hardening "${DATA_SCRIPT}" "${edge}"
  chmod 700 "${edge}"
  # A data-plane script without the check mode must never be run: an old
  # wins-edge-hardening treats any argument as a full firewall rebuild.
  old_edge="${fx}/old-wins-edge-hardening"
  printf '#!/usr/bin/env bash\ntouch %q\n' "${fx}/old-edge-executed" > "${old_edge}"
  chmod 700 "${old_edge}"
  printf 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n' > "${fx}/gateway.env"
  chown 0:0 "${fx}/gateway.env"
  chmod 600 "${fx}/gateway.env"
  # Records WINVPN-INPUT after every insert and delete, so a window in which
  # either v3 ACCEPT is missing is visible, and logs every mutating call. With
  # WINN3_BOOT_FAULT=OP:PROTO (-I:udp, -I:tcp, -D:tcp or -D:udp) a matching
  # WINVPN-INPUT call fails without reaching the kernel; OP:PROTO:silent makes
  # it report success without reaching the kernel.
  cat > "${fx}/snapbin/iptables" <<EOF
#!/usr/bin/env bash
rc=0
case " \$* " in
  *" -I WINVPN-INPUT "*|*" -D WINVPN-INPUT "*)
    printf '%s\\n' "\$*" >> "\${WINN3_BOOT_CALLS:?}"
    fault_rest="\${WINN3_BOOT_FAULT#*:}"
    if [[ -n "\${WINN3_BOOT_FAULT:-}" && " \$* " == *" \${WINN3_BOOT_FAULT%%:*} WINVPN-INPUT "* \\
        && " \$* " == *" -p \${fault_rest%%:*} "* ]]; then
      if [[ "\${fault_rest}" == *:silent ]]; then
        echo "injected silent no-op: \$*" >&2
        exit 0
      fi
      echo "injected failure: \$*" >&2
      exit 1
    fi ;;
esac
$(printf '%q' "${real_iptables}") "\$@" || rc=\$?
case " \$* " in
  *" -I WINVPN-INPUT "*|*" -D WINVPN-INPUT "*)
    { $(printf '%q' "${real_iptables}") -w 10 -S WINVPN-INPUT; echo --; } >> "\${WINN3_BOOT_SNAPSHOTS:?}" ;;
esac
exit "\${rc}"
EOF
  chmod 700 "${fx}/snapbin/iptables"

  # boot_fixture NAME [absent]: WINVPN-INPUT rule lines (iptables -S form) on
  # stdin become an iptables-restore file with empty guard chains; `absent`
  # declares no WINVPN-INPUT and puts the lines in INPUT instead.
  boot_fixture() {
    local chain_decl=':WINVPN-INPUT - [0:0]' input_jump='-A INPUT -j WINVPN-INPUT' body
    body="$(cat)"
    if [[ "${2:-}" == absent ]]; then
      chain_decl=""
      input_jump=""
    fi
    {
      printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT ACCEPT [0:0]' \
        ':WINVPN-SSH-RECOVERY - [0:0]' ':WINVPN-LOCAL-SERVING - [0:0]' \
        ':WINVPN-NFQ-PROBE - [0:0]' ':WINVPN-CF-STEALTH - [0:0]'
      [[ -z "${chain_decl}" ]] || printf '%s\n' "${chain_decl}"
      [[ -z "${input_jump}" ]] || printf '%s\n' "${input_jump}"
      [[ -z "${body}" ]] || printf '%s\n' "${body}"
      printf '%s\n' 'COMMIT'
    } > "${fx}/$1.restore"
  }
  # run_boot NAME [EDGE] [FAULT]: loads NAME.restore into a fresh netns and
  # runs the helper twice there (FAULT injected into the first run only),
  # keeping each run's exit code, log, mutating calls and ruleset, and the
  # guard chains before and after each run.
  run_boot() {
    local name="$1" edge_path="${2:-${edge}}" fault="${3:-}"
    : > "${fx}/${name}.snapshots"
    unshare -n bash -c '
      set -u
      fx="$1" name="$2" helper="$3" edge_path="$4" fault="$5"
      save() { iptables-save | grep -v "^#" > "$1"; }
      guards() { iptables -S INPUT; iptables -S WINVPN-SSH-RECOVERY; iptables -S WINVPN-LOCAL-SERVING; }
      iptables-restore < "${fx}/${name}.restore" || exit 90
      save "${fx}/${name}.before"
      guards > "${fx}/${name}.guards0"
      for run in 1 2; do
        rc=0
        : > "${fx}/${name}.calls${run}"
        PATH="${fx}/snapbin:${PATH}" WINN3_BOOT_SNAPSHOTS="${fx}/${name}.snapshots" \
          WINN3_BOOT_CALLS="${fx}/${name}.calls${run}" WINN3_BOOT_FAULT="${fault}" \
          WINN3_GATEWAY_ENV_FILE="${fx}/gateway.env" WINN3_GATEWAY_EDGE_HARDENING="${edge_path}" \
          WINS_FIREWALL_LOCK="${fx}/wins-firewall.lock" \
          NODE_ENV_FILE="${fx}/missing-node.env" \
          PUBLIC_VPN_INGRESS_ADMISSION_FILE="${fx}/missing-admission.env" \
          bash "${helper}" > "${fx}/${name}.log${run}" 2>&1 || rc=$?
        fault=""
        echo "${rc}" > "${fx}/${name}.rc${run}"
        save "${fx}/${name}.after${run}"
        { iptables -S WINVPN-INPUT 2>/dev/null || true; } > "${fx}/${name}.chain${run}"
        iptables -S INPUT > "${fx}/${name}.input${run}"
        guards > "${fx}/${name}.guards${run}"
      done
    ' _ "${fx}" "${name}" "${helper}" "${edge_path}" "${fault}" || {
      echo "Winn v3 gateway boot firewall case ${name} could not be loaded into a netns" >&2
      return 1
    }
  }
  # expect_boot_pass NAME EXPECTED-CHAIN-FILE: both runs exit 0, the chain is
  # exactly the expected one, the second run changes nothing, and the Round G
  # checker ran and held.
  expect_boot_pass() {
    local name="$1" expected="$2"
    if [[ "$(cat "${fx}/${name}.rc1")" != 0 || "$(cat "${fx}/${name}.rc2")" != 0 ]]; then
      echo "Winn v3 gateway boot firewall failed on ${name}:" >&2
      cat "${fx}/${name}.log1" "${fx}/${name}.log2" >&2
      return 1
    fi
    diff -u "${expected}" "${fx}/${name}.chain1" >&2 || {
      echo "Winn v3 gateway boot firewall left the wrong WINVPN-INPUT on ${name}" >&2
      return 1
    }
    diff -u "${fx}/${name}.after1" "${fx}/${name}.after2" >&2 || {
      echo "Winn v3 gateway boot firewall is not idempotent on ${name}" >&2
      return 1
    }
    grep -Fq 'Winn v3 UDP 9111 policy holds (gateway enabled=1).' "${fx}/${name}.log1" || {
      echo "Winn v3 gateway boot firewall did not run the data plane's Round G check on ${name}" >&2
      cat "${fx}/${name}.log1" >&2
      return 1
    }
  }
  # expect_boot_refusal NAME REASON: nonzero, the named reason, and not one
  # rule changed.
  expect_boot_refusal() {
    local name="$1" reason="$2"
    if [[ "$(cat "${fx}/${name}.rc1")" == 0 ]]; then
      echo "Winn v3 gateway boot firewall accepted ${name}" >&2
      cat "${fx}/${name}.chain1" >&2
      return 1
    fi
    grep -Fq -- "${reason}" "${fx}/${name}.log1" || {
      echo "Winn v3 gateway boot firewall refused ${name} for the wrong reason (want: ${reason}):" >&2
      cat "${fx}/${name}.log1" >&2
      return 1
    }
    diff -u "${fx}/${name}.before" "${fx}/${name}.after1" >&2 || {
      echo "Winn v3 gateway boot firewall changed rules while refusing ${name}" >&2
      return 1
    }
  }

  # 1. The live UK layout, verbatim (read-only capture, 2026-09-23): both
  #    9111 ACCEPTs above the guards. They move behind them, UDP right after
  #    loopback and TCP right ahead of the final DROP.
  boot_fixture live-uk <<'EOF'
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY
-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING
-A WINVPN-INPUT -i lo -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -j ACCEPT
-A WINVPN-INPUT -j DROP
EOF
  cat > "${fx}/live-uk.expected" <<'EOF'
-N WINVPN-INPUT
-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY
-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING
-A WINVPN-INPUT -i lo -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -j DROP
EOF
  run_boot live-uk
  expect_boot_pass live-uk "${fx}/live-uk.expected"
  # The copy behind the guards is inserted before the one above is deleted:
  # after every mutation both v3 ACCEPTs still exist, so the repair never
  # opens a window with no accept.
  [[ -s "${fx}/live-uk.snapshots" ]]
  awk -v udp="${udp_accept}" -v tcp="${tcp_accept}" '
    $0 == "--" { if (!(u && t)) bad = 1; blocks++; u = t = 0; next }
    $0 == udp { u = 1 } $0 == tcp { t = 1 }
    END { exit (bad || blocks != 4) }' "${fx}/live-uk.snapshots" || {
    echo 'Winn v3 gateway boot firewall repair left a moment without both 9111 ACCEPTs, or did not make exactly four mutations:' >&2
    cat "${fx}/live-uk.snapshots" >&2
    return 1
  }
  grep -Fq 'removing the udp 9111 ACCEPT that sat above the guard jumps' "${fx}/live-uk.log1"
  grep -Fq 'removing the tcp 9111 ACCEPT that sat above the guard jumps' "${fx}/live-uk.log1"

  # 2. A correct Round G layout (the installer's own kernel dump): untouched.
  boot_fixture round-g <<'EOF'
-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY
-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING
-A WINVPN-INPUT -i lo -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0
-A WINVPN-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A WINVPN-INPUT -i awg0 -p tcp -m tcp --dport 8080 -j DROP
-A WINVPN-INPUT -i awg0 -p udp -m udp --dport 53 -j ACCEPT
-A WINVPN-INPUT -i awg0 -p tcp -m tcp --dport 53 -j ACCEPT
-A WINVPN-INPUT -i awg0 -p tcp -m multiport --dports 853,8853 -j REJECT --reject-with tcp-reset
-A WINVPN-INPUT -i awg0 -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp-port-unreachable
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 8080 -j DROP
-A WINVPN-INPUT -p icmp -m icmp --icmp-type 8 -j DROP
-A WINVPN-INPUT -p udp -m udp --dport 6881:6889 -j DROP
-A WINVPN-INPUT -p tcp -m tcp --dport 6881:6889 -j DROP
-A WINVPN-INPUT -p tcp -m tcp --dport 6969 -j DROP
-A WINVPN-INPUT -j DROP
EOF
  { echo '-N WINVPN-INPUT'; grep '^-A WINVPN-INPUT ' "${fx}/round-g.restore"; } > "${fx}/round-g.expected"
  run_boot round-g
  expect_boot_pass round-g "${fx}/round-g.expected"
  diff -u "${fx}/round-g.before" "${fx}/round-g.after1" >&2
  [[ ! -s "${fx}/round-g.snapshots" ]]

  # 2b. The same layout built before this gateway's env file existed (no 9111
  #     rules): UDP lands right behind loopback, TCP right ahead of the final
  #     DROP, after the NFQUEUE block and every port-specific DROP.
  grep -vF -- '--dport 9111 ' "${fx}/round-g.restore" | grep '^-A WINVPN-INPUT ' | boot_fixture round-g-no-v3
  awk -v udp="${udp_accept}" -v tcp="${tcp_accept}" '
    $0 == "-A WINVPN-INPUT -j DROP" { print tcp }
    { print }
    $0 == "-A WINVPN-INPUT -i lo -j ACCEPT" { print udp }' \
    <(echo '-N WINVPN-INPUT'; grep '^-A WINVPN-INPUT ' "${fx}/round-g-no-v3.restore") > "${fx}/round-g-no-v3.expected"
  run_boot round-g-no-v3
  expect_boot_pass round-g-no-v3 "${fx}/round-g-no-v3.expected"

  # 3. An empty chain, and 4. a chain missing the guards: no safe place, so
  #    refuse and change nothing.
  : | boot_fixture empty
  run_boot empty
  expect_boot_refusal empty 'WINVPN-INPUT does not start with -j WINVPN-SSH-RECOVERY'
  grep -v -e "^${recovery}\$" -e "^${serving}\$" "${fx}/live-uk.restore" | grep '^-A WINVPN-INPUT ' | boot_fixture no-guards
  [[ "$(grep -c -e 'WINVPN-SSH-RECOVERY$' -e 'WINVPN-LOCAL-SERVING$' "${fx}/no-guards.restore" || true)" == 0 ]]
  run_boot no-guards
  expect_boot_refusal no-guards 'WINVPN-INPUT does not start with -j WINVPN-SSH-RECOVERY'
  # A foreign rule above the guards (the canada shape) is not this unit's to
  # move, and a chain that does not end in DROP has no TCP place.
  { echo '-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT'; grep '^-A WINVPN-INPUT ' "${fx}/live-uk.restore"; } | boot_fixture foreign-above
  run_boot foreign-above
  expect_boot_refusal foreign-above 'WINVPN-INPUT does not start with -j WINVPN-SSH-RECOVERY'
  printf '%s\n' "${recovery}" "${serving}" "${loopback}" | boot_fixture no-final-drop
  run_boot no-final-drop
  expect_boot_refusal no-final-drop 'WINVPN-INPUT does not end with -j DROP'
  # The chain absent: a standalone host keeps its INPUT behaviour; a host whose
  # INPUT already jumps to a guard chain is a half-built data plane.
  : | boot_fixture absent absent
  run_boot absent
  [[ "$(cat "${fx}/absent.rc1")" == 0 && "$(cat "${fx}/absent.rc2")" == 0 ]]
  printf '%s\n' '-P INPUT DROP' '-A INPUT -p tcp -m tcp --dport 9111 -j ACCEPT' \
    '-A INPUT -p udp -m udp --dport 9111 -j ACCEPT' | diff -u - "${fx}/absent.input1" >&2
  diff -u "${fx}/absent.after1" "${fx}/absent.after2" >&2
  echo '-A INPUT -j WINVPN-SSH-RECOVERY' | boot_fixture absent-guarded absent
  run_boot absent-guarded
  expect_boot_refusal absent-guarded 'INPUT jumps to a data-plane guard chain but WINVPN-INPUT does not exist'

  # The Round G checker is consulted, not decorative: a stale pre-G UDP 9111
  # queue rule later in the chain fails the unit loudly.
  awk '{ print } $0 == "-A WINVPN-INPUT -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0" {
      print "-A WINVPN-INPUT -p udp -m udp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0" }' \
    <(grep '^-A WINVPN-INPUT ' "${fx}/round-g.restore") | boot_fixture stale-queue
  run_boot stale-queue
  [[ "$(cat "${fx}/stale-queue.rc1")" != 0 ]]
  grep -Fq 'winn3-udp-policy: NFQUEUE can match UDP 9111' "${fx}/stale-queue.log1"
  grep -Fq -- '--check-winn3-udp-policy rejects WINVPN-INPUT' "${fx}/stale-queue.log1"
  # ...and a data-plane script without the check mode is never executed.
  cp "${fx}/live-uk.restore" "${fx}/old-edge.restore"
  run_boot old-edge "${old_edge}"
  [[ "$(cat "${fx}/old-edge.rc1")" == 0 ]]
  diff -u "${fx}/live-uk.expected" "${fx}/old-edge.chain1" >&2
  [[ ! -e "${fx}/old-edge-executed" ]] || {
    echo 'Winn v3 gateway boot firewall ran a wins-edge-hardening that has no check mode (a full rebuild)' >&2
    return 1
  }
  grep -Fq 'has no --check-winn3-udp-policy; only the guard-order check above ran.' "${fx}/old-edge.log1"

  # Lane L76: the layouts the certified data plane builds. Round SU puts the
  # queue watchdog's probe jump between the guards and the loopback ACCEPT on
  # every admitted node; Round EX2 adds a TCP 443 ACCEPT at position 7 where
  # 443 is an admitted stealth port. The helper used to refuse both (lane L75,
  # France). First the four live chains, read-only captures of 2026-09-26:
  # each is already correct, so both runs change nothing and Round G holds.
  local su_layouts="${ROOT_DIR}/server/testdata/winn3_gateway_winvpn_input" su_node
  local su_probe='-A WINVPN-INPUT -i lo -p tcp -m tcp --dport 9199 -j WINVPN-NFQ-PROBE'
  for su_node in uk germany canada france; do
    [[ "$(sed -n 3p "${su_layouts}/${su_node}")" == "${su_probe}" ]]
    boot_fixture "su-live-${su_node}" < "${su_layouts}/${su_node}"
    { echo '-N WINVPN-INPUT'; cat "${su_layouts}/${su_node}"; } > "${fx}/su-live-${su_node}.expected"
    run_boot "su-live-${su_node}"
    expect_boot_pass "su-live-${su_node}" "${fx}/su-live-${su_node}.expected"
    diff -u "${fx}/su-live-${su_node}.before" "${fx}/su-live-${su_node}.after1" >&2
    [[ ! -s "${fx}/su-live-${su_node}.snapshots" ]]
  done
  [[ "$(sed -n 7p "${su_layouts}/canada")" == '-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT' ]]
  # The same chains without their 9111 rules: UDP lands right behind the
  # loopback ACCEPT (position 5, behind the probe), TCP right ahead of DROP.
  for su_node in uk canada; do
    grep -vF -e '--dport 9111 ' "${su_layouts}/${su_node}" | boot_fixture "su-fresh-${su_node}"
    awk -v udp="${udp_accept}" -v tcp="${tcp_accept}" '
      $0 == "-A WINVPN-INPUT -j DROP" { print tcp }
      { print }
      $0 == "-A WINVPN-INPUT -i lo -j ACCEPT" { print udp }' \
      <(echo '-N WINVPN-INPUT'; grep '^-A WINVPN-INPUT ' "${fx}/su-fresh-${su_node}.restore") > "${fx}/su-fresh-${su_node}.expected"
    [[ "$(sed -n 6p "${fx}/su-fresh-${su_node}.expected")" == "${udp_accept}" ]]
    run_boot "su-fresh-${su_node}"
    expect_boot_pass "su-fresh-${su_node}" "${fx}/su-fresh-${su_node}.expected"
    grep -Fq 'accepting UDP 9111 at WINVPN-INPUT position 5, right behind -i lo -j ACCEPT' "${fx}/su-fresh-${su_node}.log1"
  done
  # The probe anywhere else in the head, in any other form, or any other rule
  # in slot 3 is refused unchanged.
  local su_body su_rule su_i=0
  su_body="$(sed -n '5,$p' "${su_layouts}/uk")"
  for su_rule in \
      "${su_probe}|${recovery}|${serving}|${loopback}" \
      "${recovery}|${su_probe}|${serving}|${loopback}" \
      "${recovery}|${serving}|${su_probe}|${su_probe}|${loopback}" \
      "${recovery}|${serving}|-A WINVPN-INPUT -i lo -p tcp -m tcp --dport 9198 -j WINVPN-NFQ-PROBE|${loopback}" \
      "${recovery}|${serving}|-A WINVPN-INPUT -p tcp -m tcp --dport 9199 -j WINVPN-NFQ-PROBE|${loopback}" \
      "${recovery}|${serving}|-A WINVPN-INPUT -i lo -p tcp -m tcp --dport 9199 -j WINVPN-CF-STEALTH|${loopback}" \
      "${recovery}|${serving}|-A WINVPN-INPUT -p tcp -m tcp --dport 22 -j ACCEPT|${loopback}" \
      "${recovery}|${serving}|-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT|${loopback}"; do
    su_i=$((su_i + 1))
    { tr '|' '\n' <<<"${su_rule}"; printf '%s\n' "${su_body}"; } | boot_fixture "su-refuse-${su_i}"
    run_boot "su-refuse-${su_i}"
    expect_boot_refusal "su-refuse-${su_i}" 'WINVPN-INPUT does not start with -j WINVPN-SSH-RECOVERY'
  done
  # End to end: the chain the data-plane installer itself generates. The
  # generated wins-edge-hardening's apply_firewall runs with stubbed tools
  # (as in test_public_ingress_admission_runtime) and hands its filter table
  # to a fake iptables-restore; that table is then loaded into the netns with
  # the real one, and the helper runs against it. With the gateway env file
  # the build already accepts v3, so nothing may change; without it (a data
  # plane built before the gateway) the helper adds UDP right behind the
  # loopback ACCEPT and TCP ahead of the final DROP. Variants: EX2 443 early
  # ACCEPT on (the default), Cloudflare-only, and 443 not a stealth port.
  local su_gen="${fx}/su-gen" su_variant su_env
  local -a su_vars=()
  install -d -m 700 "${su_gen}" "${su_gen}/bin"
  sed '/^apply_rps$/,$d' "${edge}" > "${su_gen}/edge-probe"
  printf '%s\n' '#!/usr/bin/env bash' '[[ "$*" == *"route show default"* ]] && echo "default via 192.0.2.1 dev eth0"' 'exit 0' > "${su_gen}/bin/ip"
  write_edge_output_chain_stubs "${su_gen}/bin"
  printf '%s\n' '#!/usr/bin/env bash' "printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT ACCEPT [0:0]' COMMIT" > "${su_gen}/bin/iptables-save"
  printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' 'payload="$(cat)"' '[[ " $* " != *" --test "* ]] || exit 0' \
    'printf "%s\n" "${payload}" > "${SU_GEN_RECEIPT:?}"' '"${0%/*}/edge-output-chain-apply" "$@" <<<"${payload}"' > "${su_gen}/bin/iptables-restore"
  printf '%s\n' '#!/usr/bin/env bash' '[[ "${1:-}" == show ]] && echo "ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml"' 'exit 0' > "${su_gen}/bin/systemctl"
  printf '%s\n' '#!/usr/bin/env bash' 'echo "NFQ support: yes"' > "${su_gen}/bin/suricata"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "${su_gen}/bin/netfilter-persistent"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "${su_gen}/bin/curl"
  chmod 700 "${su_gen}"/bin/*
  printf '%s\n' '0 0 0 0 0 0 0 0 0' > "${su_gen}/queue0"
  # su_generate NAME GATEWAY-ENV [VAR=VALUE...]: NAME.restore is the generated
  # *filter table with the two guard chains declared (apply_firewall never
  # creates them; their owners do) and DOCKER-USER declared: since IA-DP-12
  # apply_firewall leaves DOCKER-USER out of its restore header (declaring it
  # flushed operator rules) and creates it live with `iptables -N`, which the
  # stubbed iptables here does not carry into the netns. Docker creates it on
  # a real node anyway.
  su_generate() {
    local name="$1" gateway_env="$2"
    shift 2
    (
      set -Eeuo pipefail
      export PATH="${su_gen}/bin:${PATH}" SU_GEN_RECEIPT="${su_gen}/${name}.receipt"
      export EDGE_OUTPUT_CHAIN_STATE="${su_gen}/${name}.output-chain"
      rm -f -- "${EDGE_OUTPUT_CHAIN_STATE}"
      export WINN3_GATEWAY_ENV_FILE="${gateway_env}" WINSVPN_TEST_ROOT="${su_gen}/root"
      export NODE_ENV_FILE="${work_dir}/missing-node.env" PUBLIC_VPN_INGRESS_ADMISSION_FILE="${work_dir}/missing-admission.env"
      export PUBLIC_VPN_INGRESS_ADMISSION=1 INSTALL_DATA_IDS_IPS=1 DATA_NFQUEUE_PROC_PATH="${su_gen}/queue0"
      export IPTABLES_BIN="${su_gen}/bin/iptables" IPTABLES_SAVE_BIN="${su_gen}/bin/iptables-save"
      export IPTABLES_RESTORE_BIN="${su_gen}/bin/iptables-restore" NODE_MANAGEMENT_TUNNEL_ENABLED=1
      export WG_PORT=9110 STEALTH_ORIGIN_PORT=80 STEALTH_TRANSPORTS=80:none,443:tls COMPANION_TCP_PORT=8000
      export ALLOW_PUBLIC_STEALTH_HTTP=1 CLOUDFLARE_ONLY_STEALTH=0 VPN_INTERFACES=awg0
      local su_assignment
      for su_assignment in "$@"; do
        export "${su_assignment?}"
      done
      # shellcheck disable=SC1090,SC1091
      source "${su_gen}/edge-probe"
      apply_firewall
    ) > "${su_gen}/${name}.apply.log" 2>&1 || {
      echo "the data-plane generator failed for ${name}:" >&2
      cat "${su_gen}/${name}.apply.log" >&2
      return 1
    }
    awk '$0 == "*filter" { f = 1 } f { print } f && $0 == "COMMIT" { exit }' "${su_gen}/${name}.receipt" \
      | awk 'NR == 1 { print; print ":WINVPN-SSH-RECOVERY - [0:0]"; print ":WINVPN-LOCAL-SERVING - [0:0]"; print ":DOCKER-USER - [0:0]"; next } { print }' \
      > "${fx}/${name}.restore"
    grep -Fxq -- '-A WINVPN-INPUT -i lo -p tcp --dport 9199 -j WINVPN-NFQ-PROBE' "${fx}/${name}.restore"
  }
  su_env="${su_gen}/gateway.env"
  printf 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n' > "${su_env}"
  chown 0:0 "${su_env}"
  chmod 600 "${su_env}"
  for su_variant in ex2 cf no443; do
    case "${su_variant}" in
      ex2) su_vars=() ;;
      cf) su_vars=(CLOUDFLARE_ONLY_STEALTH=1) ;;
      no443) su_vars=(STEALTH_TRANSPORTS=80:none) ;;
    esac
    su_generate "su-gen-${su_variant}" "${su_env}" "${su_vars[@]}"
    su_generate "su-gen-${su_variant}-nov3" "${su_gen}/missing-gateway.env" "${su_vars[@]}"
    if [[ "${su_variant}" == no443 ]]; then
      [[ "$(grep -c -F -e '--dport 443 ' "${fx}/su-gen-${su_variant}.restore" || true)" == 0 ]]
    else
      grep -Fxq -- '-A WINVPN-INPUT -p tcp --dport 443 -j ACCEPT' "${fx}/su-gen-${su_variant}.restore"
    fi
    # Built with the gateway env file: the chain already carries v3, and the
    # helper changes nothing.
    run_boot "su-gen-${su_variant}"
    [[ "$(cat "${fx}/su-gen-${su_variant}.rc1")" == 0 && "$(cat "${fx}/su-gen-${su_variant}.rc2")" == 0 ]] || {
      echo "Winn v3 gateway boot firewall refused the generated ${su_variant} chain:" >&2
      cat "${fx}/su-gen-${su_variant}.log1" >&2
      return 1
    }
    diff -u "${fx}/su-gen-${su_variant}.before" "${fx}/su-gen-${su_variant}.after2" >&2
    [[ ! -s "${fx}/su-gen-${su_variant}.snapshots" ]]
    [[ "$(sed -n 4p "${fx}/su-gen-${su_variant}.chain1")" == "${su_probe}" ]]
    grep -Fq 'Winn v3 UDP 9111 policy holds (gateway enabled=1).' "${fx}/su-gen-${su_variant}.log1"
    if [[ "${su_variant}" == ex2 ]]; then
      [[ "$(sed -n 8p "${fx}/su-gen-${su_variant}.chain1")" == '-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT' ]]
    fi
    # Built before the gateway env file existed: the helper adds both.
    [[ "$(grep -c -F -e '--dport 9111 ' "${fx}/su-gen-${su_variant}-nov3.restore" || true)" == 0 ]]
    run_boot "su-gen-${su_variant}-nov3"
    { echo '-N WINVPN-INPUT'; grep '^-A WINVPN-INPUT ' "${fx}/su-gen-${su_variant}-nov3.before"; } \
      | awk -v udp="${udp_accept}" -v tcp="${tcp_accept}" '
          $0 == "-A WINVPN-INPUT -j DROP" { print tcp }
          { print }
          $0 == "-A WINVPN-INPUT -i lo -j ACCEPT" { print udp }' > "${fx}/su-gen-${su_variant}-nov3.expected"
    expect_boot_pass "su-gen-${su_variant}-nov3" "${fx}/su-gen-${su_variant}-nov3.expected"
  done
  echo "PASS Winn v3 gateway boot firewall accepts the Round SU probe and Round EX2 443 layouts (four live chains and the data-plane installer's own), refuses every other head, and places v3 behind the probe"

  # Round I (v2) cases. Each is recorded rather than aborting, so a run on an
  # older helper names every case it fails.
  local -a v2_failed=()
  v2_case() {
    local label="$1"
    shift
    "$@" || v2_failed+=("${label}")
  }
  # Existing TCP placements are proven, not just found: an inspection bypass,
  # an unreachable ACCEPT and a missing final DROP are all refused unchanged,
  # even when the UDP ACCEPT would still need inserting.
  v2_refuse() {
    local name="$1" reason="$2"
    shift 2
    printf '%s\n' "${recovery}" "${serving}" "${loopback}" "$@" | boot_fixture "${name}"
    run_boot "${name}" || return 1
    expect_boot_refusal "${name}" "${reason}"
  }
  local tcp_queue='-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0'
  v2_case tcp-bypass v2_refuse tcp-bypass 'a TCP 9111 NFQUEUE sits after the TCP ACCEPT (inspection bypass)' \
    "${udp_accept}" "${tcp_accept}" "${tcp_queue}" '-A WINVPN-INPUT -j DROP'
  v2_case tcp-bypass-no-udp v2_refuse tcp-bypass-no-udp 'a TCP 9111 NFQUEUE sits after the TCP ACCEPT (inspection bypass)' \
    "${tcp_accept}" "${tcp_queue}" '-A WINVPN-INPUT -j DROP'
  # (Round I Turn 2) A commented TCP queue after the ACCEPT is unparsed text
  # that could hide the queue, so it is refused, not read as harmless.
  local tcp_queue_commented='-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -m comment --comment "inspect tcp" -j NFQUEUE --queue-num 0'
  v2_case tcp-bypass-commented v2_refuse tcp-bypass-commented 'a rule behind the UDP 9111 ACCEPT cannot be parsed' \
    "${udp_accept}" "${tcp_accept}" "${tcp_queue_commented}" '-A WINVPN-INPUT -j DROP'
  v2_case tcp-bypass-commented-no-udp v2_refuse tcp-bypass-commented-no-udp 'a rule behind the UDP 9111 ACCEPT cannot be parsed' \
    "${tcp_accept}" "${tcp_queue_commented}" '-A WINVPN-INPUT -j DROP'
  v2_case tcp-unreachable v2_refuse tcp-unreachable 'a rule ahead of the TCP 9111 ACCEPT can stop or divert it' \
    "${udp_accept}" '-A WINVPN-INPUT -j DROP' "${tcp_accept}" '-A WINVPN-INPUT -j DROP'
  v2_case tcp-no-final-drop v2_refuse tcp-no-final-drop 'WINVPN-INPUT does not end with -j DROP' \
    "${udp_accept}" "${tcp_accept}"

  # Fault injection on the live UK layout, with an armed recovery pin and a
  # serving-chain rule: a failed insert issues no delete, a failed delete
  # stops the rest, every failure names the changes already made, the guards
  # and the pin are untouched, a UDP and a TCP 9111 ACCEPT survive, and a clean
  # rerun converges on the repaired layout.
  awk '$0 == "COMMIT" {
      print "-A WINVPN-SSH-RECOVERY -s 10.211.0.2/32 -p tcp -m tcp --dport 22 -j ACCEPT"
      print "-A WINVPN-LOCAL-SERVING -i lo -j RETURN"
    } { print }' "${fx}/live-uk.restore" > "${fx}/fault-base.restore"
  { echo '-N WINVPN-INPUT'; grep '^-A WINVPN-INPUT ' "${fx}/live-uk.restore"; } > "${fx}/fault-original.chain"
  awk -v udp="${udp_accept}" '{ print } $0 == "-A WINVPN-INPUT -i lo -j ACCEPT" { print udp }' \
    "${fx}/fault-original.chain" > "${fx}/fault-udp-inserted.chain"
  { echo '-N WINVPN-INPUT'; printf '%s\n' "${tcp_accept}" "${udp_accept}"; tail -n +2 "${fx}/live-uk.expected"; } \
    > "${fx}/fault-both-inserted.chain"
  { echo '-N WINVPN-INPUT'; printf '%s\n' "${udp_accept}"; tail -n +2 "${fx}/live-uk.expected"; } \
    > "${fx}/fault-tcp-deleted.chain"
  v2_fault() {
    local fault="$1" name="$2" expected="$3" failed="$4" made="$5"
    cp "${fx}/fault-base.restore" "${fx}/${name}.restore"
    run_boot "${name}" "${edge}" "${fault}" || return 1
    if [[ "$(cat "${fx}/${name}.rc1")" == 0 ]]; then
      echo "Winn v3 gateway boot firewall ignored an injected ${fault} failure" >&2
      return 1
    fi
    grep -Fq "injected failure:" "${fx}/${name}.log1" || {
      echo "the ${fault} fault was never injected on ${name}" >&2
      return 1
    }
    diff -u "${expected}" "${fx}/${name}.chain1" >&2 || {
      echo "Winn v3 gateway boot firewall left the wrong chain after an injected ${fault} failure" >&2
      return 1
    }
    grep -Fq "winn3 gateway firewall: ${failed}. Changes already made: ${made}. Nothing further was changed." "${fx}/${name}.log1" || {
      echo "Winn v3 gateway boot firewall misreported the changes made before the ${fault} failure:" >&2
      cat "${fx}/${name}.log1" >&2
      return 1
    }
    if [[ "${fault}" == -I:* ]] && grep -q -- ' -D WINVPN-INPUT ' "${fx}/${name}.calls1"; then
      echo "Winn v3 gateway boot firewall issued a delete after a failed insert (${fault})" >&2
      return 1
    fi
    diff -u "${fx}/${name}.guards0" "${fx}/${name}.guards1" >&2 || {
      echo "Winn v3 gateway boot firewall changed INPUT or a guard chain on ${name}" >&2
      return 1
    }
    grep -Fxq -- "${recovery}" "${fx}/${name}.chain1" && grep -Fxq -- "${serving}" "${fx}/${name}.chain1" \
      && grep -Fxq -- "${udp_accept}" "${fx}/${name}.chain1" && grep -Fxq -- "${tcp_accept}" "${fx}/${name}.chain1" \
      && grep -Fxq -- '-A WINVPN-SSH-RECOVERY -s 10.211.0.2/32 -p tcp -m tcp --dport 22 -j ACCEPT' "${fx}/${name}.guards1" || {
      echo "a guard jump, the recovery pin or a 9111 ACCEPT is gone after the ${fault} failure on ${name}" >&2
      return 1
    }
    [[ "$(cat "${fx}/${name}.rc2")" == 0 ]] && diff -u "${fx}/live-uk.expected" "${fx}/${name}.chain2" >&2 || {
      echo "a clean rerun after the ${fault} failure did not converge on the repaired layout (${name})" >&2
      cat "${fx}/${name}.log2" >&2
      return 1
    }
  }
  # An insert that reports success but changed nothing: the re-read before
  # any delete must catch it, so both originals stay.
  v2_silent() {
    cp "${fx}/fault-base.restore" "${fx}/fault-tcp-silent.restore"
    run_boot fault-tcp-silent "${edge}" -I:tcp:silent || return 1
    [[ "$(cat "${fx}/fault-tcp-silent.rc1")" != 0 ]] \
      && grep -Fq 'injected silent no-op:' "${fx}/fault-tcp-silent.log1" \
      && ! grep -q -- ' -D WINVPN-INPUT ' "${fx}/fault-tcp-silent.calls1" \
      && diff -u "${fx}/fault-udp-inserted.chain" "${fx}/fault-tcp-silent.chain1" >&2 \
      && grep -Fq 'no ACCEPT above the guards was deleted. Changes already made: inserted the UDP 9111 ACCEPT at position 6; inserted the TCP 9111 ACCEPT at position 15.' "${fx}/fault-tcp-silent.log1" \
      && diff -u "${fx}/fault-tcp-silent.guards0" "${fx}/fault-tcp-silent.guards1" >&2 \
      && [[ "$(cat "${fx}/fault-tcp-silent.rc2")" == 0 ]] && diff -u "${fx}/live-uk.expected" "${fx}/fault-tcp-silent.chain2" >&2 || {
      echo "Winn v3 gateway boot firewall deleted or misreported after an insert that did not take:" >&2
      cat "${fx}/fault-tcp-silent.log1" "${fx}/fault-tcp-silent.calls1" >&2
      return 1
    }
  }
  v2_case fault-tcp-insert-silent v2_silent
  v2_case fault-udp-insert v2_fault -I:udp fault-udp-insert "${fx}/fault-original.chain" \
    'inserting the UDP 9111 ACCEPT failed' 'none'
  v2_case fault-tcp-insert v2_fault -I:tcp fault-tcp-insert "${fx}/fault-udp-inserted.chain" \
    'inserting the TCP 9111 ACCEPT failed' 'inserted the UDP 9111 ACCEPT at position 6'
  v2_case fault-tcp-delete v2_fault -D:tcp fault-tcp-delete "${fx}/fault-both-inserted.chain" \
    'deleting the tcp 9111 ACCEPT above the guards failed' \
    'inserted the UDP 9111 ACCEPT at position 6; inserted the TCP 9111 ACCEPT at position 15'
  v2_case fault-udp-delete v2_fault -D:udp fault-udp-delete "${fx}/fault-tcp-deleted.chain" \
    'deleting the udp 9111 ACCEPT above the guards failed' \
    'inserted the UDP 9111 ACCEPT at position 6; inserted the TCP 9111 ACCEPT at position 15; deleted the tcp 9111 ACCEPT above the guards'
  if (( ${#v2_failed[@]} )); then
    echo "Winn v3 gateway boot firewall Round I cases failed: ${v2_failed[*]}" >&2
    return 1
  fi

  test_winn3_gateway_boot_firewall_traffic "${fx}" "${helper}" "${edge}"
  echo "PASS Winn v3 gateway boot firewall never inserts above the WINVPN-INPUT guards: live UK layout repaired in place without an accept gap and idempotently, Round G layout untouched, empty/guardless/foreign/half-built chains refused unchanged, Round G check enforced, old edge script never run; existing TCP placements proven (bypass, commented bypass, unreachable, no final DROP refused unchanged); injected insert/delete failures stop before any further change and are reported"
}

# Real packets on the live UK layout with the local-serving latch engaged and
# the SSH-recovery pin armed: before the repair v3 UDP/TCP 9111 are accepted
# above the latch; after it they reach the latch and are dropped, and pinned
# TCP 22 still gets through the recovery chain.
test_winn3_gateway_boot_firewall_traffic() {
  local fx="$1" helper="$2" edge="$3"
  awk '
    $0 == "COMMIT" {
      print "-A WINVPN-SSH-RECOVERY -s 10.211.0.2/32 -p tcp -m tcp --dport 22 -j ACCEPT"
      print "-A WINVPN-LOCAL-SERVING -i lo -j RETURN"
      print "-A WINVPN-LOCAL-SERVING -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j RETURN"
      print "-A WINVPN-LOCAL-SERVING -j DROP"
    }
    { print }' "${fx}/live-uk.restore" > "${fx}/latched.restore"
  unshare -n bash -c '
    set -Eeuo pipefail
    fx="$1" helper="$2" edge="$3"
    ip link set lo up
    unshare -n sleep 120 &
    client=$!
    trap "kill ${client} 2>/dev/null || true" EXIT
    for _ in $(seq 1 50); do
      [[ "$(readlink /proc/${client}/ns/net 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ]] && break
      sleep 0.1
    done
    ip link add gw0 type veth peer name cl0 netns "${client}"
    ip addr add 10.211.0.1/24 dev gw0
    ip link set gw0 up
    nsenter -t "${client}" -n ip addr add 10.211.0.2/24 dev cl0
    nsenter -t "${client}" -n ip link set cl0 up
    nsenter -t "${client}" -n ip link set lo up
    iptables-restore < "${fx}/latched.restore"
    probe() {
      local i
      for i in 1 2 3; do
        nsenter -t "${client}" -n bash -c "echo probe > /dev/udp/10.211.0.1/9111" || true
      done
      nsenter -t "${client}" -n timeout 2 bash -c ": < /dev/tcp/10.211.0.1/9111" 2>/dev/null || true
      nsenter -t "${client}" -n timeout 2 bash -c ": < /dev/tcp/10.211.0.1/22" 2>/dev/null || true
      iptables-save -c > "$1"
    }
    probe "${fx}/traffic.before"
    iptables -Z
    WINN3_GATEWAY_ENV_FILE="${fx}/gateway.env" WINN3_GATEWAY_EDGE_HARDENING="${edge}" \
      NODE_ENV_FILE="${fx}/missing-node.env" PUBLIC_VPN_INGRESS_ADMISSION_FILE="${fx}/missing-admission.env" \
      bash "${helper}" > "${fx}/traffic.log" 2>&1
    iptables -Z
    probe "${fx}/traffic.after"
  ' _ "${fx}" "${helper}" "${edge}" || {
    echo 'Winn v3 gateway boot firewall traffic check could not run:' >&2
    cat "${fx}/traffic.log" >&2 2>/dev/null || true
    return 1
  }
  # counter FILE RULE: packets counted by the exact rule in an iptables-save -c dump.
  counter() {
    awk -v rule="$2" 'index($0, "] " rule) && substr($0, index($0, "] ") + 2) == rule {
      sub(/^\[/, ""); split($0, c, ":"); print c[1]; found = 1; exit }
      END { if (!found) print "missing" }' "$1"
  }
  local udp_accept='-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT'
  local tcp_accept='-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT'
  local latch_drop='-A WINVPN-LOCAL-SERVING -j DROP'
  local pin='-A WINVPN-SSH-RECOVERY -s 10.211.0.2/32 -p tcp -m tcp --dport 22 -j ACCEPT'
  local before_udp before_tcp before_latch before_pin after_udp after_tcp after_latch after_pin
  before_udp="$(counter "${fx}/traffic.before" "${udp_accept}")"
  before_tcp="$(counter "${fx}/traffic.before" "${tcp_accept}")"
  before_latch="$(counter "${fx}/traffic.before" "${latch_drop}")"
  before_pin="$(counter "${fx}/traffic.before" "${pin}")"
  after_udp="$(counter "${fx}/traffic.after" "${udp_accept}")"
  after_tcp="$(counter "${fx}/traffic.after" "${tcp_accept}")"
  after_latch="$(counter "${fx}/traffic.after" "${latch_drop}")"
  after_pin="$(counter "${fx}/traffic.after" "${pin}")"
  if ! [[ "${before_udp}" == 3 && "${before_tcp}" -ge 1 && "${before_latch}" == 0 && "${before_pin}" -ge 1 \
      && "${after_udp}" == 0 && "${after_tcp}" == 0 && "${after_latch}" -ge 4 && "${after_pin}" -ge 1 ]]; then
    echo "Winn v3 gateway boot firewall traffic: before udp=${before_udp} tcp=${before_tcp} latch=${before_latch} pin=${before_pin}; after udp=${after_udp} tcp=${after_tcp} latch=${after_latch} pin=${after_pin}" >&2
    return 1
  fi
}

# Round H follow-up OI-H4.5, with Round I's provenance rules: the data-plane
# postflight's NFQ check, run against real Suricata 8 daemons under real
# systemd units shaped like the package's suricata.service with the
# installer's `-D --pidfile ... -q 0 -c ...` ExecStart, each in its own
# private network namespace (queue 0 in each). Every rejection must name its
# reason; each case is recorded rather than aborting, so a run against an
# older check names every case it fails.
# Known issue 1 (the 2026-09 fleet fq flow_limit incident): the WAN qdisc does
# not survive a reboot, so wins-edge-queues.service reapplies it at every boot.
# Run the installer's own write_edge_hardening_script on tmpfs in a private
# mount namespace, then the edge script it wrote with --queues-only against a
# dummy default-route device in a private network namespace, and read back
# what the kernel reports.
test_data_edge_queues_boot_reapply() {
  local case_dir="${work_dir}/data-edge-queues"
  local stub_bin="${case_dir}/bin" out="${case_dir}/out" shown
  mkdir -p "${stub_bin}" "${out}"
  cat > "${stub_bin}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${EDGE_QUEUES_SYSTEMCTL_LOG:?}"
EOF
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "${stub_bin}/udevadm"
  chmod 700 "${stub_bin}"/*
  cat > "${case_dir}/write.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
data_script="$1" stub_bin="$2" out="$3"
for dir in /usr/local/bin /usr/local/sbin /etc/systemd/system /etc/udev; do
  [[ -d "${dir}" ]] || { echo "${dir} is missing; it cannot be shadowed for this test" >&2; exit 1; }
  mount -t tmpfs -o mode=0755 tmpfs "${dir}"
done
export WINS_DEFAULTS_FILE="${out}/missing-defaults.env"
export WINS_SECRETS_FILE="${out}/missing-secrets.env"
export NODE_ENV_FILE="${out}/missing-node.env"
# The installer parses "$@" at top level; source it with no arguments.
set --
# shellcheck disable=SC1090
source "${data_script}"
PATH="${stub_bin}:${PATH}"
write_edge_hardening_script
cp /usr/local/bin/wins-edge-hardening /etc/systemd/system/wins-edge-queues.service "${out}/"
EOF
  cat > "${case_dir}/queues.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
edge="$1" node_env="$2"
# A sysfs mounted in this namespace lists only this namespace's devices, so
# the RPS pass cannot touch the host's interfaces.
mount -t sysfs sysfs /sys
ip link set lo up
ip link add wanq0 type dummy
ip addr add 192.0.2.2/24 dev wanq0
ip link set wanq0 up
ip route add default via 192.0.2.1 dev wanq0
# The unit's environment: node.env and nothing else. Only tc's report goes
# to stdout.
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin NODE_ENV_FILE="${node_env}" "${edge}" --queues-only >&2
tc qdisc show dev wanq0 root
EOF
  chmod 700 "${case_dir}/write.sh" "${case_dir}/queues.sh"
  EDGE_QUEUES_SYSTEMCTL_LOG="${out}/systemctl.log" \
    unshare -m bash "${case_dir}/write.sh" "${DATA_SCRIPT}" "${stub_bin}" "${out}"
  # The unit is enabled after it is written, and it is wanted at boot.
  [[ "$(cat "${out}/systemctl.log")" == $'daemon-reload\nenable wins-edge-queues.service' ]]
  grep -Fxq 'ExecStart=/usr/local/bin/wins-edge-hardening --queues-only' "${out}/wins-edge-queues.service"
  awk '/^\[/ {section = $0} section == "[Install]" && $0 == "WantedBy=multi-user.target" {found = 1} END {exit !found}' \
    "${out}/wins-edge-queues.service"
  # The installer writes no qdisc override into node.env, so boot runs the
  # shipped defaults. flow_limit 32768 is the calibrated value (installer
  # comment above apply_wan_qdisc: every Canada measurement ran 32768; 1024
  # and 2048 were measured as drops at the qdisc or the socket, and 100 and
  # 256 clip the single-flow tunnel's send bursts).
  : > "${out}/node.env"
  shown="$(unshare -m -n bash "${case_dir}/queues.sh" "${out}/wins-edge-hardening" "${out}/node.env")"
  [[ "${shown}" == 'qdisc fq '* && "${shown}" == *' flow_limit 32768p '* ]] || {
    echo "boot-time WAN qdisc is not the calibrated fq flow_limit 32768: ${shown:-none}" >&2
    return 1
  }
  echo "PASS data wins-edge-queues is enabled for boot and reapplies the calibrated WAN fq (flow_limit 32768) from node.env alone"
}

# Round EX2: the installer postflight's per-route canary check. TCP 443 must
# have used its accept above the queue rule and never reached the queue;
# every other route must have been queued and accepted after inspection, and
# none may gain an accept above its queue rule. Runs the installer's own
# wins_inline_route_counters and wins_inline_route_check against a stubbed
# `iptables -S WINVPN-INPUT -v` in the live (kernel) form.
test_inline_route_bypass_postflight() {
  local fx="${work_dir}/ex2-route-postflight" fn out rc
  install -d -m 755 "${fx}/bin"
  for fn in wins_inline_route_counters wins_inline_route_check; do
    awk -v f="${fn}() {" '$0 == f { p = 1 } p { print } p && $0 == "}" { exit }' "${DATA_SCRIPT}" > "${fx}/${fn}.sh"
    [[ -s "${fx}/${fn}.sh" ]] || { echo "installer lacks ${fn}" >&2; return 1; }
  done
  cat > "${fx}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
[[ " $* " == *' -S WINVPN-INPUT -v '* ]] || exit 2
cat "${EX2_ROUTE_FIXTURE:?}"
EOF
  chmod 700 "${fx}/bin/iptables"
  # counters EARLY443 Q80 A80 Q443 A443: a live-form chain with those -c counts.
  counters() {
    cat <<EOF
-N WINVPN-INPUT
-A WINVPN-INPUT -c 9 9 -j WINVPN-SSH-RECOVERY
-A WINVPN-INPUT -i lo -p tcp -m tcp --dport 9199 -c 9 9 -j WINVPN-NFQ-PROBE
-A WINVPN-INPUT -i lo -c 9 9 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -c $1 99 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -c $2 99 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -c $4 99 -j NFQUEUE --queue-num 0 --queue-bypass
-A WINVPN-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -c 9 9 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 80 -c $3 99 -j ACCEPT
-A WINVPN-INPUT -p tcp -m tcp --dport 443 -c $5 99 -j ACCEPT
-A WINVPN-INPUT -c 9 9 -j DROP
EOF
  }
  # route PORT FIXTURE: wins_inline_route_counters output for PORT.
  route() {
    (
      export PATH="${fx}/bin:${PATH}" EX2_ROUTE_FIXTURE="$2"
      source "${fx}/wins_inline_route_counters.sh"
      wins_inline_route_counters "$1"
    )
  }
  # verdict PORT BEFORE-FIXTURE AFTER-FIXTURE BYPASS443: rc of
  # wins_inline_route_check (BYPASS443 = --expects-443-bypass output).
  verdict() {
    (
      err() { printf 'ERR %s\n' "$*" >&2; }
      source "${fx}/wins_inline_route_check.sh"
      wins_inline_route_check "$1" "$(route "$1" "$2")" "$(route "$1" "$3")" "$4"
    )
  }
  counters 5 1 2 0 3 > "${fx}/t0"
  [[ "$(route 443 "${fx}/t0")" == '0 3 5' ]]
  [[ "$(route 80 "${fx}/t0")" == '1 2 0' ]]
  # Healthy EX2 canary: 443 via the early accept only; 80 queued then accepted.
  counters 8 4 5 0 3 > "${fx}/t1"
  verdict 443 "${fx}/t0" "${fx}/t1" 1
  verdict 80 "${fx}/t0" "${fx}/t1" 1
  # 443 queued then accepted after inspection: passes only when the build
  # does not emit the bypass (a config where 443 is not bypassed).
  counters 5 4 5 2 6 > "${fx}/t2"
  verdict 443 "${fx}/t0" "${fx}/t2" 0
  # expect_reject NAME PORT AFTER-FIXTURE BYPASS443 REASON
  expect_reject() {
    rc=0
    out="$(verdict "$2" "${fx}/t0" "$3" "$4" 2>&1)" || rc=$?
    if [[ "${rc}" == 0 ]] || ! grep -Fq -- "$5" <<<"${out}"; then
      echo "EX2 route check accepted ${1} (rc=${rc}): ${out}" >&2
      return 1
    fi
  }
  # The bypass is emitted but the canary took the pre-EX2 path (missing or
  # ineffective bypass): must fail.
  expect_reject 443-pre-ex2-path-with-bypass 443 "${fx}/t2" 1 'the canary did not use it or also reached NFQUEUE'
  counters 8 4 5 1 3 > "${fx}/r1"
  expect_reject 443-bypassed-but-queued 443 "${fx}/r1" 1 'the canary did not use it or also reached NFQUEUE'
  counters 5 1 2 0 3 > "${fx}/r2"
  expect_reject 443-never-reached 443 "${fx}/r2" 1 'the canary did not use it or also reached NFQUEUE'
  expect_reject 443-never-reached-unbypassed 443 "${fx}/r2" 0 'did not pass NFQUEUE and a Suricata verdict'
  # Not emitted, yet 443 accepted above its queue rule: fails.
  expect_reject 443-bypassed-when-not-emitted 443 "${fx}/t1" 0 'accepted above the queue 5->8'
  expect_reject 443-unknown-expectation 443 "${fx}/t1" '' 'unknown TCP 443 bypass expectation'
  counters 5 1 5 0 3 > "${fx}/r3"
  expect_reject 80-not-queued 80 "${fx}/r3" 1 'did not pass NFQUEUE and a Suricata verdict'
  counters 5 4 2 0 3 > "${fx}/r4"
  expect_reject 80-not-accepted-after-inspection 80 "${fx}/r4" 1 'did not pass NFQUEUE and a Suricata verdict'
  # An accept above the 80 queue rule counts as bypassed for 80 and fails it.
  awk '{ print } !done && $0 ~ /^-A WINVPN-INPUT -p tcp -m tcp --dport 443 -c [0-9]+ 99 -j ACCEPT$/ {
    print "-A WINVPN-INPUT -p tcp -m tcp --dport 80 -c 7 99 -j ACCEPT"; done = 1 }' "${fx}/t1" > "${fx}/r5"
  [[ "$(grep -c -- '--dport 80 -c 7 99 -j ACCEPT' "${fx}/r5")" == 1 ]]
  [[ "$(route 80 "${fx}/r5")" == '4 5 7' ]]
  expect_reject 80-accepted-above-queue 80 "${fx}/r5" 1 'accepted above the queue 0->7'
  echo 'PASS postflight route check: 443 bypasses its queue rule and nothing else does'
}

test_data_nfq_postflight_runtime() {
  local fx="${work_dir}/data-nfq-runtime" base_cfg="${work_dir}/data-suricata/suricata.yaml"
  local prefix="${WINSVPN_NFQ_TEST_PREFIX:-winsvpn-nfqtest}-$$"
  local real_suricatasc real_systemctl real_suricata real_journalctl name
  [[ "$(id -u)" == 0 ]] || {
    echo 'Data-plane NFQ runtime checks need root for systemd units, journald and NFQUEUE in a private netns' >&2
    return 1
  }
  for name in suricatasc systemctl systemd-run journalctl ip suricata; do
    command -v "${name}" >/dev/null 2>&1 || {
      echo "Data-plane NFQ runtime checks need ${name}" >&2
      return 1
    }
  done
  # The units below run the real daemon and read its startup log, so this
  # section proves nothing on a Suricata the installer would refuse to deploy
  # (Ubuntu's 7.0.3 instead of the OISF stable package). Say so, not "did not come up".
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    verify_suricata_package
  ) || {
    echo 'ENVIRONMENT: install the OISF stable Suricata (ppa:oisf/suricata-stable) before this section; see verify_suricata_package above.' >&2
    return 1
  }
  real_suricatasc="$(command -v suricatasc)"
  real_systemctl="$(command -v systemctl)"
  real_suricata="$(command -v suricata)"
  real_journalctl="$(command -v journalctl)"
  [[ -s "${base_cfg}" ]]
  install -d -m 755 "${fx}" "${fx}/bin"
  awk '$0 == "verify_data_suricata_nfq_runtime() {" { p = 1 } p { print } p && $0 == "}" { exit }' \
    "${DATA_SCRIPT}" > "${fx}/verify.sh"
  [[ -s "${fx}/verify.sh" ]]
  bash -n "${fx}/verify.sh"
  # Wrappers: `suricata.service` maps to the test unit and a socket-less
  # suricatasc call reaches the configured socket, so a check that hard-codes
  # either still meets the real daemon; `suricata --dump-config` can restart
  # the unit once, mid-verification.
  cat > "${fx}/bin/systemctl" <<EOF
#!/usr/bin/env bash
args=()
for arg in "\$@"; do
  [[ "\${arg}" != suricata.service ]] || arg="\${NFQ_TEST_UNIT:?}"
  args+=("\${arg}")
done
exec $(printf '%q' "${real_systemctl}") "\${args[@]}"
EOF
  cat > "${fx}/bin/suricatasc" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == -c && \$# == 2 ]]; then
  exec $(printf '%q' "${real_suricatasc}") -c "\$2" "\${NFQ_TEST_DEFAULT_SOCKET:?}"
fi
exec $(printf '%q' "${real_suricatasc}") "\$@"
EOF
  cat > "${fx}/bin/suricata" <<EOF
#!/usr/bin/env bash
if [[ -n "\${NFQ_TEST_RESTART_FLAG:-}" && ! -e "\${NFQ_TEST_RESTART_FLAG}" && " \$* " == *" --dump-config "* ]]; then
  : > "\${NFQ_TEST_RESTART_FLAG}"
  $(printf '%q' "${real_systemctl}") restart "\${NFQ_TEST_UNIT:?}" >&2
fi
exec $(printf '%q' "${real_suricata}") "\$@"
EOF
  chmod 700 "${fx}/bin/systemctl" "${fx}/bin/suricatasc" "${fx}/bin/suricata"
  # nfq_variant NAME NFQ-JSON: the installer's config at NAME/suricata.yaml
  # with this nfq value, its log in NAME/ and its own command socket.
  nfq_variant() {
    install -d -m 755 "${fx}/$1"
    python3 - "${base_cfg}" "${fx}/$1/suricata.yaml" "$2" "${fx}/$1" "${fx}/$1/socket" <<'PYEOF'
import json
import sys
from pathlib import Path
import yaml

data = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
data["nfq"] = json.loads(sys.argv[3])
data["default-log-dir"] = sys.argv[4]
data["unix-command"] = {"enabled": True, "filename": sys.argv[5]}
Path(sys.argv[2]).write_text("%YAML 1.1\n---\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PYEOF
  }
  # Owner ruling, incident CS2 / Round SU: data planes fail open, so the
  # healthy nfq mapping carries fail-open: true next to repeat mode and both
  # marks, and the postflight requires it (resolved and loaded config).
  local repeat='{"mode": "repeat", "repeat-mark": 1073741824, "repeat-mask": 1073741824, "fail-open": true}'
  local listed='[{"mode": "repeat", "repeat-mark": 1073741824, "repeat-mask": 1073741824, "fail-open": true}]'
  # accept, wrongmask, nomode and failclosed are read through \${!name} below.
  # shellcheck disable=SC2034
  local accept='{"mode": "accept", "repeat-mark": 1073741824, "repeat-mask": 1073741824, "fail-open": true}'
  local wrongmark='{"mode": "repeat", "repeat-mark": 536870912, "repeat-mask": 536870912, "fail-open": true}'
  # shellcheck disable=SC2034
  local wrongmask='{"mode": "repeat", "repeat-mark": 1073741824, "repeat-mask": 536870912, "fail-open": true}'
  # shellcheck disable=SC2034
  local nomode='{"repeat-mark": 1073741824, "repeat-mask": 1073741824, "fail-open": true}'
  # shellcheck disable=SC2034
  local failclosed='{"mode": "repeat", "repeat-mark": 1073741824, "repeat-mask": 1073741824, "fail-open": false}'
  python3 - "${base_cfg}" <<'PYEOF'
import sys
import yaml

nfq = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))["nfq"]
assert isinstance(nfq, dict), nfq
assert nfq == {"mode": "repeat", "repeat-mark": 0x40000000, "repeat-mask": 0x40000000, "fail-open": True}, nfq
PYEOF
  nfq_variant repeat "${repeat}"
  nfq_variant loaded-list "${listed}"
  nfq_variant loaded-wrongmark "${wrongmark}"
  nfq_variant other "${repeat}"
  (
    units=()
    namespaces=()
    other_pid=""
    cleanup() {
      local unit ns
      for unit in "${units[@]}"; do
        "${real_systemctl}" stop "${unit}" >/dev/null 2>&1 || true
        "${real_systemctl}" reset-failed "${unit}" >/dev/null 2>&1 || true
      done
      [[ -z "${other_pid}" ]] || kill "${other_pid}" 2>/dev/null || true
      for _ in $(seq 1 50); do
        [[ -n "${other_pid}" ]] && kill -0 "${other_pid}" 2>/dev/null || break
        sleep 0.1
      done
      for ns in "${namespaces[@]}"; do
        ip netns del "${ns}" 2>/dev/null || true
      done
    }
    trap cleanup EXIT
    new_netns() {
      ip netns add "$1" && ip -n "$1" link set lo up || return 1
      namespaces+=("$1")
    }
    # start_unit NAME: a transient unit with the package unit's PIDFile=,
    # ProtectSystem=full and ProtectHome=true, and the installer's ExecStart.
    start_unit() {
      local d="${fx}/$1" unit="${prefix}-$1.service" ready=0 inv main
      new_netns "${prefix}-$1" || return 1
      units+=("${unit}")
      rm -f "${d}/suricata.pid"
      "${real_systemctl}" reset-failed "${unit}" >/dev/null 2>&1 || true
      systemd-run --quiet --unit="${unit}" -p PIDFile="${d}/suricata.pid" \
        -p NetworkNamespacePath="/run/netns/${prefix}-$1" -p ProtectSystem=full -p ProtectHome=true \
        -p Restart=on-failure \
        "${real_suricata}" -D --pidfile "${d}/suricata.pid" -q 0 -c "${d}/suricata.yaml" || return 1
      for _ in $(seq 1 160); do
        inv="$("${real_systemctl}" show "${unit}" -p InvocationID --value 2>/dev/null)"
        main="$("${real_systemctl}" show "${unit}" -p MainPID --value 2>/dev/null)"
        if [[ -n "${inv}" && -s "${d}/suricata.pid" && "$(cat "${d}/suricata.pid")" == "${main}" ]] \
            && "${real_suricatasc}" -c uptime "${d}/socket" >/dev/null 2>&1 \
            && grep -Fq 'suricata: Preparing unexpected signal handling' "${d}/suricata.log" 2>/dev/null \
            && grep -Fq 'This is Suricata version' \
              <<<"$("${real_journalctl}" "_SYSTEMD_INVOCATION_ID=${inv}" -o cat --no-pager 2>/dev/null)"; then
          ready=1
          break
        fi
        sleep 0.25
      done
      [[ "${ready}" == 1 ]] || {
        echo "Suricata unit ${unit} did not come up on NFQUEUE 0:" >&2
        "${real_systemctl}" status "${unit}" --no-pager >&2 || true
        cat "${d}/suricata.log" >&2 2>/dev/null || true
        return 1
      }
    }
    set_nfq() {
      python3 - "${fx}/$1/suricata.yaml" "$2" <<'PYEOF'
import json
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["nfq"] = json.loads(sys.argv[2])
path.write_text("%YAML 1.1\n---\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PYEOF
    }
    nfq_failed=()
    # expect_nfq pass|fail LABEL NAME REASON [UNIT]: runs the check on NAME's
    # config against its unit (default: NAME's own unit).
    expect_nfq() {
      local expected="$1" label="$2" cfg_name="$3" reason="$4" unit="${5:-${prefix}-$3.service}" rc=0
      (
        export PATH="${fx}/bin:${PATH}" NFQ_TEST_UNIT="${unit}"
        export NFQ_TEST_DEFAULT_SOCKET="${fx}/${cfg_name}/socket"
        # The installer's certified default (Round SU): fail open, with no
        # operator override, as on a fresh data plane.
        unset SURICATA_NFQUEUE_FAIL_OPEN
        export SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT=1
        err() { printf '%s\n' "$*" >&2; }
        log() { printf '%s\n' "$*"; }
        # shellcheck disable=SC1091
        source "${fx}/verify.sh"
        verify_data_suricata_nfq_runtime "${fx}/${cfg_name}/suricata.yaml" "${unit}"
      ) > "${fx}/${label}.log" 2>&1 || rc=$?
      if [[ "${expected}" == pass ]]; then
        if [[ "${rc}" == 0 ]] && grep -Fq 'Suricata NFQ runs in repeat mode with mark and mask 0x40000000' "${fx}/${label}.log"; then
          return 0
        fi
        echo "data-plane NFQ postflight rejected the healthy repeat-mode daemon (${label}):" >&2
        cat "${fx}/${label}.log" >&2
        nfq_failed+=("${label}")
        return 0
      fi
      if [[ "${rc}" == 0 ]]; then
        echo "data-plane NFQ postflight accepted ${label}" >&2
        nfq_failed+=("${label}")
      elif ! grep -Fq -- "${reason}" "${fx}/${label}.log"; then
        echo "data-plane NFQ postflight rejected ${label} for the wrong reason (want: ${reason}):" >&2
        cat "${fx}/${label}.log" >&2
        nfq_failed+=("${label}")
      fi
      return 0
    }
    start_unit repeat || exit 1
    repeat_log="${fx}/repeat/suricata.log"
    cp "${repeat_log}" "${fx}/repeat-log.saved"
    cp "${fx}/repeat/suricata.yaml" "${fx}/repeat-cfg.saved"
    main="$("${real_systemctl}" show "${prefix}-repeat" -p MainPID --value)"
    parent="$(awk '/ suricata: This is Suricata version / { sub(/^\[/, ""); print $1; exit }' "${repeat_log}")"
    # The generated invocation, as observed: the banner and NFQ line come from
    # the pre-fork parent, and the daemon (MainPID = ExecMainPID) is reparented.
    echo "INFO nfq provenance: $("${real_systemctl}" show "${prefix}-repeat" -p InvocationID -p MainPID -p ExecMainPID -p ExecMainStartTimestamp | tr '\n' ' ')log-parent=${parent} daemon-ppid=$(awk '{ sub(/^.*\) /, ""); print $2 }' "/proc/${main}/stat")"
    [[ "${parent}" =~ ^[0-9]+$ && "${parent}" != "${main}" ]] || nfq_failed+=("daemonized-parent")
    expect_nfq pass healthy repeat ''
    # tamper MODE: edit the running unit's log in place (the inode the daemon
    # appends to), starting from its pristine copy.
    tamper() {
      python3 - "${repeat_log}" "${fx}/repeat-log.saved" "$1" "${parent}" "${main}" <<'PYEOF'
import sys
from pathlib import Path

log, saved, mode, parent, main = sys.argv[1:]
lines = Path(saved).read_text(encoding="utf-8").splitlines()
p, m = f"[{parent} - ", f"[{main} - "
nfq = next(i for i, l in enumerate(lines) if l.startswith(p) and "nfq: NFQ running in " in l)
banner = next(i for i, l in enumerate(lines) if l.startswith(p) and " suricata: This is Suricata version " in l)
first_m = next(i for i, l in enumerate(lines) if l.startswith(m))
stamp = lines[first_m].split("] ", 1)[1][:19]
if mode in ("nfq-standard", "interleaved"):
    lines[nfq] = lines[nfq].split("nfq: ")[0] + "nfq: NFQ running in standard ACCEPT/DROP mode"
elif mode == "nfq-wrongmark":
    lines[nfq] = lines[nfq].replace("mark 1073741824/1073741824", "mark 536870912/536870912")
elif mode == "banner-old":
    head, rest = lines[banner].split("] ", 1)
    lines[banner] = head + "] 2000-01-01 00:00:00" + rest[19:]
elif mode == "parent-pid":
    lines = [l.replace(p, "[1 - ", 1) if l.startswith(p) else l for l in lines]
elif mode == "daemon-pid":
    lines[first_m] = lines[first_m].replace(m, "[1 - ", 1)
if mode in ("interleaved", "later-lines"):
    lines += [
        f"[1 - Suricata-Main] {stamp} Notice: suricata: This is Suricata version 8.0.7 RELEASE running in SYSTEM mode",
        f"[1 - Suricata-Main] {stamp} Info: nfq: NFQ running in "
        + ("REPEAT mode with mark 1073741824/1073741824" if mode == "interleaved" else "standard ACCEPT/DROP mode"),
        f"{m}Suricata-Main] {stamp} Info: unix-manager: later line from the running daemon",
    ]
with open(log, "w", encoding="utf-8") as out:
    out.write("\n".join(lines) + "\n")
PYEOF
    }
    untamper() { cat "${fx}/repeat-log.saved" > "${repeat_log}"; }
    # 1. Resolved configuration: the running daemon keeps its loaded repeat
    #    mode while the file on disk drifts to a list, accept mode (marks still
    #    set), a wrong mark, a wrong mask alone, no mode at all, or fail-open
    #    false (fail closed, against the Round SU ruling).
    for name in listed accept wrongmark wrongmask nomode failclosed; do
      set_nfq repeat "${!name}"
      expect_nfq fail "dump-${name}" repeat 'Suricata does not resolve nfq as a repeat-mode mapping'
      cp "${fx}/repeat-cfg.saved" "${fx}/repeat/suricata.yaml"
    done
    grep -Fq 'nfq.0.mode = repeat' "${fx}/dump-listed.log" || nfq_failed+=("dump-listed-names-list")
    # 3. Startup record: standard mode or a wrong mark on the parent's NFQ
    #    line, a banner older than the invocation, a parent that is not the
    #    journal's, a record not followed by MainPID, and (Round I) an
    #    interleaved later start whose REPEAT line must not count, while the
    #    same kind of later lines after a good start change nothing.
    for mode in nfq-standard nfq-wrongmark banner-old parent-pid daemon-pid interleaved later-lines; do
      case "${mode}" in
        nfq-standard|interleaved) reason="The running Suricata logged 'NFQ running in standard ACCEPT/DROP mode'" ;;
        nfq-wrongmark) reason="The running Suricata logged 'NFQ running in REPEAT mode with mark 536870912/536870912'" ;;
        banner-old) reason='predates' ;;
        parent-pid) reason="No Suricata start banner from the startup parent PID ${parent}" ;;
        daemon-pid) reason='is not followed by' ;;
        later-lines) reason='' ;;
      esac
      tamper "${mode}"
      if [[ "${mode}" == later-lines ]]; then
        expect_nfq pass "log-${mode}" repeat ''
      else
        expect_nfq fail "log-${mode}" repeat "${reason}"
      fi
      untamper
    done
    # 2. Loaded configuration: a daemon started with a list or a wrong mark,
    #    whose file on disk was then corrected, still holds what it loaded.
    start_unit loaded-list || exit 1
    set_nfq loaded-list "${repeat}"
    expect_nfq fail loaded-list loaded-list 'The running Suricata holds nfq.mode = <unset> in its loaded configuration'
    "${real_systemctl}" stop "${prefix}-loaded-list" >/dev/null 2>&1 || true
    start_unit loaded-wrongmark || exit 1
    set_nfq loaded-wrongmark "${repeat}"
    expect_nfq fail loaded-wrongmark loaded-wrongmark 'The running Suricata holds nfq.repeat-mark = 536870912'
    "${real_systemctl}" stop "${prefix}-loaded-wrongmark" >/dev/null 2>&1 || true
    # (Round I) The configured socket path served by another Suricata daemon.
    new_netns "${prefix}-other" || exit 1
    ip netns exec "${prefix}-other" "${real_suricata}" -D --pidfile "${fx}/other/suricata.pid" -q 0 \
      -c "${fx}/other/suricata.yaml" > "${fx}/other/start.out" 2>&1 || exit 1
    for _ in $(seq 1 160); do
      "${real_suricatasc}" -c uptime "${fx}/other/socket" >/dev/null 2>&1 && break
      sleep 0.25
    done
    other_pid="$(cat "${fx}/other/suricata.pid")"
    mv "${fx}/repeat/socket" "${fx}/repeat/socket.saved"
    mv "${fx}/other/socket" "${fx}/repeat/socket"
    expect_nfq fail socket-other repeat "is held by PID ${other_pid}, not MainPID ${main}"
    mv "${fx}/repeat/socket" "${fx}/other/socket"
    mv "${fx}/repeat/socket.saved" "${fx}/repeat/socket"
    expect_nfq pass healthy-again repeat ''
    # Missing identity, and (Round I) a restart during collection.
    expect_nfq fail no-unit repeat 'has no verifiable running identity' "${prefix}-absent.service"
    export NFQ_TEST_RESTART_FLAG="${fx}/restart.flag"
    expect_nfq fail restart repeat 'changed identity during verification'
    unset NFQ_TEST_RESTART_FLAG
    [[ -e "${fx}/restart.flag" ]] || nfq_failed+=("restart-not-injected")
    if (( ${#nfq_failed[@]} )); then
      echo "data-plane NFQ postflight cases failed: ${nfq_failed[*]}" >&2
      exit 1
    fi
  ) || return 1
  echo "PASS data-plane postflight proves Suricata NFQ repeat mode on one unchanged invocation of the running daemon: resolved config, loaded config over a socket whose kernel peer is MainPID, and the startup parent's record (journald _PID) followed by MainPID; list, accept, wrong mark or mask, standard-mode or wrong-mark log, stale banner, foreign parent, missing daemon line, interleaved later start, socket of another daemon, restart during collection and missing unit rejected"
}

test_windows_preseed_cloudflare_access_contract() {
  python3 - "${WINDOWS_PRESEED_SCRIPT}" <<'PYEOF'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
required = (
    "'CLOUDFLARE_TUNNEL_API_TOKEN', 'CLOUDFLARE_ACCESS_API_TOKEN'",
    "'SetCloudflareAccessToken'",
    "function Set-CloudflareAccessToken",
    '"$api/apps?per_page=1"',
    '"$api/service_tokens?per_page=1"',
    "'00000000-0000-0000-0000-000000000000'",
    '"$api/apps/$nonexistentId"',
    '"$api/service_tokens/$nonexistentId"',
    "if ($status -in 401, 403)",
    "if ($status -notin 400, 404, 422)",
    "$values.CLOUDFLARE_ACCESS_API_TOKEN = $token",
    "'CLOUDFLARE_ACCESS_API_TOKEN'))",
)
missing = [needle for needle in required if needle not in source]
if missing:
    raise SystemExit(f"Windows deployment preseed lacks the Cloudflare Access contract: {missing}")

setter = source[
    source.index("function Set-CloudflareAccessToken"):
    source.index("function Set-CloudflareAppCloudToken")
]
if "PostAsync(\"$api/service_tokens\"" in setter or "PostAsync(\"$api/apps\"" in setter:
    raise SystemExit("Cloudflare Access permission validation can create provider resources")
reader = source[
    source.index("function Read-DeploymentSecret"):
    source.index("function Resolve-SshPublicKey")
]
if "finally {" not in reader or "Clear-ClipboardSecret" not in reader:
    raise SystemExit("Central deployment-secret reader does not clear clipboard input")
if ("Read-DeploymentSecret" not in setter or
        "$token = ''" not in setter or
        "Assert-PreseedComplete -Values $values" not in setter):
    raise SystemExit("Cloudflare Access setter does not clear its token or fail closed")
PYEOF
  echo "PASS Windows DPAPI preseed Cloudflare Access least-privilege contract"
}

test_cloudflare_access_service_token_bootstrap() {
  local generated fake_bin api_log runtime_dir env_file legacy_file
  generated="${work_dir}/cloudflare-access-functions.sh"
  python3 - "${CONTROL_SCRIPT}" "${generated}" <<'PYEOF'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("append_runtime_env_kv() {")
end = source.index("\npackage_manager_busy() {", start)
# replace_runtime_env_kv (IA-CP-09) writes through the installer's own
# atomic_replace_file, which is defined elsewhere: extract that one too.
helper_head = "\natomic_replace_file() {\n"
if source.count(helper_head) != 1:
    raise SystemExit("atomic_replace_file() is not defined exactly once in the control installer")
helper_start = source.index(helper_head) + 1
helper = source[helper_start:source.index("\n}\n", helper_start) + 3]
pathlib.Path(sys.argv[2]).write_text(helper + "\n" + source[start:end] + "\n", encoding="utf-8")
PYEOF

  fake_bin="${work_dir}/cloudflare-access-bin"
  runtime_dir="${work_dir}/cloudflare-access-run"
  env_file="${work_dir}/cloudflare-access.env"
  legacy_file="${work_dir}/cloudflare-access-legacy.env"
  api_log="${work_dir}/cloudflare-access-curl.log"
  mkdir -p "${fake_bin}" "${runtime_dir}"
  : > "${env_file}"
  : > "${legacy_file}"
  : > "${api_log}"
  cat > "${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"${WINS_TEST_API_LOG}"
if [[ "$*" == *'?per_page=1000'* ]]; then
  printf '%s\n200\n' '{"success":true,"result":[]}'
elif [[ "$*" == *'/access/service_tokens' ]]; then
  printf '%s\n200\n' '{"success":true,"result":{"id":"12345678-1234-4234-8234-123456789abc","client_id":"unit-test.access","client_secret":"ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"}}'
else
  printf '%s\n500\n' '{"success":false,"errors":[{"message":"unexpected test URL"}]}'
fi
EOF
  chmod 700 "${fake_bin}/curl"

  # shellcheck disable=SC1090
  source "${generated}"
  err() { echo "ERROR $*" >&2; }
  log() { :; }
  ENV_FILE="${env_file}"
  LEGACY_ENV_FILE="${legacy_file}"
  WINS_RUNTIME_DIR="${runtime_dir}"
  WINS_TEST_API_LOG="${api_log}"
  export WINS_TEST_API_LOG
  HIDE_CONTROL_ORIGIN=1
  HIDE_CONTROL_ORIGIN_DEFAULT=1
  REQUIRE_CLOUDFLARE_ACCESS=1
  REQUIRE_CLOUDFLARE_ACCESS_DEFAULT=1
  CLOUDFLARE_TUNNEL_ACCOUNT_ID='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  CLOUDFLARE_TUNNEL_ACCOUNT_ID_DEFAULT=''
  CLOUDFLARE_WINS_ACCOUNT_ID=''
  CLOUDFLARE_ACCESS_API_TOKEN='api-token-must-not-appear-in-process-args'
  CLOUDFLARE_ACCESS_API_TOKEN_DEFAULT=''
  CLOUDFLARE_ACCESS_SERVICE_TOKEN_NAME='winsvpn-management-hub'
  CLOUDFLARE_ACCESS_SERVICE_TOKEN_NAME_DEFAULT='winsvpn-management-hub'
  CLOUDFLARE_ACCESS_SERVICE_TOKEN_DURATION='8760h'
  CLOUDFLARE_ACCESS_SERVICE_TOKEN_DURATION_DEFAULT='8760h'
  CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID=''
  CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID_DEFAULT=''
  TUNNEL_SERVICE_TOKEN_ID=''
  TUNNEL_SERVICE_TOKEN_ID_DEFAULT=''
  TUNNEL_SERVICE_TOKEN_SECRET=''
  TUNNEL_SERVICE_TOKEN_SECRET_DEFAULT=''
  PATH="${fake_bin}:${PATH}" ensure_cloudflare_access_service_token

  grep -Fqx "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID='12345678-1234-4234-8234-123456789abc'" "${env_file}"
  grep -Fqx "TUNNEL_SERVICE_TOKEN_ID='unit-test.access'" "${env_file}"
  grep -Fqx "TUNNEL_SERVICE_TOKEN_SECRET='ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss'" "${env_file}"
  cmp "${env_file}" "${legacy_file}"
  if grep -Fq 'api-token-must-not-appear-in-process-args' "${api_log}"; then
    err "Cloudflare Access API token leaked into curl process arguments"
    return 1
  fi
  if [[ -n "$(find "${runtime_dir}" -type f -print -quit)" ]]; then
    err "Cloudflare Access temporary authorization header was not removed"
    return 1
  fi
  echo "PASS Cloudflare Access service-token one-touch bootstrap and root-only persistence simulation"
}

test_core_management_provider_simulation() {
  python3 - "${CONTROL_SCRIPT}" <<'PYEOF'
import hashlib
import hmac
import ipaddress
import base64
import os
import pathlib
import re
import secrets
import socket
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")

class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail

calls = []
dns_records = {}
tunnel_id = "11111111-2222-4333-8444-555555555555"
access_app_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
service_token_uuid = "99999999-8888-4777-8666-555555555555"
token = "t" * 120

def cloudflare_api_json(method, url, api_token, payload=None):
    calls.append((method, url, api_token, payload))
    if url.endswith("/token"):
        return {"success": True, "result": token}
    if method == "GET" and "dns_records?" in url:
        record_name = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("name", [""])[0]
        record = dns_records.get(record_name)
        return {"success": True, "result": [record] if record else []}
    if method == "GET" and "cfd_tunnel?" in url:
        return {"success": True, "result": []}
    if method == "GET" and "/access/apps?" in url:
        return {"success": True, "result": []}
    if method == "POST" and url.endswith("/cfd_tunnel"):
        return {"success": True, "result": {"id": tunnel_id}}
    if method == "POST" and url.endswith("/dns_records"):
        record = {"id": "dns-record-id", **payload}
        dns_records[payload["name"]] = record
        return {"success": True, "result": record}
    if method == "PUT" and "/dns_records/" in url:
        record = {"id": url.rsplit("/", 1)[-1], **payload}
        dns_records[payload["name"]] = record
        return {"success": True, "result": record}
    if method == "POST" and url.endswith("/access/apps"):
        return {"success": True, "result": {"id": access_app_id, "domain": payload["domain"]}}
    return {"success": True, "result": {}}

def normalize_hostname(value):
    return str(value or "").strip().lower().rstrip(".")

namespace = {
    "hashlib": hashlib,
    "hmac": hmac,
    "re": re,
    "urllib": urllib,
    "HTTPException": HTTPException,
    "RATE_LIMIT_SECRET": "rate-secret-for-test",
    "MANAGEMENT_NAME_HMAC_KEY": "rate-secret-for-test",
    "ADMIN_SECRET_TOKEN": "admin-secret-for-test",
    "NODE_MANAGEMENT_TUNNEL_ZONE_NAME": "winsvpn.com",
    "NODE_MANAGEMENT_TUNNEL_ZONE_ID": "a" * 32,
    "CLOUDFLARE_TUNNEL_ACCOUNT_ID": "b" * 32,
    "CLOUDFLARE_TUNNEL_API_TOKEN": "tunnel-api-token",
    "CLOUDFLARE_WINS_API_TOKEN": "dns-api-token",
    "HIDE_CONTROL_ORIGIN": True,
    "REQUIRE_CLOUDFLARE_ACCESS": True,
    "CLOUDFLARE_ACCESS_API_TOKEN": "access-api-token",
    "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID": service_token_uuid,
    "TUNNEL_SERVICE_TOKEN_ID": "test-client.access",
    "TUNNEL_SERVICE_TOKEN_SECRET": "s" * 64,
    "normalize_hostname": normalize_hostname,
    "cloudflare_api_json": cloudflare_api_json,
}
tunnel_start = source.index("def management_tunnel_hostname(")
tunnel_end = source.index('@app.post("/admin/nodes/bootstrap-management-tunnel")')
# Round CF (lane L41, diff 03) placed the hub edge broker (FastAPI routes,
# pydantic models, os.getenv settings) between ensure_core_management_tunnel
# and this route. The simulation covers only the management-tunnel helpers,
# so the slice ends at the broker's section marker when it is present.
broker_marker = source.find("\n# --- Hub-brokered edge operations", tunnel_start, tunnel_end)
if broker_marker >= 0:
    tunnel_end = broker_marker
tunnel_source = source[tunnel_start:tunnel_end]
for helper in (
    "management_tunnel_hostname", "node_management_hostname", "core_management_hostname",
    "ensure_cloudflare_access_application", "ensure_ssh_management_tunnel",
    "ensure_node_management_tunnel", "ensure_core_management_tunnel",
):
    if f"\ndef {helper}(" not in "\n" + tunnel_source:
        raise SystemExit(f"management-tunnel slice lost {helper}")
if "@app." in tunnel_source or "BaseModel" in tunnel_source:
    raise SystemExit("management-tunnel slice reaches into the hub edge broker")
exec(tunnel_source, namespace)
result = namespace["ensure_core_management_tunnel"]("test-core")
expected_tag = hmac.new(b"rate-secret-for-test", b"core-management:test-core", hashlib.sha256).hexdigest()[:16]
expected_host = f"core-test-core-{expected_tag}.winsvpn.com"
if result != {
    "tunnel_id": tunnel_id,
    "ssh_host": expected_host,
    "tunnel_token": token,
    "access_required": True,
    "access_application_id": access_app_id,
}:
    raise SystemExit(f"unexpected Core tunnel result: {result}")
configuration_calls = [call for call in calls if call[0] == "PUT" and call[1].endswith("/configurations")]
if len(configuration_calls) != 1:
    raise SystemExit(f"expected one tunnel configuration write, got {len(configuration_calls)}")
ingress = configuration_calls[0][3]["config"]["ingress"]
if ingress != [
    {"hostname": expected_host, "service": "ssh://127.0.0.1:22", "originRequest": {"connectTimeout": 10}},
    {"service": "http_status:404"},
]:
    raise SystemExit(f"Core tunnel exposes an unexpected ingress: {ingress}")
dns_writes = [call for call in calls if call[0] == "POST" and "/dns_records" in call[1]]
if len(dns_writes) != 1 or dns_writes[0][3] != {
    "type": "CNAME",
    "name": expected_host,
    "content": f"{tunnel_id}.cfargotunnel.com",
    "ttl": 1,
    "proxied": True,
}:
    raise SystemExit(f"unexpected Core management DNS write: {dns_writes}")
access_writes = [call for call in calls if call[0] == "POST" and call[1].endswith("/access/apps")]
if len(access_writes) != 1:
    raise SystemExit(f"expected one Access application write, got {len(access_writes)}")
access_payload = access_writes[0][3]
if access_payload.get("domain") != expected_host or access_payload.get("type") != "self_hosted":
    raise SystemExit(f"Access application targets the wrong management hostname: {access_payload}")
policies = access_payload.get("policies") or []
if len(policies) != 1 or policies[0].get("decision") != "non_identity" or policies[0].get("include") != [
    {"service_token": {"token_id": service_token_uuid}}
]:
    raise SystemExit(f"Access application is not bound to the dedicated service token: {policies}")

# Re-running the bootstrap must not replace an already-correct proxied CNAME.
# Avoiding a no-op write also avoids transient negative DNS caching while a
# fresh Core waits for the hub to verify the new management route.
namespace["ensure_core_management_tunnel"]("test-core")
dns_mutations = [
    call for call in calls
    if call[0] in {"POST", "PUT"} and "/dns_records" in call[1]
]
if len(dns_mutations) != 1:
    raise SystemExit(f"idempotent Core bootstrap rewrote unchanged DNS: {dns_mutations}")

ssh_namespace = {
    "base64": base64,
    "ipaddress": ipaddress,
    "os": os,
    "Path": Path,
    "re": re,
    "secrets": secrets,
    "MANAGEMENT_KNOWN_HOSTS_LOCK": threading.Lock(),
    "HIDE_CONTROL_ORIGIN": True,
    "REQUIRE_CLOUDFLARE_ACCESS": True,
    "TUNNEL_SERVICE_TOKEN_ID": "test-client.access",
    "TUNNEL_SERVICE_TOKEN_SECRET": "s" * 64,
    "NODE_MANAGEMENT_TUNNEL_ZONE_NAME": "winsvpn.com",
    "normalize_hostname": normalize_hostname,
    # H0 (D3): node_ssh_command refuses this hub's own address by name.
    "socket": socket,
    "IONOS_HUB_IP": "192.0.2.254",
}
known_hosts_dir = tempfile.TemporaryDirectory()
known_hosts_path = Path(known_hosts_dir.name) / "managed_known_hosts"
ssh_namespace["MANAGEMENT_KNOWN_HOSTS_PATH"] = str(known_hosts_path)
# The management SSH helpers, in two slices: the host-key and hub-self-refusal
# helpers up to the H2 signer block, then node_ssh_command and core_ssh_command
# after it. The H2/H3 winn/3 provisioning code between them is not under test
# here and needs the hub's own imports.
ssh_source = (
    source[source.index("def normalized_management_ssh_host_keys("):source.index("# H2: design v17 3.1, 3.5, 3.13, 3.14 and 3.18.")]
    + source[source.index("def node_ssh_command(node_host: str, remote_command: str, connect_timeout"):source.index("def mark_node_management_status(")]
)
exec(ssh_source, ssh_namespace)
try:
    ssh_namespace["core_ssh_command"](expected_host, "ubuntu", "true", connect_timeout=8)
except ValueError:
    pass
else:
    raise SystemExit("Core SSH command accepted an unpinned management hostname")
key_algorithm = b"ssh-ed25519"
key_blob = (
    len(key_algorithm).to_bytes(4, "big")
    + key_algorithm
    + (32).to_bytes(4, "big")
    + (b"K" * 32)
)
host_key = "ssh-ed25519 " + base64.b64encode(key_blob).decode("ascii")
ssh_namespace["install_management_known_hosts"](expected_host, [host_key])
if known_hosts_path.read_text(encoding="utf-8") != f"{expected_host} {host_key}\n":
    raise SystemExit("Core SSH host-key pin file contains unexpected data")
if known_hosts_path.stat().st_mode & 0o077:
    raise SystemExit("Core SSH host-key pin file is not owner-only")
command = ssh_namespace["core_ssh_command"](expected_host, "ubuntu", "true", connect_timeout=8)
joined = " ".join(command)
for required in (
    "ubuntu@" + expected_host,
    "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h",
    "StrictHostKeyChecking=yes",
    "UserKnownHostsFile=" + str(known_hosts_path),
    "GlobalKnownHostsFile=/dev/null",
    "UpdateHostKeys=no",
    "BatchMode=yes",
):
    if required not in joined:
        raise SystemExit(f"Core SSH command is missing {required}: {command}")
if "test-client.access" in joined or "s" * 32 in joined:
    raise SystemExit("Access service-token credentials leaked into the SSH process arguments")
try:
    ssh_namespace["core_ssh_command"]("203.0.113.8", "ubuntu", "true")
except ValueError:
    pass
else:
    raise SystemExit("Core management accepted direct-IP SSH while origin hiding is enabled")
ssh_namespace["TUNNEL_SERVICE_TOKEN_SECRET"] = ""
try:
    ssh_namespace["core_ssh_command"](expected_host, "ubuntu", "true")
except ValueError:
    pass
else:
    raise SystemExit("Core management allowed a Cloudflare hostname without Access service-token credentials")
# H0 (D3): this hub's own address, loopback and localhost are refused by name
# before any other check, so no management command can become a root command
# on the hub itself.
for own_host in ("192.0.2.254", "127.0.0.1", "localhost"):
    try:
        ssh_namespace["core_ssh_command"](own_host, "ubuntu", "true")
    except ValueError as exc:
        if "Refusing to manage this hub" not in str(exc):
            raise SystemExit(f"Core management refused {own_host} for another reason: {exc}")
    else:
        raise SystemExit(f"Core management accepted this hub's own address {own_host}")
known_hosts_dir.cleanup()
PYEOF
  echo "PASS per-Core Cloudflare connector, localhost-only SSH ingress, opaque DNS, and hidden-origin SSH simulation"
}

test_suricata_daily_update_contract() {
  local role script generated fake_bin log_file rules_dir su_line
  local old_rule='alert tcp any any -> any 80 (msg:"wins-test old"; sid:9100001; rev:1;)'
  local new_rule='alert tcp any any -> any 80 (msg:"wins-test new"; sid:9100002; rev:1;)'
  for role in control data core; do
    if [[ "${role}" == "control" ]]; then
      script="${CONTROL_SCRIPT}"
    elif [[ "${role}" == "data" ]]; then
      script="${DATA_SCRIPT}"
    else
      script="${CORE_SCRIPT}"
    fi
    generated="${work_dir}/${role}-wins-suricata-update"
    python3 - "${script}" "${generated}" <<'PYEOF'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
header = "cat > /usr/local/bin/wins-suricata-update <<'EOF'\n"
start = source.index(header) + len(header)
end = source.index("\nEOF", start)
pathlib.Path(sys.argv[2]).write_text(source[start:end] + "\n", encoding="utf-8")
PYEOF
    chmod 700 "${generated}"
    fake_bin="${work_dir}/${role}-suricata-update-bin"
    mkdir -p "${fake_bin}"
    # Every role's update downloads with --output into a staging
    # directory under WINS_SURICATA_RULES_DIR, reviews it there and swaps it
    # in. This stub writes the downloaded ruleset there; with
    # WINS_TEST_SURICATA_ACTION_FAIL=1 it carries a blocking action.
    cat > "${fake_bin}/suricata-update" <<'EOF'
#!/usr/bin/env bash
printf 'suricata-update %s\n' "$*" >>"${WINS_TEST_LOG}"
while (($#)); do
  if [[ "$1" == --output ]]; then
    if [[ "${WINS_TEST_SURICATA_ACTION_FAIL:-0}" == "1" ]]; then
      printf '%s\n' 'drop tcp any any -> any 80 (msg:"wins-test blocking"; sid:9100003; rev:1;)' > "$2/suricata.rules"
    else
      printf '%s\n' "${WINS_TEST_NEW_RULE:?}" > "$2/suricata.rules"
    fi
    shift
  fi
  shift
done
EOF
    cat > "${fake_bin}/suricata" <<'EOF'
#!/usr/bin/env bash
printf 'suricata %s\n' "$*" >>"${WINS_TEST_LOG}"
[[ "${WINS_TEST_SURICATA_CONFIG_FAIL:-0}" != "1" ]]
EOF
    # Every activation also records the active ruleset it loads.
    cat > "${fake_bin}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"${WINS_TEST_LOG}"
case "${1:-}" in
  start|restart|reload|kill)
    printf 'activation-loaded %s\n' "$(cat "${WINS_SURICATA_RULES_DIR:?}/suricata.rules")" >>"${WINS_TEST_LOG}"
    ;;
esac
[[ "${1:-}" == "is-active" ]]
EOF
    cat > "${fake_bin}/suricatasc" <<'EOF'
#!/usr/bin/env bash
printf 'suricatasc %s\n' "$*" >>"${WINS_TEST_LOG}"
printf 'activation-loaded %s\n' "$(cat "${WINS_SURICATA_RULES_DIR:?}/suricata.rules")" >>"${WINS_TEST_LOG}"
EOF
    # The control update proves the hub still answers through nginx.
    cat > "${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'curl-health' >>"${WINS_TEST_LOG}"
EOF
    chmod 700 "${fake_bin}"/*

    # A private rules directory holding the previous (good) ruleset. The
    # default, /var/lib/suricata/rules, is the live host's: a control update
    # run without this would stage and swap there.
    rules_dir="${work_dir}/${role}-suricata-rules"
    log_file="${work_dir}/${role}-suricata-update.log"
    reset_suricata_update_case() {
      rm -rf -- "${rules_dir}"
      mkdir -p "${rules_dir}"
      printf '%s\n' "${old_rule}" > "${rules_dir}/suricata.rules"
      : > "${log_file}"
    }
    run_suricata_update() {
      env PATH="${fake_bin}:${PATH}" WINS_TEST_LOG="${log_file}" \
        WINS_SURICATA_ACTION_POLICY_BIN=/bin/true WINS_SURICATA_RULES_DIR="${rules_dir}" \
        WINS_SURICATA_HEALTH_SECONDS=5 WINS_TEST_NEW_RULE="${new_rule}" "$@" "${generated}"
    }

    reset_suricata_update_case
    run_suricata_update
    if [[ "${role}" == "control" ]]; then
      su_line="$(grep '^suricata-update ' "${log_file}")"
      [[ "${su_line}" == "suricata-update --disable-conf /etc/suricata/disable.conf --modify-conf /etc/suricata/modify.conf --no-test --no-reload --output ${rules_dir}/.wins-staging."?????? ]]
      [[ "$(<"${rules_dir}/suricata.rules")" == "${new_rule}" ]]
      [[ "$(<"${rules_dir}/suricata.rules.last-good")" == "${old_rule}" ]]
      grep -Fxq "activation-loaded ${new_rule}" "${log_file}"
      grep -Fxq 'curl-health' "${log_file}"
    else
      su_line="$(grep '^suricata-update ' "${log_file}")"
      [[ "${su_line}" == "suricata-update --disable-conf /etc/suricata/disable.conf --modify-conf /etc/suricata/modify.conf --no-test --no-reload --output ${rules_dir}/.wins-staging."?????? ]]
      [[ "$(<"${rules_dir}/suricata.rules")" == "${new_rule}" ]]
      grep -Fxq "activation-loaded ${new_rule}" "${log_file}"
    fi
    grep -Fxq 'suricata -T -c /etc/suricata/suricata.yaml' "${log_file}"
    grep -Fxq 'systemctl is-active --quiet suricata.service' "${log_file}"
    grep -Fxq 'suricatasc -c reload-rules' "${log_file}"
    if grep -Eq '^systemctl (start|kill) ' "${log_file}"; then
      echo "${role} restarted or signaled Suricata despite a successful socket reload." >&2
      return 1
    fi
    [[ -z "$(find "${rules_dir}" -mindepth 1 -name '.wins-staging.*' -print)" ]]

    reset_suricata_update_case
    if run_suricata_update WINS_TEST_SURICATA_CONFIG_FAIL=1; then
      echo "${role} accepted an invalid updated Suricata ruleset." >&2
      return 1
    fi
    # A failed config test must put the
    # last good ruleset back, and nothing may ever load the failed one.
    grep -Fxq 'suricata -T -c /etc/suricata/suricata.yaml' "${log_file}"
    [[ "$(<"${rules_dir}/suricata.rules")" == "${old_rule}" ]]
    if grep -Fxq "activation-loaded ${new_rule}" "${log_file}"; then
      echo "${role} activated a ruleset after its config test failed." >&2
      return 1
    fi
    [[ -z "$(find "${rules_dir}" -mindepth 1 -name '.wins-staging.*' -print)" ]]

    reset_suricata_update_case
    if run_suricata_update WINS_TEST_SURICATA_ACTION_FAIL=1; then
      echo "${role} accepted an imported Suricata blocking/bypass action." >&2
      return 1
    fi
    if grep -Eq '^(suricata |suricatasc|systemctl |activation-loaded )' "${log_file}"; then
      echo "${role} validated or activated a ruleset after its action-policy gate failed." >&2
      return 1
    fi
    [[ "$(<"${rules_dir}/suricata.rules")" == "${old_rule}" ]]
    [[ -z "$(find "${rules_dir}" -mindepth 1 -name '.wins-staging.*' -print)" ]]
  done
  echo "PASS daily Suricata update, pre-activation config test, and live reload contract"
}

test_control_fail_closed_cutover_contract() {
  local policy_dir="${work_dir}/control-cutover-policy"
  local fake_canary="${policy_dir}/fake-gateway-canary"
  local canary_count="${policy_dir}/canary-count"
  mkdir -p "${policy_dir}"

  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    systemctl() { return 1; }
    REQUIRE_REMOTE_BACKUP=1
    if run_initial_backup; then
      echo "required initial backup did not stop public cutover" >&2
      return 1
    fi
    # LSR (owner ruling, Sol N-18; Claude N-28): a failed first backup stops
    # public cutover whatever REQUIRE_REMOTE_BACKUP says. Only exit 75 (the
    # remote copy failed, every local stage succeeded) lets the deploy go on.
    REQUIRE_REMOTE_BACKUP=0
    if run_initial_backup; then
      echo "optional initial backup failure did not stop public cutover" >&2
      return 1
    fi
  )

  cat > "${fake_canary}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${WINS_CANARY_SKIP_GATEWAY_RECORD:-0}" == "1" ]] || exit 90
count=0
[[ -f "${FAKE_CANARY_COUNT}" ]] && count="$(<"${FAKE_CANARY_COUNT}")"
count=$((count + 1))
printf '%s\n' "${count}" > "${FAKE_CANARY_COUNT}"
[[ "${count}" -ge 2 ]]
EOF
  chmod 700 "${fake_canary}"
  # H0 (62a802b): the runner never executes a canary itself. It starts
  # wins-gateway-canary-prepublication.service, which write_gateway_canary
  # derives from the reviewed wins-gateway-canary.service with its own sed
  # program. Build that unit here the same way (the installer's unit text run
  # through the installer's sed program) and let the systemctl stub run what
  # the unit says: its one ExecStart must be the reviewed canary, which the
  # fake stands in for, and its Environment= lines are the only canary
  # variables the fake sees. The fake exits 90 without the skip-record
  # variable, so a derivation that lost it fails every attempt here.
  local canary_unit="${policy_dir}/wins-gateway-canary.service"
  local prepublication_unit="${policy_dir}/wins-gateway-canary-prepublication.service"
  local prepublication_unit_without_skip="${policy_dir}/wins-gateway-canary-prepublication-without-skip.service"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /etc/systemd/system/wins-gateway-canary.service <<'EOF'" EOF > "${canary_unit}"
  [[ -s "${canary_unit}" ]]
  python3 - "${CONTROL_SCRIPT}" "${policy_dir}/prepublication-unit.sed" <<'PYEOF'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").split("\n")
first = "  sed '/^\\[Service\\]$/a\\"
starts = [index for index, line in enumerate(lines) if line == first]
if len(starts) != 1:
    sys.exit(f"control installer has {len(starts)} prepublication unit derivations, not one")
program = ["/^\\[Service\\]$/a\\"]
index = starts[0] + 1
while index < len(lines) and not lines[index].endswith("' \\"):
    program.append(lines[index])
    index += 1
if index >= len(lines):
    sys.exit("the prepublication unit derivation has no end")
program.append(lines[index][: -len("' \\")])
if lines[index + 1:index + 3] != [
    "    /etc/systemd/system/wins-gateway-canary.service \\",
    "    > /etc/systemd/system/wins-gateway-canary-prepublication.service",
]:
    sys.exit("the prepublication unit is no longer derived from the reviewed canary unit")
Path(sys.argv[2]).write_text("\n".join(program) + "\n", encoding="utf-8")
PYEOF
  sed -f "${policy_dir}/prepublication-unit.sed" "${canary_unit}" > "${prepublication_unit}"
  grep -vFx 'Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1' "${prepublication_unit}" \
    > "${prepublication_unit_without_skip}"
  # play_prepublication_unit UNIT ARGS...: `systemctl ARGS` for the runner,
  # answering only a synchronous start of the prepublication unit.
  play_prepublication_unit() {
    local unit_file="$1" line exec_line="" in_service=0
    local -a unit_env=()
    shift
    [[ "$*" == 'start wins-gateway-canary-prepublication.service' ]] || return 64
    while IFS= read -r line; do
      if [[ "${line}" == '[Service]' ]]; then
        in_service=1
      elif [[ "${line}" == '['* ]]; then
        in_service=0
      elif [[ "${in_service}" == 1 && "${line}" == Environment=* ]]; then
        [[ "${line#Environment=}" =~ ^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_.,:/@+-]*$ ]] || return 66
        unit_env+=("${line#Environment=}")
      elif [[ "${in_service}" == 1 && "${line}" == ExecStart=* ]]; then
        [[ -z "${exec_line}" ]] || return 65
        exec_line="${line}"
      fi
    done < "${unit_file}"
    [[ "${exec_line}" == 'ExecStart=/usr/local/bin/wins-gateway-canary' ]] || return 65
    env -u WINS_CANARY_WINN3_ADVISORY -u WINS_CANARY_SKIP_GATEWAY_RECORD \
      "${unit_env[@]}" FAKE_CANARY_COUNT="${canary_count}" "${fake_canary}"
  }
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    systemctl() { play_prepublication_unit "${prepublication_unit}" "$@"; }
    PUBLIC_CANARY_ATTEMPTS=2
    PUBLIC_CANARY_INTERVAL_SECONDS=0
    run_prepublication_gateway_canary
  )
  [[ "$(<"${canary_count}")" == "2" ]]
  # A canary that never passes stops public cutover: the runner returns 1, so
  # the active-gateway pointer is not published.
  rm -f -- "${canary_count}"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    systemctl() { play_prepublication_unit "${prepublication_unit}" "$@"; }
    PUBLIC_CANARY_ATTEMPTS=1
    PUBLIC_CANARY_INTERVAL_SECONDS=0
    if run_prepublication_gateway_canary; then
      echo "a failing prepublication canary did not stop public cutover" >&2
      return 1
    fi
  )
  [[ "$(<"${canary_count}")" == "1" ]]
  # Anti-vacuity: the same unit without the skip-record line fails every
  # attempt before the fake counts one, so the passes above came from the
  # installer's derivation and not from the stub.
  rm -f -- "${canary_count}"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    systemctl() { play_prepublication_unit "${prepublication_unit_without_skip}" "$@"; }
    PUBLIC_CANARY_ATTEMPTS=2
    PUBLIC_CANARY_INTERVAL_SECONDS=0
    if run_prepublication_gateway_canary; then
      echo "a prepublication unit without the skip-record variable passed the canary gate" >&2
      return 1
    fi
  )
  [[ ! -e "${canary_count}" ]]
  # The runner pins the reviewed canary path: an override is refused before
  # any unit starts, and the unreviewed program is never run, in or out of a
  # unit.
  local unreviewed_canary="${policy_dir}/unreviewed-canary"
  printf '#!/usr/bin/env bash\n: > %q\n' "${policy_dir}/unreviewed-canary-ran" > "${unreviewed_canary}"
  chmod 700 "${unreviewed_canary}"
  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    systemctl() { : > "${policy_dir}/prepublication-unit-started"; return 0; }
    WINS_GATEWAY_CANARY_BIN="${unreviewed_canary}"
    PUBLIC_CANARY_ATTEMPTS=1
    PUBLIC_CANARY_INTERVAL_SECONDS=0
    if run_prepublication_gateway_canary; then
      echo "the prepublication canary accepted an unreviewed canary binary" >&2
      return 1
    fi
  )
  [[ ! -e "${policy_dir}/unreviewed-canary-ran" && ! -e "${policy_dir}/prepublication-unit-started" ]]

  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    sysctl() { :; }
    root_backed_by_luks() { return 1; }
    unencrypted_swap_devices() {
      [[ -f "${policy_dir}/swap-disabled" ]] || printf '%s\n' "${WINS_SWAPFILE_PATH}"
    }
    swapoff() {
      [[ "${1:-}" == "${WINS_SWAPFILE_PATH}" ]]
      : > "${policy_dir}/swap-disabled"
    }
    WINS_FSTAB_PATH="${policy_dir}/fstab"
    WINS_SWAPFILE_PATH="${policy_dir}/swapfile"
    WINS_MEMORY_SYSCTL_PATH="${policy_dir}/memory.conf"
    ENABLE_WINS_SWAPFILE=0
    ENABLE_ZRAM_SWAP=0
    WINS_CRYPTSWAP_ENABLED=0
    ALLOW_UNENCRYPTED_SWAPFILE=0
    legacy_loop_swap_sources() { :; }
    printf '%s\n' \
      '/dev/root / ext4 defaults 0 1' \
      "${WINS_SWAPFILE_PATH} none swap sw 0 0" \
      '/dev/sda2 none swap sw 0 0' > "${WINS_FSTAB_PATH}"
    : > "${WINS_SWAPFILE_PATH}"
    configure_swap_policy
    [[ ! -e "${WINS_SWAPFILE_PATH}" ]]
    if grep -Eq '^[[:space:]]*[^#[:space:]]+[[:space:]]+([^[:space:]]+[[:space:]]+)?swap([[:space:]]|$)' "${WINS_FSTAB_PATH}"; then false; fi
    grep -Fxq '/dev/root / ext4 defaults 0 1' "${WINS_FSTAB_PATH}"
  )

  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    sysctl() { :; }
    root_backed_by_luks() { return 1; }
    unencrypted_swap_devices() { printf '%s\n' "${WINS_SWAPFILE_PATH}"; }
    swapoff() { return 1; }
    WINS_FSTAB_PATH="${policy_dir}/failure-fstab"
    WINS_SWAPFILE_PATH="${policy_dir}/failure-swapfile"
    WINS_MEMORY_SYSCTL_PATH="${policy_dir}/failure-memory.conf"
    ENABLE_WINS_SWAPFILE=0
    ENABLE_ZRAM_SWAP=0
    WINS_CRYPTSWAP_ENABLED=0
    ALLOW_UNENCRYPTED_SWAPFILE=0
    legacy_loop_swap_sources() { :; }
    : > "${WINS_FSTAB_PATH}"
    : > "${WINS_SWAPFILE_PATH}"
    if configure_swap_policy; then
      echo "plaintext swap disable failure did not stop deployment" >&2
      return 1
    fi
    [[ -e "${WINS_SWAPFILE_PATH}" ]]
  )

  echo "PASS control plaintext-swap remediation, required backup, and prepublication canary gates"
}

test_next_boot_kernel_cmdline() {
  local d="${work_dir}/next-boot-cmdline" role script
  mkdir -p "${d}"
  for role in control data core; do
    case "${role}" in
      control) script="${CONTROL_SCRIPT}" ;;
      data) script="${DATA_SCRIPT}" ;;
      core) script="${CORE_SCRIPT}" ;;
    esac
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      NODE_ENV_FILE="${d}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      log() { :; }
      warn() { :; }
      err() { :; }
      r="${d}/${role}"
      menu() {
        printf '%s\n' \
          'if [ -s $prefix/grubenv ]; then' '  load_env' 'fi' \
          'if [ "${next_entry}" ] ; then' '   set default="${next_entry}"' '   set next_entry=' 'else' "   set default=\"$1\"" 'fi' \
          'function load_video {' '  insmod all_video' '}' \
          "menuentry 'Ubuntu' --class ubuntu \$menuentry_id_option 'gnulinux-simple-abc' {" \
          "	linux	/boot/vmlinuz-6.8.0-142-generic root=PARTUUID=x ro console=tty1 $2 \$vt_handoff" '}' \
          "submenu 'Advanced options for Ubuntu' \$menuentry_id_option 'gnulinux-advanced-abc' {" \
          "	menuentry 'Ubuntu, with Linux 6.8.0-142-generic' \$menuentry_id_option 'gnulinux-6.8.0-142-generic-advanced-abc' {" \
          "		linux	/boot/vmlinuz-6.8.0-142-generic root=PARTUUID=x ro console=tty1 \$vt_handoff" '	}' \
          "	menuentry 'Ubuntu, with Linux 6.8.0-139-generic' \$menuentry_id_option 'gnulinux-6.8.0-139-generic-advanced-abc' {" \
          "		linux	/boot/vmlinuz-6.8.0-139-generic root=PARTUUID=x ro console=tty1 $3 \$vt_handoff" '	}' '}' \
          '### BEGIN /etc/grub.d/41_custom ###' 'if [ -f  ${config_directory}/custom.cfg ]; then' '  source ${config_directory}/custom.cfg' \
          'elif [ -z "${config_directory}" -a -f  $prefix/custom.cfg ]; then' '  source $prefix/custom.cfg' 'fi'
      }
      stub() { printf '%s\n' "$@" > "${r}/boot/efi/EFI/ubuntu/grub.cfg"; }
      fixture() {
        rm -rf "${r}"
        mkdir -p "${r}/boot/grub" "${r}/proc" "${r}/etc/default/grub.d" "${r}/boot/efi/EFI/ubuntu" "${r}/sys/firmware/efi" "${r}/_l40_fixture"
        printf '1\n' > "${r}/_l40_fixture/esp_count"
        printf '%s\n' 'rootuuid /' 'datauuid /mnt/data' > "${r}/_l40_fixture/fs"
        menu "$1" "$2" "$3" > "${r}/boot/grub/grub.cfg"
        printf '%s\n' '# GRUB Environment Block' "$4" '#####' > "${r}/boot/grub/grubenv"
        printf '%s\n' 'BOOT_IMAGE=/vmlinuz-6.8.0-142-generic root=PARTUUID=x ro console=tty1' > "${r}/proc/cmdline"
        printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="console=tty1"' > "${r}/etc/default/grub"
        stub 'search.fs_uuid rootuuid root' "set prefix=(\$root)'/boot/grub'" 'configfile $prefix/grub.cfg'
      }
      out() { next_boot_cmdline_problems_at_root "${r}"; }

      # Revision 6 cases, now reached through the resolved ESP stub.
      fixture 0 "" "systemd.zram=0" ""
      [[ -z "$(out)" ]]
      fixture 0 "systemd.zram=0" "" ""
      [[ "$(out)" == *"entry default 0 -> Ubuntu: systemd.zram=0 disables zram"* ]]
      fixture "1>1" "" "systemd.zram=0" ""
      [[ "$(out)" == *"entry default 1>1 -> Ubuntu, with Linux 6.8.0-139-generic: systemd.zram=0"* ]]
      fixture '${saved_entry}' "" "systemd.zram=0" "saved_entry=gnulinux-advanced-abc>gnulinux-6.8.0-139-generic-advanced-abc"
      [[ "$(out)" == *"6.8.0-139-generic: systemd.zram=0 disables zram"* ]]
      fixture 0 "" "module_blacklist=zram" "next_entry=1>1"
      [[ "$(out)" == *"next_entry (one-shot next boot) 1>1"*"blacklists the zram module"* ]]
      fixture '${foo}' "" "systemd.mask=dev-zram0.swap" ""
      [[ "$(out)" == *"any entry"*"masks a unit zram swap needs"* ]]
      fixture 0 "" "" ""
      printf '%s\n' 'BOOT_IMAGE=/vmlinuz ro systemd.zram=off' > "${r}/proc/cmdline"
      [[ "$(out)" == *"current kernel command line"*"systemd.zram=off disables zram"* ]]
      fixture 0 "" "" ""
      printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT systemd.zram=0"' > "${r}/etc/default/grub.d/99-x.cfg"
      [[ "$(out)" == *"GRUB_CMDLINE_LINUX_DEFAULT: systemd.zram=0 disables zram"* ]]
      fixture 0 "" "" ""
      printf '%s\n' 'root=/dev/vda1 ro console=ttyS0' > "${r}/proc/cmdline"
      [[ "$(out)" == *"did not come through GRUB"* ]]
      fixture 0 "" "" ""
      mkdir -p "${r}/boot/loader/entries" "${r}/boot/efi/EFI/Linux"
      printf '%s\n' 'title x' 'options root=x systemd.zram=0' > "${r}/boot/loader/entries/x.conf"
      [[ "$(out)" == *"BLS entry /boot/loader/entries/x.conf: systemd.zram=0 disables zram"* ]]
      : > "${r}/boot/efi/EFI/Linux/u.efi"
      [[ "$(out)" == *"unified kernel image(s) present"* ]]
      rm -rf "${r}/boot"
      [[ "$(out)" == *"no known boot loader configuration"* ]]

      # Revision 7: the stub chain decides which file GRUB loads.
      fixture 0 "" "" ""
      mkdir -p "${r}/boot/other"
      menu 0 "systemd.zram=0" "" > "${r}/boot/other/grub.cfg"
      stub 'search.fs_uuid rootuuid root' "set prefix=(\$root)'/boot/other'" 'configfile $prefix/grub.cfg'
      [[ "$(out)" == "/boot/other/grub.cfg entry default 0 -> Ubuntu: systemd.zram=0 disables zram" ]]
      mkdir -p "${r}/boot/stage"
      printf '%s\n' "set prefix=(\$root)'/boot/other'" 'configfile $prefix/grub.cfg' > "${r}/boot/stage/stage2.cfg"
      stub 'search.fs_uuid rootuuid root' 'configfile /boot/stage/stage2.cfg'
      [[ "$(out)" == "/boot/other/grub.cfg entry default 0 -> Ubuntu: systemd.zram=0 disables zram" ]]
      fixture 0 "" "" ""
      mkdir -p "${r}/mnt/data/grubx"
      menu 0 "module_blacklist=zram" "" > "${r}/mnt/data/grubx/grub.cfg"
      stub 'search --no-floppy --fs-uuid --set=root datauuid' "set prefix=(\$root)'/grubx'" 'configfile $prefix/grub.cfg'
      [[ "$(out)" == "/mnt/data/grubx/grub.cfg entry default 0 -> Ubuntu: module_blacklist=zram blacklists the zram module" ]]
      stub 'configfile (hd9,gpt9)/grub.cfg'
      [[ "$(out)" == *"is on a device this check cannot map"*"refusing" ]]
      printf 'ghost\n' >> "${r}/_l40_fixture/fs"
      stub 'search.fs_uuid ghost root' "set prefix=(\$root)'/grub'" 'configfile $prefix/grub.cfg'
      [[ "$(out)" == *"filesystem UUID ghost is not mounted"* ]]
      printf 'datauuid /mnt/other\n' >> "${r}/_l40_fixture/fs"
      stub 'search.fs_uuid datauuid root' "set prefix=(\$root)'/grubx'" 'configfile $prefix/grub.cfg'
      [[ "$(out)" == *"filesystem UUID datauuid is carried by 2 block devices"* ]]
      fixture 0 "" "" ""
      printf '%s\n' 'configfile /boot/loop.cfg' > "${r}/boot/loop.cfg"
      stub 'search.fs_uuid rootuuid root' 'configfile /boot/loop.cfg'
      [[ "$(out)" == *"chain deeper than 5"* ]]
      stub 'search.file /x root' 'configfile /boot/grub/grub.cfg'
      [[ "$(out)" == *"unsupported command in a boot-path stub: search.file"* ]]
      stub 'search.fs_uuid rootuuid root'
      [[ "$(out)" == *"does not hand over to a menu configuration"* ]]
      fixture 0 "" "" ""
      printf '2\n' > "${r}/_l40_fixture/esp_count"
      [[ "$(out)" == *"2 EFI system partitions found"* ]]
      fixture 0 "" "" ""
      mkdir -p "${r}/boot/efi/EFI/BOOT" "${r}/boot/other"
      menu 0 "systemd.zram=0" "" > "${r}/boot/other/grub.cfg"
      printf '%s\n' 'search.fs_uuid rootuuid root' "set prefix=(\$root)'/boot/other'" 'configfile $prefix/grub.cfg' > "${r}/boot/efi/EFI/BOOT/grub.cfg"
      [[ "$(out)" == *"/boot/other/grub.cfg entry default 0 -> Ubuntu: systemd.zram=0"* ]]
      fixture 0 "" "" ""
      printf '%s\n' 'set default="l40"' "menuentry 'l40' \$menuentry_id_option 'l40' {" '	linux /vmlinuz ro systemd.zram=0' '}' > "${r}/boot/grub/custom.cfg"
      [[ "$(out)" == *"source /boot/grub/custom.cfg adds menu entries"*"custom.cfg:l40: systemd.zram=0 disables zram"* ]]

      # Revision 8: on BIOS the core image that runs is read from the BIOS boot
      # partition the MBR loads; synthetic GRUB 2.12 i386-pc images below.
      mkcore() {
        python3 - "$@" <<'PY'
import lzma
import struct
import sys


def obj(typ, body):
    body += b"\0"
    body += b"\0" * (-len(body) % 4)
    return struct.pack("<II", typ, 8 + len(body)) + body


def core(prefix, config, first):
    kern = bytes((i * 7 + 3) & 0xFF for i in range(4000))
    objs = obj(0, b"\x7fELF l40 fake module")
    if config != "-":
        objs += obj(2, config.encode())
    objs += obj(3, prefix.encode())
    unc = kern + struct.pack("<III", 0x676D696D, 12, 12 + len(objs)) + objs
    comp = lzma.compress(unc, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}])
    dec = bytearray(b"\x90" * 2832)
    struct.pack_into("<IIIH", dec, 8, len(comp), len(unc), 0, 0x758)
    body = bytes(dec) + comp
    body += b"\0" * (-len(body) % 512)
    ds = bytearray(512)
    struct.pack_into("<QHH", ds, 0x200 - 12, first + 1, len(body) // 512, 0x820)
    return bytes(ds) + body


def mbr(k):
    m = bytearray(512)
    struct.pack_into("<Q", m, 0x5C, k)
    struct.pack_into("<H", m, 0x1FE, 0xAA55)
    return bytes(m)


a = sys.argv[1:]
if a[0] == "core":
    open(a[4], "wb").write(core(a[1], a[2], int(a[3])))
elif a[0] == "mbr":
    open(a[2], "wb").write(mbr(int(a[1])))
else:
    k = int(a[1])
    open(a[4], "wb").write(mbr(k) + b"\0" * (512 * (k - 1)) + core(a[2], a[3], k))
PY
      }
      gptblk() {
        printf '%s\n' 'sda - disk gpt - - -' 'sda1 sda part gpt 0fc63daf-8483-4772-8e79-3d69d8477de4 1 2099200' "$@" > "${r}/_l40_fixture/blk"
      }
      bios() {
        fixture 0 "$1" "" ""
        rm -rf "${r}/sys/firmware/efi"
        mkdir -p "${r}/boot/grub/i386-pc" "${r}/_l40_fixture/dev"
        gptblk 'sda14 sda part gpt 21686148-6449-6e6f-744e-656564454649 14 2048'
        printf '%s\n' 'sda1 /' > "${r}/_l40_fixture/devmnt"
        mkcore mbr 2048 "${r}/_l40_fixture/dev/sda"
        mkcore core '(,gpt1)/boot/grub' "$2" 2048 "${r}/_l40_fixture/dev/sda14"
        mkcore core '(,gpt1)/boot/grub' - 2048 "${r}/boot/grub/i386-pc/core.img"
      }
      bios "" -
      [[ -z "$(out 2>&1)" ]]
      bios "systemd.zram=0" -
      [[ "$(out)" == "/boot/grub/grub.cfg entry default 0 -> Ubuntu: systemd.zram=0 disables zram" ]]
      bios "" "set prefix=(\$root)'/boot/other'"
      mkdir -p "${r}/boot/other"
      menu 0 "systemd.zram=0" "" > "${r}/boot/other/grub.cfg"
      [[ "$(out 2>/dev/null)" == "/boot/other/grub.cfg entry default 0 -> Ubuntu: systemd.zram=0 disables zram" ]]
      [[ "$(out 2>&1 >/dev/null)" == *"differs from /boot/grub/i386-pc/core.img"* ]]
      bios "" $'search.fs_uuid datauuid root\nset prefix=($root)/grubx\nconfigfile $prefix/grub.cfg'
      mkdir -p "${r}/mnt/data/grubx"
      menu 0 "module_blacklist=zram" "" > "${r}/mnt/data/grubx/grub.cfg"
      [[ "$(out 2>/dev/null)" == "/mnt/data/grubx/grub.cfg entry default 0 -> Ubuntu: module_blacklist=zram blacklists the zram module" ]]
      bios "" -
      gptblk
      [[ "$(out)" == *"0 BIOS core image locations"*"refusing" ]]
      gptblk 'sda14 sda part gpt 21686148-6449-6e6f-744e-656564454649 14 2048' 'sda15 sda part gpt 21686148-6449-6e6f-744e-656564454649 15 10240'
      [[ "$(out)" == *"2 BIOS core image locations"*"refusing" ]]
      bios "" -
      printf 'not a core image\n' > "${r}/_l40_fixture/dev/sda14"
      [[ "$(out)" == *"the core image that runs cannot be read and parsed"*"refusing" ]]
      bios "" -
      mkcore mbr 34 "${r}/_l40_fixture/dev/sda"
      [[ "$(out)" == *"loads sector 34, not the BIOS boot partition /dev/sda14 at sector 2048"* ]]
      bios "" -
      mkcore core '(,gpt9)/grub' - 2048 "${r}/_l40_fixture/dev/sda14"
      [[ "$(out 2>/dev/null)" == *"partition 9 of /dev/sda not found; refusing" ]]
      bios "" -
      printf '%s\n' 'sda - disk dos - - -' 'sda1 sda part dos 0x83 1 2048' > "${r}/_l40_fixture/blk"
      mkcore gapdisk 1 '(,msdos1)/boot/grub' - "${r}/_l40_fixture/dev/sda"
      [[ -z "$(out 2>/dev/null)" ]]
      printf '%s\n' 'sdb - disk dos - - -' 'sdb1 sdb part dos 0x83 1 2048' >> "${r}/_l40_fixture/blk"
      cp "${r}/_l40_fixture/dev/sda" "${r}/_l40_fixture/dev/sdb"
      [[ "$(out)" == *"2 BIOS core image locations"*"post-MBR gap of /dev/sda"*"post-MBR gap of /dev/sdb"* ]]
    )
  done
  echo "PASS next-boot kernel command line from the resolved boot loader chain on control, data and Core"
}

test_zram_next_boot_config() {
  local d="${work_dir}/zram-next-boot" role script
  mkdir -p "${d}"
  for role in control data core; do
    case "${role}" in
      control) script="${CONTROL_SCRIPT}" ;;
      data) script="${DATA_SCRIPT}" ;;
      core) script="${CORE_SCRIPT}" ;;
    esac
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      NODE_ENV_FILE="${d}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      log() { :; }
      warn() { :; }
      err() { :; }
      c="${d}/${role}"
      mkdir -p "${c}"
      printf '%s\n' '# Managed by Win'"'"'s VPN. Compressed RAM only: intentionally no writeback-device.' \
        '[zram0]' 'zram-size = min(ram * 50 / 100, 2048)' 'compression-algorithm = zstd' 'swap-priority = 100' > "${c}/main.conf"
      mock_files=("${c}/main.conf")
      zram_generator_config_files() { printf '%s\n' "${mock_files[@]}"; }
      problems() { zram_effective_config_problems 50 2048; }

      [[ -z "$(problems)" ]]
      printf '%s\n' '[zram0]' 'writeback-device = /dev/vdb' > "${c}/90-writeback.conf"
      mock_files=("${c}/main.conf" "${c}/90-writeback.conf")
      [[ "$(problems)" == "[zram0] writeback-device = /dev/vdb is not in the reviewed policy" ]]
      printf '%s\n' '[zram1]' 'zram-size = 512' > "${c}/50-extra.conf"
      mock_files=("${c}/main.conf" "${c}/50-extra.conf")
      [[ "$(problems)" == "extra section [zram1] in the zram-generator configuration" ]]
      printf '%s\n' '[zram0]' 'zram-size = ram' > "${c}/60-size.conf"
      mock_files=("${c}/main.conf" "${c}/60-size.conf")
      [[ "$(problems)" == *'zram-size is "ram"'* ]]
      printf '%s\n' '[zram0]' 'swap-priority = 5' > "${c}/61-prio.conf"
      mock_files=("${c}/main.conf" "${c}/61-prio.conf")
      [[ "$(problems)" == *'swap-priority is "5"'* ]]
      printf '%s\n' 'set!n=echo 1' > "${c}/10-global.conf"
      mock_files=("${c}/10-global.conf" "${c}/main.conf")
      [[ "$(problems)" == *"global directive set!n"* ]]
      printf '%s\n' '[zram0]' 'writeback-device = "/dev/vdb"' > "${c}/70-quoted.conf"
      mock_files=("${c}/main.conf" "${c}/70-quoted.conf")
      [[ "$(problems)" == *"outside the reviewed key = value grammar"* ]]
      # A lower-precedence copy that sets writeback is still seen, even when a
      # higher copy of the same name is empty (masked).
      : > "${c}/90-masked.conf"
      mock_files=("${c}/main.conf" "${c}/90-writeback.conf" "${c}/90-masked.conf")
      [[ "$(problems)" == *"writeback-device"* ]]
      mock_files=("${c}/main.conf" "${c}/90-masked.conf")
      [[ -z "$(problems)" ]]
      mock_files=()
      [[ "$(problems)" == "no zram-generator configuration exists: zram would not return at the next boot" ]]

      # The real file-list order (read from the installer source, because the
      # function is mocked above): the main file is the first found of /run,
      # /etc, /usr/local/lib, /usr/lib, and drop-ins are listed lowest first.
      [[ "$(grep -c 'for d in /run /etc /usr/local/lib /usr/lib; do' "${script}")" == "1" ]]
      [[ "$(grep -c 'for d in /usr/lib /usr/local/lib /etc /run; do' "${script}")" == "2" ]]

      printf '%s\n' 'vm.swappiness=10' > "${c}/98-winsvpn-memory.conf"
      printf '%s\n' 'vm.swappiness = 100' > "${c}/99-override.conf"
      sysctl_files=("${c}/98-winsvpn-memory.conf")
      sysctl_config_files() { printf '%s\n' "${sysctl_files[@]}"; }
      live_swappiness() { printf '10\n'; }
      [[ -z "$(swappiness_problems)" ]]
      sysctl_files=("${c}/98-winsvpn-memory.conf" "${c}/99-override.conf")
      [[ "$(swappiness_problems)" == *'next boot sets vm.swappiness to "100"'* ]]
      sysctl_files=("${c}/98-winsvpn-memory.conf")
      live_swappiness() { printf '60\n'; }
      [[ "$(swappiness_problems)" == *'live vm.swappiness is "60"'* ]]
    )
  done
  echo "PASS next-boot zram-generator and swappiness evaluation on control, data and Core"
}

test_zram_only_swap_policy_all_roles() {
  local d="${work_dir}/zram-only-policy" role script
  mkdir -p "${d}"
  for role in control data core; do
    case "${role}" in
      control) script="${CONTROL_SCRIPT}" ;;
      data) script="${DATA_SCRIPT}" ;;
      core) script="${CORE_SCRIPT}" ;;
    esac
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      NODE_ENV_FILE="${d}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      log() { :; }
      warn() { :; }
      err() { printf '%s\n' "$*" >> "${d}/err-${role}"; }

      # Defaults: zram on, disk swap off, loop-backed swap off.
      [[ "${ENABLE_ZRAM_SWAP_DEFAULT}" == "1" ]]
      if [[ "${role}" == "core" ]]; then
        [[ "${ENABLE_WINS_SWAPFILE}" == "0" && "${WINS_CRYPTSWAP_ENABLED}" == "0" ]]
      else
        [[ "${ENABLE_WINS_SWAPFILE_DEFAULT}" == "0" && "${WINS_CRYPTSWAP_ENABLED_DEFAULT}" == "0" ]]
      fi

      mock_swaps=""
      mock_enabled="disabled"
      mock_active="inactive"
      swapon() { printf '%s' "${mock_swaps}"; }
      lsblk() {
        case "${!#}" in
          /dev/dm-0) printf 'crypt\nloop\n' ;;
          /dev/zram0) printf 'disk\n' ;;
        esac
      }
      mock_other_enabled="not-found"
      mock_other_active="inactive"
      systemctl() {
        local state
        if [[ "$1" == "is-enabled" ]]; then
          if [[ "$2" == "wins-cryptswap.service" ]]; then state="${mock_enabled}"; else state="${mock_other_enabled}"; fi
          printf '%s\n' "${state}"
          [[ "${state}" == "enabled" ]]
          return
        fi
        if [[ "$1" == "is-active" ]]; then
          if [[ "$2" == "wins-cryptswap.service" ]]; then state="${mock_active}"; else state="${mock_other_active}"; fi
          printf '%s\n' "${state}"
          [[ "${state}" == "active" ]]
          return
        fi
        : > "${d}/systemctl-called-${role}"
      }
      readlink() { printf '%s\n' "${!#}"; }
      mock_sysfs="${d}/sys-${role}"
      mkdir -p "${mock_sysfs}/zram0" "${mock_sysfs}/zram1"
      printf 'none\n' > "${mock_sysfs}/zram1/backing_dev"
      printf 'none\n' > "${mock_sysfs}/zram0/backing_dev"
      zram_backing_dev() { cat "${mock_sysfs}/$1/backing_dev"; }
      mock_canon="ok"
      zram_next_boot_divergences() { if [[ "${mock_canon}" != "ok" ]]; then printf 'mock next-boot divergence\n'; fi; return 0; }
      mock_persist=""
      persistent_non_zram_swap_sources() { if [[ -n "${mock_persist}" ]]; then printf '%s\n' "${mock_persist}"; fi; return 0; }
      mock_block=""
      legacy_cryptswap_block_state() { if [[ -n "${mock_block}" ]]; then printf '%s\n' "${mock_block}"; fi; return 0; }
      WINS_ZRAM_CONFIG_PATH="${d}/zram-${role}.conf"
      : > "${WINS_ZRAM_CONFIG_PATH}"

      mock_swaps=$'/dev/zram0\n'
      zram_only_swap_postcondition
      [[ -z "$(legacy_loop_swap_sources)" ]]

      mock_swaps=$'/dev/zram0\n/dev/dm-0\n'
      [[ "$(legacy_loop_swap_sources)" == "active loop-backed swap /dev/dm-0" ]]
      if zram_only_swap_postcondition; then exit 1; fi

      mock_swaps=""
      if zram_only_swap_postcondition; then exit 1; fi

      mock_swaps=$'/dev/zram0\n'
      mock_enabled="enabled"
      [[ "$(legacy_loop_swap_sources)" == "boot-enabled wins-cryptswap.service (enabled)" ]]
      if zram_only_swap_postcondition; then exit 1; fi
      mock_enabled="disabled"

      printf '/dev/vdb\n' > "${mock_sysfs}/zram0/backing_dev"
      if zram_only_swap_postcondition; then exit 1; fi
      printf 'none\n' > "${mock_sysfs}/zram0/backing_dev"
      printf 'writeback-device = /dev/vdb\n' > "${WINS_ZRAM_CONFIG_PATH}"
      if zram_only_swap_postcondition; then exit 1; fi
      : > "${WINS_ZRAM_CONFIG_PATH}"

      mock_swaps=$'/dev/zram0\n/swapfile\n'
      if zram_only_swap_postcondition; then exit 1; fi

      # A legacy loop swap stops configure_swap_policy before any change.
      mock_swaps=$'/dev/dm-0\n'
      swapoff() { : > "${d}/swapoff-called-${role}"; }
      sysctl() { : > "${d}/sysctl-called-${role}"; }
      configure_zram_swap() { : > "${d}/zram-called-${role}"; }
      WINS_FSTAB_PATH="${d}/fstab-${role}"
      WINS_SWAPFILE_PATH="${d}/swapfile-${role}"
      WINS_MEMORY_SYSCTL_PATH="${d}/memory-${role}.conf"
      printf '%s\n' '/dev/sda2 none swap sw 0 0' > "${WINS_FSTAB_PATH}"
      if configure_swap_policy; then exit 1; fi
      [[ ! -e "${d}/swapoff-called-${role}" && ! -e "${d}/sysctl-called-${role}" && ! -e "${d}/zram-called-${role}" ]]
      [[ ! -e "${WINS_MEMORY_SYSCTL_PATH}" && ! -e "${d}/systemctl-called-${role}" ]]
      grep -Fxq '/dev/sda2 none swap sw 0 0' "${WINS_FSTAB_PATH}"
      grep -Fq 'Legacy loop-backed encrypted swap is present: active loop-backed swap /dev/dm-0' "${d}/err-${role}"

      # The preflight stops on it too, and passes without it (positive control).
      root_backed_by_luks() { return 0; }
      unencrypted_swap_devices() { :; }
      verify_core_secret_permissions() { return 0; }
      if (verify_disk_encryption_posture) >/dev/null 2>&1; then exit 1; fi
      mock_swaps=$'/dev/zram0\n'
      (verify_disk_encryption_posture) >/dev/null 2>&1

      # The postcondition gate enforces zram only.
      CORE_DISK_ENCRYPTION_EFFECTIVE="substitute"
      CONTROL_DISK_ENCRYPTION_EFFECTIVE="substitute"
      require_encrypted_swap_established
      mock_swaps=$'/dev/zram0\n/dev/dm-0\n'
      if require_encrypted_swap_established; then exit 1; fi
      mock_swaps=""
      if require_encrypted_swap_established; then exit 1; fi

      # Revision 3: an extra zram device or an active unit fails the postcondition.
      mock_swaps=$'/dev/zram0\n/dev/zram1\n'
      if zram_only_swap_postcondition; then exit 1; fi
      mock_swaps=$'/dev/zram0\n'
      mock_active="active"
      [[ "$(legacy_loop_swap_sources)" == "active wins-cryptswap.service" ]]
      if zram_only_swap_postcondition; then exit 1; fi
      mock_active="inactive"
      zram_only_swap_postcondition

      # The loop chain is gone, and ENABLE_WINS_SWAPFILE=1 plus
      # WINS_CRYPTSWAP_ENABLED=1 never reaches it.
      if declare -F configure_encrypted_swap >/dev/null; then exit 1; fi
      losetup() { : > "${d}/losetup-called-${role}"; }
      cryptsetup() { : > "${d}/cryptsetup-called-${role}"; }
      fallocate() { : > "${d}/fallocate-called-${role}"; }
      mkswap() { : > "${d}/mkswap-called-${role}"; }
      rm -f "${d}/err-${role}"
      ENABLE_WINS_SWAPFILE=1
      WINS_CRYPTSWAP_ENABLED=1
      mock_swaps=$'/dev/dm-0\n'
      if (verify_disk_encryption_posture) >/dev/null 2>&1; then exit 1; fi
      if configure_swap_policy; then exit 1; fi
      grep -Fq 'Legacy loop-backed encrypted swap is present' "${d}/err-${role}"
      mock_swaps=$'/dev/zram0\n'
      if (verify_disk_encryption_posture) >/dev/null 2>&1; then exit 1; fi
      if configure_swap_policy; then exit 1; fi
      grep -Fq 'WINS_CRYPTSWAP_ENABLED=1 is refused' "${d}/err-${role}"
      WINS_CRYPTSWAP_ENABLED=0
      if configure_swap_policy; then exit 1; fi
      grep -Fq 'no separately reviewed LUKS-backed disk-swap mechanism' "${d}/err-${role}"
      for marker in losetup cryptsetup fallocate mkswap swapoff sysctl zram systemctl; do
        [[ ! -e "${d}/${marker}-called-${role}" ]]
      done
      [[ ! -e "${WINS_MEMORY_SYSCTL_PATH}" ]]
      ENABLE_WINS_SWAPFILE=0

      # Revision 4: an override naming another service cannot hide the
      # canonical wins-cryptswap.service (Sol, Round CS3 Turn 4).
      WINS_CRYPTSWAP_UNIT_PATH="/etc/systemd/system/l40-other.service"
      mock_swaps=$'/dev/zram0\n'
      mock_enabled="enabled"
      [[ "$(legacy_loop_swap_sources)" == "boot-enabled wins-cryptswap.service (enabled)" ]]
      if zram_only_swap_postcondition; then exit 1; fi
      if require_encrypted_swap_established; then exit 1; fi
      if configure_swap_policy; then exit 1; fi
      if (verify_disk_encryption_posture) >/dev/null 2>&1; then exit 1; fi
      # An overridden unit is inspected in addition, never instead.
      mock_enabled="disabled"
      mock_other_enabled="enabled"
      [[ "$(legacy_loop_swap_sources)" == "boot-enabled l40-other.service (enabled)" ]]
      if zram_only_swap_postcondition; then exit 1; fi
      mock_other_enabled="not-found"
      zram_only_swap_postcondition
      unset WINS_CRYPTSWAP_UNIT_PATH
      # The canonical zram config, persistent swap and a still-open mapping.
      mock_canon="bad"
      if zram_only_swap_postcondition; then exit 1; fi
      mock_canon="ok"
      mock_persist="fstab swap entry /swapfile"
      if zram_only_swap_postcondition; then exit 1; fi
      mock_persist=""
      mock_block="present mapping /dev/mapper/wins-cryptswap"
      [[ "$(legacy_loop_swap_sources)" == "present mapping /dev/mapper/wins-cryptswap" ]]
      if zram_only_swap_postcondition; then exit 1; fi
      if configure_swap_policy; then exit 1; fi
      mock_block=""
      zram_only_swap_postcondition
    )
  done
  echo "PASS zram-only swap policy on control, data and Core: defaults, postcondition, legacy stop, preflight, 1/1 refused, canonical unit whatever the environment"
}

test_control_zram_swap_policy() {
  local zram_dir="${work_dir}/control-zram-policy"
  local config_path="${zram_dir}/systemd/zram-generator.conf"
  local generator_path="${zram_dir}/zram-generator"
  mkdir -p "${zram_dir}/systemd"
  printf '#!/usr/bin/env bash\nexit 0\n' > "${generator_path}"
  chmod 755 "${generator_path}"

  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    ENABLE_ZRAM_SWAP=1
    ZRAM_SWAP_PERCENT=50
    ZRAM_SWAP_MAX_MB=2048
    WINS_ZRAM_CONFIG_PATH="${config_path}"
    WINS_ZRAM_GENERATOR_PATH="${generator_path}"
    configure_zram_swap render-only
    [[ "$(stat -c '%a' "${config_path}")" == "644" ]]
    grep -Fxq '[zram0]' "${config_path}"
    grep -Fxq 'zram-size = min(ram * 50 / 100, 2048)' "${config_path}"
    grep -Fxq 'compression-algorithm = zstd' "${config_path}"
    grep -Fxq 'swap-priority = 100' "${config_path}"
    if grep -Eq '^[[:space:]]*writeback-device[[:space:]]*=' "${config_path}"; then false; fi
  )

  for invalid in \
    'ZRAM_SWAP_PERCENT=0' \
    'ZRAM_SWAP_PERCENT=0100' \
    'ZRAM_SWAP_PERCENT=101' \
    'ZRAM_SWAP_MAX_MB=0' \
    'ZRAM_SWAP_MAX_MB=02048' \
    'ZRAM_SWAP_MAX_MB=8193' \
    'ENABLE_ZRAM_SWAP=maybe'; do
    (
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
      log() { :; }
      warn() { :; }
      err() { :; }
      ENABLE_ZRAM_SWAP=1
      ZRAM_SWAP_PERCENT=50
      ZRAM_SWAP_MAX_MB=2048
      eval "${invalid}"
      if validate_zram_policy_settings; then false; fi
    )
  done

  (
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    ENABLE_ZRAM_SWAP=1
    WINS_ZRAM_CONFIG_PATH="${zram_dir}/linked.conf"
    WINS_ZRAM_GENERATOR_PATH="${generator_path}"
    ln -s "${config_path}" "${WINS_ZRAM_CONFIG_PATH}"
    if configure_zram_swap render-only; then false; fi
  )
  echo "PASS control zram is bounded, RAM-only, fail-closed, and symlink-safe"
}

test_early_presecret_swap_guards() {
  local script label guard_dir
  for script in "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${CORE_SCRIPT}"; do
    label="$(basename "${script}")"
    guard_dir="${work_dir}/early-swap-${label}"
    mkdir -p "${guard_dir}"
    (
      WINS_DEFAULTS_FILE="${guard_dir}/absent-defaults"
      WINS_SECRETS_FILE="${guard_dir}/absent-secrets"
      NODE_ENV_FILE="${guard_dir}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      wins_early_unprotected_swap_devices() {
        [[ -f "${guard_dir}/disabled" ]] || printf '%s\n' /dev/fake-plaintext-swap
      }
      swapoff() {
        [[ "${1:-}" == "/dev/fake-plaintext-swap" ]]
        : > "${guard_dir}/disabled"
      }
      wins_early_plaintext_swap_guard --deploy
      [[ -f "${guard_dir}/disabled" ]]
      [[ -z "$(wins_early_unprotected_swap_devices)" ]]
    )
  done

  guard_dir="${work_dir}/early-swap-negative"
  mkdir -p "${guard_dir}"
  (
    WINS_DEFAULTS_FILE="${guard_dir}/absent-defaults"
    WINS_SECRETS_FILE="${guard_dir}/absent-secrets"
    NODE_ENV_FILE="${guard_dir}/absent-node"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    wins_early_unprotected_swap_devices() { printf '%s\n' /dev/fake-plaintext-swap; }
    swapoff() { : > "${guard_dir}/unexpected-swapoff"; return 1; }
    if wins_early_plaintext_swap_guard --validate; then
      echo "validate-only early swap guard accepted plaintext swap" >&2
      return 1
    fi
    [[ ! -e "${guard_dir}/unexpected-swapoff" ]]
    if wins_early_plaintext_swap_guard --deploy; then
      echo "early swapoff failure did not stop credential loading" >&2
      return 1
    fi
  )
  echo "PASS control/data/Core pre-secret plaintext-swap guards"
}

test_data_plaintext_swap_policy() {
  local policy_dir="${work_dir}/data-swap-policy"
  mkdir -p "${policy_dir}"
  (
    WINS_DEFAULTS_FILE="${policy_dir}/absent-defaults"
    WINS_SECRETS_FILE="${policy_dir}/absent-secrets"
    NODE_ENV_FILE="${policy_dir}/absent-node"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    sysctl() { :; }
    root_backed_by_luks() { return 1; }
    unencrypted_swap_devices() {
      [[ -f "${policy_dir}/managed-disabled" ]] || printf '%s\n' "${WINS_SWAPFILE_PATH}"
      [[ -f "${policy_dir}/partition-disabled" ]] || printf '%s\n' /dev/sda2
    }
    swapoff() {
      case "${1:-}" in
        "${WINS_SWAPFILE_PATH}") : > "${policy_dir}/managed-disabled" ;;
        /dev/sda2) : > "${policy_dir}/partition-disabled" ;;
        *) return 1 ;;
      esac
    }
    WINS_FSTAB_PATH="${policy_dir}/fstab"
    WINS_SWAPFILE_PATH="${policy_dir}/swapfile"
    WINS_MEMORY_SYSCTL_PATH="${policy_dir}/memory.conf"
    DISABLE_UNENCRYPTED_SWAP=1
    ENABLE_WINS_SWAPFILE=0
    ENABLE_ZRAM_SWAP=0
    WINS_CRYPTSWAP_ENABLED=0
    legacy_loop_swap_sources() { :; }
    ALLOW_UNENCRYPTED_SWAPFILE=0
    printf '%s\n' \
      '/dev/root / ext4 defaults 0 1' \
      "${WINS_SWAPFILE_PATH} none swap sw 0 0" \
      '/dev/sda2 none swap sw 0 0' > "${WINS_FSTAB_PATH}"
    : > "${WINS_SWAPFILE_PATH}"
    configure_swap_policy
    [[ ! -e "${WINS_SWAPFILE_PATH}" ]]
    if grep -Eq '^[[:space:]]*[^#[:space:]]+[[:space:]]+([^[:space:]]+[[:space:]]+)?swap([[:space:]]|$)' "${WINS_FSTAB_PATH}"; then false; fi
    grep -Fxq '/dev/root / ext4 defaults 0 1' "${WINS_FSTAB_PATH}"
  )

  (
    WINS_DEFAULTS_FILE="${policy_dir}/absent-defaults"
    WINS_SECRETS_FILE="${policy_dir}/absent-secrets"
    NODE_ENV_FILE="${policy_dir}/absent-node"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${DATA_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    sysctl() { :; }
    root_backed_by_luks() { return 1; }
    unencrypted_swap_devices() { printf '%s\n' "${WINS_SWAPFILE_PATH}"; }
    swapoff() { return 1; }
    WINS_FSTAB_PATH="${policy_dir}/failure-fstab"
    WINS_SWAPFILE_PATH="${policy_dir}/failure-swapfile"
    WINS_MEMORY_SYSCTL_PATH="${policy_dir}/failure-memory.conf"
    DISABLE_UNENCRYPTED_SWAP=1
    ENABLE_WINS_SWAPFILE=0
    ENABLE_ZRAM_SWAP=0
    WINS_CRYPTSWAP_ENABLED=0
    legacy_loop_swap_sources() { :; }
    ALLOW_UNENCRYPTED_SWAPFILE=0
    printf '%s\n' "${WINS_SWAPFILE_PATH} none swap sw 0 0" > "${WINS_FSTAB_PATH}"
    : > "${WINS_SWAPFILE_PATH}"
    if configure_swap_policy; then
      echo "data-plane plaintext swap disable failure did not stop deployment" >&2
      return 1
    fi
    [[ -e "${WINS_SWAPFILE_PATH}" ]]
    grep -Fq "${WINS_SWAPFILE_PATH} none swap" "${WINS_FSTAB_PATH}"
  )
  echo "PASS data-plane persisted and active plaintext-swap remediation"
}

test_core_plaintext_swap_policy() {
  local policy_dir="${work_dir}/core-swap-policy"
  mkdir -p "${policy_dir}"
  (
    WINS_DEFAULTS_FILE="${policy_dir}/absent-defaults"
    WINS_SECRETS_FILE="${policy_dir}/absent-secrets"
    NODE_ENV_FILE="${policy_dir}/absent-node"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CORE_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    sysctl() { :; }
    root_backed_by_luks() { return 0; }
    unencrypted_swap_devices() {
      [[ -f "${policy_dir}/managed-disabled" ]] || printf '%s\n' "${WINS_SWAPFILE_PATH}"
      [[ -f "${policy_dir}/partition-disabled" ]] || printf '%s\n' /dev/sda2
    }
    swapoff() {
      case "${1:-}" in
        "${WINS_SWAPFILE_PATH}") : > "${policy_dir}/managed-disabled" ;;
        /dev/sda2) : > "${policy_dir}/partition-disabled" ;;
        *) return 1 ;;
      esac
    }
    WINS_FSTAB_PATH="${policy_dir}/fstab"
    WINS_SWAPFILE_PATH="${policy_dir}/swapfile"
    WINS_MEMORY_SYSCTL_PATH="${policy_dir}/memory.conf"
    ENABLE_WINS_SWAPFILE=0
    ENABLE_ZRAM_SWAP=0
    legacy_loop_swap_sources() { :; }
    printf '%s\n' \
      '/dev/root / ext4 defaults 0 1' \
      "${WINS_SWAPFILE_PATH} none swap sw 0 0" \
      '/dev/sda2 none swap sw 0 0' > "${WINS_FSTAB_PATH}"
    : > "${WINS_SWAPFILE_PATH}"
    configure_swap_policy
    [[ -e "${WINS_SWAPFILE_PATH}" ]]
    if grep -Eq '^[[:space:]]*[^#[:space:]]+[[:space:]]+([^[:space:]]+[[:space:]]+)?swap([[:space:]]|$)' "${WINS_FSTAB_PATH}"; then false; fi
    grep -Fxq '/dev/root / ext4 defaults 0 1' "${WINS_FSTAB_PATH}"
  )

  (
    WINS_DEFAULTS_FILE="${policy_dir}/absent-defaults"
    WINS_SECRETS_FILE="${policy_dir}/absent-secrets"
    NODE_ENV_FILE="${policy_dir}/absent-node"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CORE_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { :; }
    sysctl() { :; }
    root_backed_by_luks() { return 0; }
    unencrypted_swap_devices() { printf '%s\n' /dev/sda2; }
    swapoff() { return 1; }
    WINS_FSTAB_PATH="${policy_dir}/failure-fstab"
    WINS_SWAPFILE_PATH="${policy_dir}/failure-swapfile"
    WINS_MEMORY_SYSCTL_PATH="${policy_dir}/failure-memory.conf"
    ENABLE_WINS_SWAPFILE=0
    ENABLE_ZRAM_SWAP=0
    legacy_loop_swap_sources() { :; }
    printf '%s\n' \
      '/dev/root / ext4 defaults 0 1' \
      '/dev/sda2 none swap sw 0 0' > "${WINS_FSTAB_PATH}"
    if configure_swap_policy; then
      echo "Core plaintext swap disable failure did not stop deployment" >&2
      return 1
    fi
    grep -Fq '/dev/sda2 none swap' "${WINS_FSTAB_PATH}"
  )
  echo "PASS Core persisted and active plaintext-swap remediation"
}

test_control_nginx_capacity_tuning() {
  local nginx_main="${work_dir}/nginx-capacity.conf"
  printf '%s\n' \
    'user www-data;' \
    'worker_processes 2;' \
    'pid /run/nginx.pid;' \
    'events {' \
    '    worker_connections 768;' \
    '}' \
    'http { include /etc/nginx/mime.types; }' > "${nginx_main}"

  for _ in 1 2; do
    extract_heredoc "${CONTROL_SCRIPT}" \
      'python3 - "${nginx_main_config}" "${nginx_worker_connections}" "${nginx_nofile_limit}"' PYEOF \
      | python3 - "${nginx_main}" 8192 65535
  done
  [[ "$(grep -Fc 'worker_processes auto;' "${nginx_main}")" == "1" ]]
  [[ "$(grep -Fc 'worker_rlimit_nofile 65535;' "${nginx_main}")" == "1" ]]
  [[ "$(grep -Fc 'worker_connections 8192;' "${nginx_main}")" == "1" ]]
  echo "PASS control Nginx dynamic worker and file-descriptor capacity tuning"
}

test_proxy_role_nginx_capacity_tuning() {
  local role="$1" script="$2"
  local role_dir="${work_dir}/${role}-nginx-capacity"
  local nginx_main="${role_dir}/nginx.conf"
  local nginx_conf_d="${role_dir}/conf.d"
  local nginx_dropin_dir="${role_dir}/nginx.service.d"
  mkdir -p "${nginx_conf_d}" "${nginx_dropin_dir}" "${role_dir}/logs"
  cat > "${nginx_main}" <<EOF
pid ${role_dir}/nginx.pid;
error_log ${role_dir}/logs/error.log;
worker_processes 2;
events {
    worker_connections 768;
}
http {
    include /etc/nginx/mime.types;
    # Keep nginx -t off the host's /var/lib/nginx, as above.
    client_body_temp_path ${role_dir}/logs/body;
    proxy_temp_path ${role_dir}/logs/proxy;
    fastcgi_temp_path ${role_dir}/logs/fastcgi;
    uwsgi_temp_path ${role_dir}/logs/uwsgi;
    scgi_temp_path ${role_dir}/logs/scgi;
    include ${nginx_conf_d}/*.conf;
    server {
        listen 127.0.0.1:18081;
        location /wins-capacity-test {
            limit_conn wins_xray_total 26214;
            limit_conn_status 503;
            return 204;
        }
    }
}
EOF

  (
    export WINS_DEFAULTS_FILE="${role_dir}/missing-defaults.env"
    export WINS_SECRETS_FILE="${role_dir}/missing-secrets.env"
    export NODE_ENV_FILE="${role_dir}/missing-node.env"
    export CORE_ENV_FILE="${role_dir}/missing-core.env"
    export NGINX_WORKER_CONNECTIONS=8192
    export NGINX_WORKER_NOFILE_LIMIT=16384
    export NGINX_PROXY_HEADROOM_PERCENT=35
    if [[ "${role}" == "data" ]]; then
      export DATA_NGINX_WORKER_CONNECTIONS=32768
      export DATA_NGINX_WORKER_NOFILE_LIMIT=65535
      export DATA_NGINX_PROXY_HEADROOM_PERCENT=20
    else
      export CORE_NGINX_WORKER_CONNECTIONS=32768
      export CORE_NGINX_WORKER_NOFILE_LIMIT=65535
      export CORE_NGINX_PROXY_HEADROOM_PERCENT=20
    fi
    set --
    # shellcheck disable=SC1090
    source "${script}"
    [[ "${NGINX_WORKER_CONNECTIONS}" == "32768" ]]
    [[ "${NGINX_WORKER_NOFILE_LIMIT}" == "65535" ]]
    [[ "${NGINX_PROXY_HEADROOM_PERCENT}" == "20" ]]
    WINS_NGINX_MAIN_CONFIG="${nginx_main}"
    WINS_NGINX_HTTP_CONF_D="${nginx_conf_d}"
    WINS_NGINX_SYSTEMD_DROPIN_DIR="${nginx_dropin_dir}"
    nginx_worker_process_count() { printf '2'; }
    systemctl() { [[ "$#" == "1" && "$1" == "daemon-reload" ]]; }

    [[ "$(nginx_effective_proxy_capacity)" == "26214" ]]
    if validate_nginx_capacity_inputs 4095 65535 20 >/dev/null 2>&1; then false; fi
    if validate_nginx_capacity_inputs 32768 32767 20 >/dev/null 2>&1; then false; fi
    if validate_nginx_capacity_inputs 32768 65535 9 >/dev/null 2>&1; then false; fi
    if configure_nginx_capacity 26215 >/dev/null 2>&1; then false; fi
    if [[ "${role}" == "data" ]]; then
      [[ "$(calculate_node_max_peers 26214)" == "26214" ]]
      if calculate_node_max_peers 26215 >/dev/null 2>&1; then false; fi
    else
      [[ "$(resolve_core_xray_connection_limit auto)" == "26214" ]]
      [[ "$(resolve_core_xray_connection_limit 26214)" == "26214" ]]
      if resolve_core_xray_connection_limit 26215 >/dev/null 2>&1; then false; fi
      nginx_worker_process_count() { printf '16'; }
      [[ "$(nginx_effective_proxy_capacity)" == "209712" ]]
      [[ "$(resolve_core_xray_connection_limit auto)" == "65535" ]]
      [[ "$(resolve_core_xray_connection_limit 65535)" == "65535" ]]
      if resolve_core_xray_connection_limit 65536 >/dev/null 2>&1; then false; fi
      nginx_worker_process_count() { printf '2'; }
    fi
    configure_nginx_capacity 26214
    configure_nginx_capacity 26214
  )

  [[ "$(grep -Fc 'worker_processes auto;' "${nginx_main}")" == "1" ]]
  [[ "$(grep -Fc 'worker_rlimit_nofile 65535;' "${nginx_main}")" == "1" ]]
  [[ "$(grep -Fc 'worker_connections 32768;' "${nginx_main}")" == "1" ]]
  [[ "$(grep -Fc 'limit_conn_zone $server_name zone=wins_xray_total:1m;' "${nginx_conf_d}/30-wins-xray-capacity.conf")" == "1" ]]
  [[ "$(grep -Fc 'LimitNOFILE=65535' "${nginx_dropin_dir}/30-wins-performance.conf")" == "1" ]]
  nginx -t -c "${nginx_main}" -p "${role_dir}" >/dev/null
  echo "PASS ${role} Nginx idempotent worker/NOFILE tuning and two-socket Xray admission invariant"
}

test_core_package_security_preimage() {
  local helper="${work_dir}/core-package-security-preimage.sh"
  local fixture="${work_dir}/core-package-security-fixture"
  local missing="${work_dir}/core-package-security-missing"
  local zero="${work_dir}/core-package-security-zero"
  local mock_save="${work_dir}/mock-iptables-save"
  local mock_zero="${work_dir}/mock-iptables-save-zero"
  local mock_ip6="${work_dir}/mock-ip6tables-save"
  local mock_systemctl="${work_dir}/mock-core-systemctl"
  local mock_suricata="${work_dir}/mock-core-suricata"
  local mock_suricatasc="${work_dir}/mock-core-suricatasc"
  local mock_restore="${work_dir}/mock-iptables-restore"
  local queue_file="${work_dir}/nfnetlink_queue"
  # 6a9f7ec: the protected rule count is derived from the queued TCP stealth
  # transports (encrypted UDP ingress is no longer queued) when Core IDS/IPS is
  # enabled. The extracted helpers do not carry the installer globals, so pin
  # both inputs here: five transports match the five mocked queue rules below.
  local -x INSTALL_CORE_IDS_IPS=1
  local -x CORE_STEALTH_TRANSPORTS='80:none,443:tls,10001:none,10002:tls,8443:tls'

  sed -n '/^cleanup_core_package_security_preimage_temporary() {$/,/^}$/p' "${CORE_SCRIPT}" > "${helper}"
  sed -n '/^capture_core_package_security_preimage() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${helper}"
  sed -n '/^install_core_failure_hold_firewall() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${helper}"
  sed -n '/^restore_core_package_security_preimage() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${helper}"
  sed -n '/^cleanup_core_firewall_transaction_workspace() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${helper}"
  sed -n '/^core_deployment_exit_handler() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${helper}"
  sed -n '/^core_deployment_error_handler() {$/,/^}$/p' "${CORE_SCRIPT}" >> "${helper}"
  bash -n "${helper}"
  grep -Fq 'capture_core_package_security_preimage' "${CORE_SCRIPT}"
  python3 - "${CORE_SCRIPT}" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
capture = text.index("  capture_core_package_security_preimage\n")
error_trap = text.index("  trap 'core_deployment_error_handler", text.rfind("\nmain() {"))
mutation = text.index("  apt_install\n", capture)
assert error_trap < capture < mutation
PY

  cat > "${mock_save}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]'
for port in 80 443 10001 10002 8443; do
  printf '%s\n' "-A TEST -p tcp --dport ${port} -j NFQUEUE --queue-num 0"
done
printf '%s\n' COMMIT
EOF
  cat > "${mock_zero}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' COMMIT
EOF
  cat > "${mock_ip6}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT DROP [0:0]' COMMIT
EOF
  chmod 700 "${mock_save}" "${mock_zero}" "${mock_ip6}"
  cat > "${mock_systemctl}" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  daemon-reload|reset-failed|restart) exit 0 ;;
  is-active) exit 0 ;;
  *) exit 64 ;;
esac
EOF
  cat > "${mock_suricata}" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == --build-info ]] && { echo 'NFQ support: yes'; exit 0; }
[[ "${1:-}" == -T ]] && exit 0
exit 64
EOF
  cat > "${mock_suricatasc}" <<'EOF'
#!/usr/bin/env bash
[[ "$*" == '-c uptime' ]]
EOF
  cat > "${mock_restore}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
payload="$(cat)"
if [[ " $* " != *' --test '* ]]; then
  if grep -q -- '--queue-num 0' <<<"${payload}"; then
    printf '%s\n' "${payload}" > "${MOCK_RESTORE_RECEIPT:?}"
  fi
fi
EOF
  chmod 700 "${mock_systemctl}" "${mock_suricata}" "${mock_suricatasc}" "${mock_restore}"
  printf '%s\n' '0 0 0 0 0 0 0 0 0' > "${queue_file}"

  prepare_fixture() {
    local root="$1"
    install -d -m 755 "${root}/etc/suricata" \
      "${root}/etc/systemd/system/suricata.service.d" \
      "${root}/lib/systemd/system"
    printf '%s\n' 'vars:' '  address-groups: {}' > "${root}/etc/suricata/suricata.yaml"
    printf '%s\n' '[Service]' 'ExecStart=' \
      'ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0 -c /etc/suricata/suricata.yaml' \
      > "${root}/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf"
    printf '%s\n' '[Service]' 'ExecStart=/usr/bin/suricata --af-packet' \
      > "${root}/lib/systemd/system/suricata.service"
    chmod 644 "${root}/etc/suricata/suricata.yaml" \
      "${root}/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf" \
      "${root}/lib/systemd/system/suricata.service"
  }

  prepare_fixture "${fixture}"
  local vendor_before captured_vendor
  vendor_before="$(sha256sum "${fixture}/lib/systemd/system/suricata.service" | awk '{print $1}')"
  (
    log() { :; }; warn() { :; }; err() { printf '%s\n' "$*" >&2; }
    # shellcheck source=/dev/null
    source "${helper}"
    WINS_CORE_SECURITY_ROOT="${fixture}" CORE_SECURITY_FORCE_EXISTING=1 \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_save}" \
      CORE_SECURITY_IP6TABLES_SAVE_BIN="${mock_ip6}" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${fixture}/preimage" \
      capture_core_package_security_preimage
  )
  (cd "${fixture}/preimage" && sha256sum -c files.sha256 >/dev/null)
  grep -Fxq 'expected_nfqueue_rules=5' "${fixture}/preimage/contract.env"
  [[ "$(grep -c -- '--queue-num 0' "${fixture}/preimage/live.rules.v4")" == 5 ]]
  [[ -s "${fixture}/preimage/suricata.yaml" ]]
  [[ -s "${fixture}/preimage/30-wins-inline-ips.conf" ]]
  captured_vendor="$(sha256sum "${fixture}/preimage/suricata.vendor.service" | awk '{print $1}')"
  [[ "${captured_vendor}" == "${vendor_before}" ]]
  printf '%s\n' '[Service]' 'ExecStart=/usr/bin/suricata --replacement-vendor-unit' \
    > "${fixture}/lib/systemd/system/suricata.service"
  [[ "$(sha256sum "${fixture}/preimage/suricata.vendor.service" | awk '{print $1}')" == "${vendor_before}" ]]
  printf '%s\n' 'replaced config' > "${fixture}/etc/suricata/suricata.yaml"
  printf '%s\n' '[Service]' 'ExecStart=/usr/bin/suricata --af-packet' \
    > "${fixture}/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf"
  (
    log() { :; }; warn() { :; }; err() { printf '%s\n' "$*" >&2; }
    source "${helper}"
    export CORE_SECURITY_SYSTEMCTL_BIN="${mock_systemctl}"
    export CORE_SECURITY_SURICATA_BIN="${mock_suricata}"
    export CORE_SECURITY_SURICATASC_BIN="${mock_suricatasc}"
    export CORE_SECURITY_IPTABLES_RESTORE_BIN="${mock_restore}"
    export CORE_SECURITY_IP6TABLES_RESTORE_BIN="${mock_restore}"
    export CORE_NFQUEUE_PROC_PATH="${queue_file}"
    export MOCK_RESTORE_RECEIPT="${fixture}/restored-live.rules.v4"
    restore_core_package_security_preimage "${fixture}/preimage"
  )
  [[ "$(sha256sum "${fixture}/lib/systemd/system/suricata.service" | awk '{print $1}')" == "${vendor_before}" ]]
  cmp -s "${fixture}/etc/suricata/suricata.yaml" "${fixture}/preimage/suricata.yaml"
  cmp -s "${fixture}/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf" \
    "${fixture}/preimage/30-wins-inline-ips.conf"
  [[ "$(grep -c -- '--queue-num 0' "${fixture}/restored-live.rules.v4")" == 5 ]]

  # A contract without a valid count, or a snapshot that disagrees with its
  # count, is refused before any Suricata file or firewall rule is restored.
  local refused="${work_dir}/core-package-security-refused" refused_case
  for refused_case in missing-count mismatched-count; do
    rm -rf "${refused}"
    prepare_fixture "${refused}"
    (
      log() { :; }; warn() { :; }; err() { :; }
      source "${helper}"
      WINS_CORE_SECURITY_ROOT="${refused}" CORE_SECURITY_FORCE_EXISTING=1 \
        CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_save}" \
        CORE_SECURITY_IP6TABLES_SAVE_BIN="${mock_ip6}" \
        CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${refused}/preimage" \
        capture_core_package_security_preimage
    )
    if [[ "${refused_case}" == missing-count ]]; then
      sed -i '/^expected_nfqueue_rules=/d' "${refused}/preimage/contract.env"
    else
      sed -i 's/^expected_nfqueue_rules=.*/expected_nfqueue_rules=4/' "${refused}/preimage/contract.env"
    fi
    (cd "${refused}/preimage" && rm -f files.sha256 && sha256sum ./* > files.sha256)
    printf '%s\n' 'post-failure config' > "${refused}/etc/suricata/suricata.yaml"
    if (
      log() { :; }; warn() { :; }; err() { :; }
      source "${helper}"
      export CORE_SECURITY_SYSTEMCTL_BIN="${mock_systemctl}"
      export CORE_SECURITY_SURICATA_BIN="${mock_suricata}"
      export CORE_SECURITY_SURICATASC_BIN="${mock_suricatasc}"
      export CORE_SECURITY_IPTABLES_RESTORE_BIN="${mock_restore}"
      export CORE_SECURITY_IP6TABLES_RESTORE_BIN="${mock_restore}"
      export CORE_NFQUEUE_PROC_PATH="${queue_file}"
      export MOCK_RESTORE_RECEIPT="${refused}/restored-live.rules.v4"
      restore_core_package_security_preimage "${refused}/preimage"
    ); then
      err "Core package rollback accepted a contract with ${refused_case}."
      return 1
    fi
    grep -Fxq 'post-failure config' "${refused}/etc/suricata/suricata.yaml"
    [[ ! -e "${refused}/restored-live.rules.v4" ]]
  done

  prepare_fixture "${missing}"
  rm -f "${missing}/etc/suricata/suricata.yaml"
  if (
    log() { :; }; warn() { :; }; err() { :; }
    source "${helper}"
    WINS_CORE_SECURITY_ROOT="${missing}" CORE_SECURITY_FORCE_EXISTING=1 \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_save}" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${missing}/preimage" \
      capture_core_package_security_preimage && touch "${missing}/package-mutation"
  ); then
    err 'Core package security preimage accepted an installed role with missing Suricata config.'
    return 1
  fi
  [[ ! -e "${missing}/package-mutation" && ! -e "${missing}/preimage" ]]

  prepare_fixture "${zero}"
  if (
    log() { :; }; warn() { :; }; err() { :; }
    source "${helper}"
    WINS_CORE_SECURITY_ROOT="${zero}" CORE_SECURITY_FORCE_EXISTING=1 \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_zero}" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${zero}/preimage" \
      capture_core_package_security_preimage && touch "${zero}/package-mutation"
  ); then
    err 'Core package security preimage accepted a zero-NFQUEUE live ruleset.'
    return 1
  fi
  [[ ! -e "${zero}/package-mutation" && ! -e "${zero}/preimage" ]]

  local forced="${work_dir}/core-package-security-forced-cleanup" forced_rc
  prepare_fixture "${forced}"
  set +e
  (
    set -Eeuo pipefail
    log() { :; }; warn() { :; }; err() { :; }
    source "${helper}"
    trap 'cleanup_core_package_security_preimage_temporary' ERR
    WINS_CORE_SECURITY_ROOT="${forced}" CORE_SECURITY_FORCE_EXISTING=1 \
      CORE_SECURITY_IPTABLES_SAVE_BIN=/bin/false \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${forced}/preimage" \
      capture_core_package_security_preimage
  )
  forced_rc=$?
  set -e
  [[ "${forced_rc}" != 0 ]]
  [[ -z "$(find "${forced}" -maxdepth 3 -type d -name '.preimage.*' -print -quit)" ]]

  local automatic="${work_dir}/core-package-security-automatic"
  prepare_fixture "${automatic}"
  if (
    log() { :; }; warn() { :; }; err() { :; }
    source "${helper}"
    export CORE_SECURITY_SYSTEMCTL_BIN="${mock_systemctl}"
    export CORE_SECURITY_SURICATA_BIN="${mock_suricata}"
    export CORE_SECURITY_SURICATASC_BIN="${mock_suricatasc}"
    export CORE_SECURITY_IPTABLES_RESTORE_BIN="${mock_restore}"
    export CORE_SECURITY_IP6TABLES_RESTORE_BIN="${mock_restore}"
    export CORE_NFQUEUE_PROC_PATH="${queue_file}"
    export MOCK_RESTORE_RECEIPT="${automatic}/automatic-restored.rules.v4"
    WINS_CORE_SECURITY_ROOT="${automatic}" CORE_SECURITY_FORCE_EXISTING=1 \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_save}" \
      CORE_SECURITY_IP6TABLES_SAVE_BIN="${mock_ip6}" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${automatic}/preimage" \
      capture_core_package_security_preimage
    printf '%s\n' 'package replacement' > "${automatic}/etc/suricata/suricata.yaml"
    core_deployment_error_handler 23
  ); then
    err 'Core deployment error handler lost the original failure status.'
    return 1
  fi
  cmp -s "${automatic}/etc/suricata/suricata.yaml" "${automatic}/preimage/suricata.yaml"
  [[ "$(grep -c -- '--queue-num 0' "${automatic}/automatic-restored.rules.v4")" == 5 ]]

  local fresh="${work_dir}/core-package-security-fresh"
  local mock_hold_state="${fresh}/hold-active"
  local mock_dynamic_save="${work_dir}/mock-iptables-save-dynamic"
  local mock_hold_iptables="${work_dir}/mock-iptables-hold"
  cat > "${mock_dynamic_save}" <<'EOF'
#!/usr/bin/env bash
if [[ -e "${MOCK_HOLD_STATE:?}" ]]; then
  printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' \
    ':WINVPN-CORE-FAILURE-HOLD-IN - [0:0]' ':WINVPN-CORE-FAILURE-HOLD-FWD - [0:0]' \
    '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' \
    '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD' \
    '-A WINVPN-CORE-FAILURE-HOLD-IN -i lo -j ACCEPT' \
    '-A WINVPN-CORE-FAILURE-HOLD-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' \
    '-A WINVPN-CORE-FAILURE-HOLD-IN -j DROP' \
    '-A WINVPN-CORE-FAILURE-HOLD-FWD -j DROP' COMMIT
else
  for port in 80 443 10001 10002 8443; do
    printf '%s\n' "-A TEST -p tcp --dport ${port} -j NFQUEUE --queue-num 0"
  done
fi
EOF
  cat > "${mock_hold_iptables}" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -C ]]; then [[ -e "${MOCK_HOLD_STATE:?}" ]]; exit; fi
if [[ "${1:-}" == -S && "${2:-}" == INPUT ]]; then
  printf '%s\n' '-P INPUT DROP' '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN'; exit 0
fi
if [[ "${1:-}" == -S && "${2:-}" == FORWARD ]]; then
  printf '%s\n' '-P FORWARD DROP' '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD'; exit 0
fi
exit 1
EOF
  chmod 700 "${mock_dynamic_save}" "${mock_hold_iptables}"
  install -d -m 755 "${fresh}"
  if (
    log() { :; }; warn() { :; }; err() { :; }
    source "${helper}"
    export MOCK_HOLD_STATE="${mock_hold_state}"
    export MOCK_RESTORE_RECEIPT="${fresh}/unused.rules"
    WINS_CORE_SECURITY_ROOT="${fresh}" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${fresh}/preimage" \
      capture_core_package_security_preimage
    touch "${mock_hold_state}"
    CORE_ADMIN_CIDR=127.0.0.1/32 \
      CORE_SECURITY_IPTABLES_RESTORE_BIN="${mock_restore}" \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_dynamic_save}" \
      CORE_SECURITY_IPTABLES_BIN="${mock_hold_iptables}" \
      CORE_FAILURE_HOLD_RECEIPT_ROOT="${fresh}/var/lib/winsvpn-deployment/core-firewall-failure-holds" \
      core_deployment_error_handler 29
  ); then
    err 'Fresh Core deployment failure handler lost the original status.'
    return 1
  fi
  grep -Fxq 'state=fresh' "${fresh}/preimage/contract.env"
  [[ -s "${fresh}/var/lib/winsvpn-deployment/core-firewall-failure-holds/latest.receipt" ]]

  # Simulate the package-created Suricata files now present on the rerun. Only
  # the exact root-only installer hold may be classified as degraded; arbitrary
  # zero-NFQUEUE state remains rejected by the earlier zero-rule fixture.
  prepare_fixture "${fresh}"
  (
    log() { :; }; warn() { :; }; err() { printf '%s\n' "$*" >&2; }
    source "${helper}"
    export MOCK_HOLD_STATE="${mock_hold_state}"
    WINS_CORE_SECURITY_ROOT="${fresh}" \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_dynamic_save}" \
      CORE_SECURITY_IPTABLES_BIN="${mock_hold_iptables}" \
      CORE_FAILURE_HOLD_RECEIPT_ROOT="${fresh}/var/lib/winsvpn-deployment/core-firewall-failure-holds" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${fresh}/preimage-degraded" \
      capture_core_package_security_preimage
  )
  grep -Fxq 'state=degraded' "${fresh}/preimage-degraded/contract.env"
  [[ "$(grep -c -- '--queue-num 0' "${fresh}/preimage-degraded/live.rules.v4" || true)" == 0 ]]
  rm -f "${mock_hold_state}" \
    "${fresh}/var/lib/winsvpn-deployment/core-firewall-failure-holds/latest.receipt"
  (
    log() { :; }; warn() { :; }; err() { printf '%s\n' "$*" >&2; }
    source "${helper}"
    export MOCK_HOLD_STATE="${mock_hold_state}"
    WINS_CORE_SECURITY_ROOT="${fresh}" CORE_SECURITY_FORCE_EXISTING=1 \
      CORE_SECURITY_IPTABLES_SAVE_BIN="${mock_dynamic_save}" \
      CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${fresh}/preimage-committed" \
      capture_core_package_security_preimage
  )
  grep -Fxq 'state=protected' "${fresh}/preimage-committed/contract.env"
  [[ "$(grep -c -- '--queue-num 0' "${fresh}/preimage-committed/live.rules.v4")" == 5 ]]

  grep -Fq 'core-package-security-preimage' "${ROOT_DIR}/tools/capture_live_infrastructure_rollback.ps1"
  # The live rollback capture must derive its NFQUEUE count the way the
  # installer does, never pin one, and record it in the same contract.env.
  python3 - "${ROOT_DIR}/tools/capture_live_infrastructure_rollback.ps1" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if re.search(r'nfqueue_count"?\s*(?:==|-eq)\s*"?[0-9]', text):
    raise SystemExit("rollback capture pins a literal NFQUEUE rule count")
for needle in (
    'expected_nfqueue_rules="$(core_expected_nfqueue_rules /root/wins_core.env)"',
    '[[ "$nfqueue_count" == "$expected_nfqueue_rules" ]]',
    "printf 'expected_nfqueue_rules=%s\\n' \"$expected_nfqueue_rules\"",
    '} > "$security/contract.env"',
):
    if needle not in text:
        raise SystemExit(f"rollback capture lacks the derived-count contract: {needle}")
if text.index('} > "$security/contract.env"') > text.index('(cd "$security" && sha256sum ./* > files.sha256)'):
    raise SystemExit("rollback capture writes contract.env after hashing the snapshot")
PY
  local ps1_count="${work_dir}/rollback-ps1-count.sh" count_env="${work_dir}/rollback-count.env"
  sed -n '/^core_expected_nfqueue_rules() {$/,/^}$/p' \
    "${ROOT_DIR}/tools/capture_live_infrastructure_rollback.ps1" > "${ps1_count}"
  [[ -s "${ps1_count}" ]]
  write_count_env() {
    # Same serialization as the installer's load_or_create_env (printf %q).
    { printf 'INSTALL_CORE_IDS_IPS=%q\n' "$1"; printf 'CORE_STEALTH_TRANSPORTS=%q\n' "$2"; } > "${count_env}"
    chmod 0600 "${count_env}"
  }
  # shellcheck source=/dev/null
  ps1_expected_count() { ( source "${ps1_count}"; core_expected_nfqueue_rules "${count_env}" ); }
  # Parity with the installer: the contract it wrote above for these inputs.
  write_count_env 1 "${CORE_STEALTH_TRANSPORTS}"
  [[ "$(ps1_expected_count)" == "$(sed -n 's/^expected_nfqueue_rules=//p' "${fixture}/preimage/contract.env")" ]]
  write_count_env 1 '80:none,443:tls'
  [[ "$(ps1_expected_count)" == 2 ]]
  write_count_env 0 '80:none,443:tls'
  [[ "$(ps1_expected_count)" == 0 ]]
  # Unparseable persisted values fail closed instead of defaulting, and the
  # file is parsed, never executed.
  # shellcheck disable=SC2016
  write_count_env 1 '80:none,$(touch '"${work_dir}"'/rollback-count-pwned)'
  if ps1_expected_count >/dev/null 2>&1; then
    err 'Rollback capture accepted an unparseable CORE_STEALTH_TRANSPORTS value.'
    return 1
  fi
  [[ ! -e "${work_dir}/rollback-count-pwned" ]]
  printf '%s\n' 'INSTALL_CORE_IDS_IPS=1' \
    "CORE_STEALTH_TRANSPORTS=\$(touch ${work_dir}/rollback-count-pwned)" > "${count_env}"
  if ps1_expected_count >/dev/null 2>&1; then
    err 'Rollback capture accepted a command substitution in CORE_STEALTH_TRANSPORTS.'
    return 1
  fi
  [[ ! -e "${work_dir}/rollback-count-pwned" ]]
  write_count_env '' '80:none,443:tls'
  if ps1_expected_count >/dev/null 2>&1; then
    err 'Rollback capture accepted a missing INSTALL_CORE_IDS_IPS value.'
    return 1
  fi
  grep -Fq '30-wins-inline-ips.conf' "${ROOT_DIR}/tools/capture_live_infrastructure_rollback.ps1"
  echo 'PASS Core pre-mutation snapshot, automatic protected rollback, and fresh-host failure contracts'
}

# OI-E2E-8: in `cmd | grep -q PATTERN` under pipefail, grep -q exits on the
# first match and the writer can die of SIGPIPE (141). The pipeline then fails,
# so a negative check (`if ... | grep -q; then fail; fi`) passes on the very
# content it forbids. Every match in this file is capture-then-match; keep it so.
# Round 3: bash itself parses the file (bash -n, then `declare -f` prints it in
# canonical form, one pipeline per line), so a pipe split across lines, `|&`
# and grep options in any position are all seen. A self-test arm proves the
# scanner still finds known offenders before it may pass this file.
test_suite_has_no_early_exit_grep_pipelines() {
  local suite="${ROOT_DIR}/tools/test_deployment_runtime_configs.sh"
  bash -n "${suite}"
  python3 - "${suite}" "${BASH}" <<'PYEOF'
import re
import subprocess
import sys

# Bash itself validates (bash -n) and canonicalises the text: wrapped in a
# function and printed by `declare -f`, every pipeline sits on one line,
# backslash continuations and a trailing `|` are joined, `|&` becomes
# `2>&1 |`, and comments are gone. A small tokenizer then walks the
# canonical text, including $(...), `...`, <(...) and every heredoc whose
# body is itself a bash script, and reports each pipeline whose last command
# is grep (grep, egrep, fgrep, any path, after command/builtin/exec/env and
# VAR=value prefixes) with an early-exit option in any position before `--`:
# -q -l -L -m (also inside clusters such as -Fxq), --quiet, --silent,
# --max-count, --files-with-matches, --files-without-match.
# Not covered (none occur in this file): a grep reached through a variable
# ("${GREP}"), other early-exit readers (head, awk ... exit, sed q, read), a
# group after the pipe (`a | { grep -q x; }`), and command substitutions
# inside `[[ ... ]]`.
BASH = sys.argv[2]
ARG_SHORT = set("efABCdD")
EARLY_SHORT = set("qlLm")
EARLY_LONG = ("--quiet", "--silent", "--max-count", "--files-with-matches", "--files-without-match")
GREPS = {"grep", "egrep", "fgrep"}
PREFIX_WORDS = {"command", "builtin", "exec", "nohup"}
KEYWORDS = {"if", "then", "elif", "else", "do", "while", "until", "!", "time", "{", "}", "fi", "done", "esac"}


def canonical(text, label):
    check = subprocess.run([BASH, "--norc", "--noprofile", "-n"], input=text, text=True, capture_output=True)
    if check.returncode != 0:
        raise SystemExit(f"{label}: bash -n failed: {check.stderr.strip()[:300]}")
    wrapped = "__wins_lint_body() {\n" + text + "\n}\ndeclare -f __wins_lint_body\n"
    out = subprocess.run([BASH, "--norc", "--noprofile", "-c", 'eval "$(cat)"'], input=wrapped,
                         text=True, capture_output=True)
    if out.returncode != 0 or not out.stdout.startswith("__wins_lint_body"):
        raise SystemExit(f"{label}: bash could not canonicalise the text: {out.stderr.strip()[:300]}")
    return out.stdout


def grep_exits_early(words):
    k = 0
    while k < len(words) and ("=" in words[k] and words[k].split("=", 1)[0].isidentifier()):
        k += 1
    while k < len(words) and words[k] in PREFIX_WORDS | {"env"}:
        k += 1
        while k < len(words) and (words[k].startswith("-") or ("=" in words[k] and words[k].split("=", 1)[0].isidentifier())):
            k += 1
    if k >= len(words):
        return False
    name = words[k].lstrip("\\").rsplit("/", 1)[-1]
    if name not in GREPS:
        return False
    args = words[k + 1:]
    j = 0
    while j < len(args):
        arg = args[j]
        j += 1
        if arg == "--":
            break
        if arg.startswith("--"):
            if arg.split("=", 1)[0] in EARLY_LONG:
                return True
            continue
        if arg.startswith("-") and len(arg) > 1:
            for pos, letter in enumerate(arg[1:]):
                if letter in EARLY_SHORT:
                    return True
                if letter in ARG_SHORT:
                    if pos == len(arg) - 2:
                        j += 1  # the option's value is the next word
                    break
    return False


def balanced(text, i, open_ch, close_ch, depth=1):
    """text[i] is just after the opening bracket(s); return the index after the close."""
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            i = text.index("'", i + 1) + 1
            continue
        if ch == '"':
            i = dquote_end(text, i + 1)
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise SystemExit("unbalanced bracket in canonical text")


def dquote_end(text, i):
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            return i + 1
        if text.startswith("$(", i):
            i = balanced(text, i + 2, "(", ")")
            continue
        if ch == "`":
            i = text.index("`", i + 1) + 1
            continue
        i += 1
    raise SystemExit("unterminated double quote in canonical text")


def scan(text, label, findings, line_base=""):
    i, n = 0, len(text)
    word = None
    word_start = 0
    words, pipeline = [], []
    heredocs = []
    expect = None  # "redir" or "heredoc"
    joiner = False  # last token was | && || : newlines continue the list
    line_no = 1

    def flush_word():
        nonlocal word, expect
        if word is None:
            return
        if expect == "heredoc":
            raw = text[word_start:i]
            heredocs.append((word, any(c in raw for c in "'\"\\")))
        elif expect != "redir":
            words.append(word)
        expect = None
        word = None

    def end_command():
        nonlocal words
        flush_word()
        if words and words[0] in KEYWORDS:
            while words and words[0] in KEYWORDS:
                words.pop(0)
        if words:
            pipeline.append(words)
        words = []

    def end_pipeline():
        nonlocal pipeline
        end_command()
        if len(pipeline) >= 2 and grep_exits_early(pipeline[-1]):
            findings.append(f"{label}{line_base}:{line_no}: " + " | ".join(" ".join(c) for c in pipeline)[:200])
        pipeline = []

    def sub(body):
        scan(body, label + " $(...)", findings, f"{line_base}:{line_no}")

    while i < n:
        ch = text[i]
        if ch == "\\":
            if i + 1 < n and text[i + 1] == "\n":
                i += 2
                continue
            if word is None:
                word_start = i
            word = (word or "") + text[i + 1:i + 2]
            i += 2
            continue
        if ch == "#" and word is None:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "'":
            end = text.index("'", i + 1)
            if word is None:
                word_start = i
            word = (word or "") + text[i + 1:end]
            i = end + 1
            joiner = False
            continue
        if ch == '"':
            end = dquote_end(text, i + 1)
            inner = text[i + 1:end - 1]
            k = 0
            while k < len(inner):
                if inner.startswith("$(", k) and not inner.startswith("$((", k):
                    stop = balanced(inner, k + 2, "(", ")")
                    sub(inner[k + 2:stop - 1])
                    k = stop
                elif inner[k] == "`":
                    stop = inner.index("`", k + 1)
                    sub(inner[k + 1:stop])
                    k = stop + 1
                elif inner[k] == "\\":
                    k += 2
                else:
                    k += 1
            if word is None:
                word_start = i
            word = (word or "") + inner
            i = end
            joiner = False
            continue
        if text.startswith("$((", i):
            stop = balanced(text, i + 3, "(", ")", depth=2)
            if word is None:
                word_start = i
            word = (word or "") + "$((...))"
            i = stop
            continue
        if text.startswith("$(", i) or text.startswith("<(", i) or text.startswith(">(", i):
            stop = balanced(text, i + 2, "(", ")")
            sub(text[i + 2:stop - 1])
            if word is None:
                word_start = i
            word = (word or "") + "$(...)"
            i = stop
            joiner = False
            continue
        if ch == "`":
            stop = text.index("`", i + 1)
            sub(text[i + 1:stop])
            if word is None:
                word_start = i
            word = (word or "") + "`...`"
            i = stop + 1
            continue
        if ch == "(" and word is not None and word.endswith("="):
            stop = balanced(text, i + 1, "(", ")")
            word += text[i:stop]
            i = stop
            continue
        if ch in " \t":
            flush_word()
            if words and words[-1] == "[[" and all(w in KEYWORDS for w in words[:-1]):
                stop = text.find(" ]]", i)
                if stop < 0:
                    raise SystemExit("unterminated [[ in canonical text")
                words[-1] = "[[...]]"
                i = stop + 3
                continue
            i += 1
            continue
        if ch == "\n":
            line_no += 1
            if joiner:
                flush_word()
                i += 1
                continue
            end_pipeline()
            i += 1
            for delim, quoted in heredocs:
                start = i
                while True:
                    eol = text.find("\n", i)
                    line = text[i:eol if eol >= 0 else n]
                    if line.lstrip("\t") == delim:
                        body = text[start:i]
                        if not quoted:
                            # What the shell writes for an unquoted delimiter:
                            # backslash quotes only $ ` \ and newline.
                            body = re.sub(r"\\([$`\\\n])", lambda m: "" if m.group(1) == "\n" else m.group(1), body)
                        line_no += body.count("\n") + 1
                        i = eol + 1 if eol >= 0 else n
                        first = body.split("\n", 1)[0]
                        if first.startswith("#!") and "bash" in first:
                            scan(canonical(body, f"{label} heredoc {delim}"), f"{label} heredoc {delim}", findings,
                                 f"{line_base}:{line_no}")
                        break
                    if eol < 0:
                        raise SystemExit(f"{label}: heredoc {delim} not terminated")
                    i = eol + 1
            heredocs = []
            continue
        if ch == "|":
            if text.startswith("||", i):
                end_pipeline()
                i += 2
            else:
                end_command()
                i += 2 if text.startswith("|&", i) else 1
            joiner = True
            continue
        if ch == "&":
            if text.startswith("&&", i):
                end_pipeline()
                i += 2
                joiner = True
                continue
            if text.startswith("&>", i):
                flush_word()
                i += 3 if text.startswith("&>>", i) else 2
                expect = "redir"
                continue
            end_pipeline()
            i += 1
            continue
        if ch in ";(){}" and word is None or ch in ";()":
            end_pipeline()
            i += 1
            joiner = False
            continue
        if ch in "<>":
            if word is not None and word.isdigit():
                word = None
            flush_word()
            if text.startswith("<<<", i):
                i += 3
                expect = "redir"
            elif text.startswith("<<-", i) or text.startswith("<<", i):
                i += 3 if text.startswith("<<-", i) else 2
                expect = "heredoc"
            else:
                i += 1
                while i < n and text[i] in ">&|":
                    i += 1
                if i < n and text[i].isdigit() and text[i - 1] == "&":
                    while i < n and text[i].isdigit():
                        i += 1
                    expect = None
                    continue
                expect = "redir"
            while i < n and text[i] in " \t":
                i += 1
            continue
        joiner = False
        if word is None:
            word_start = i
        word = (word or "") + ch
        i += 1
    end_pipeline()


SELF_TEST = r"""
a | grep -q x
a | grep -F -e 'NFQUEUE' -q
if grep -F -- '--dport 9210' "$r" | \
    grep -Fq -- 'NFQUEUE'; then false; fi
if grep x f |
   grep -F 'NFQUEUE' -q; then false; fi
a |& grep -Fq z
a | command grep -q z
a | LC_ALL=C grep --quiet z
a | /usr/bin/egrep -q 'a|b'
a | grep --fixed-strings --silent z
a | grep -m1 z
x="$(b | grep -lF y)"
cat > w <<'WEOF'
#!/usr/bin/env bash
ip rule show | grep -Eq '^1'
WEOF
grep -c x f
grep -q x <<<"$(ip rule show)"
a || grep -q x f
grep -Fq 'a | grep -q b' f
[[ "$x" =~ ^(#|$) ]] && continue
cat > p <<'PEOF'
print("a | grep -q b")
PEOF
a | grep -e -q x
"""
SELF_EXPECTED = 12


def lint(text, label):
    # One path for the self-test and for the suite, so a scanner that stops
    # finding offenders cannot pass the suite while the self-test is skipped.
    findings = []
    scan(canonical(text, label), label, findings)
    return findings


def main():
    findings = lint(SELF_TEST, "self-test")
    if len(findings) != SELF_EXPECTED:
        print("\n".join(findings), file=sys.stderr)
        raise SystemExit(f"section 72 self-test found {len(findings)} offenders, expected {SELF_EXPECTED}")
    suite = sys.argv[1]
    findings = lint(open(suite, encoding="utf-8").read(), suite)
    if findings:
        print("pipeline into an early-exit grep (capture the output, then match):", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        raise SystemExit(1)


main()
PYEOF
  echo "PASS runtime suite has no pipeline into an early-exit grep (bash-canonical scan, self-test 12 of 12)"
}

# N-10: every mock curl that stands in for the hub edge helpers must read its
# stdin config (mock_curl_read_stdin_config above). The race that helper closes
# is intermittent, so this checks the suite text instead of waiting for it: each
# `curl() {` mock that sets `output_file=` starts with the helper call, and the
# helper itself still reads stdin when curl is told `--config -`.
test_suite_edge_mock_curls_read_stdin_config() {
  python3 - "${ROOT_DIR}/tools/test_deployment_runtime_configs.sh" <<'PYEOF'
import re
import sys

lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
helper = None
mocks = []
for at, line in enumerate(lines):
    if line == "mock_curl_read_stdin_config() {":
        helper = "\n".join(lines[at:]).split("\n}\n", 1)[0]
    if re.match(r"^\s*curl\(\) \{\s*$", line):
        if "output_file=" in "\n".join(lines[at + 1:at + 16]):
            mocks.append((at + 1, lines[at + 1].strip()))
if helper is None or "cat > /dev/null" not in helper or '"--config"' not in helper or '"-K"' not in helper:
    raise SystemExit("mock_curl_read_stdin_config is missing or no longer reads a --config - / -K - stdin")
if len(mocks) < 8:
    raise SystemExit(f"found {len(mocks)} edge-style mock curls, expected at least 8: the scan is vacuous")
bad = [f"line {at}: first statement is {first!r}" for at, first in mocks if first != 'mock_curl_read_stdin_config "$@"']
if bad:
    raise SystemExit("mock curl that never reads its stdin config (printf | mock races under pipefail):\n" + "\n".join(bad))
print(f"PASS {len(mocks)} edge-style mock curls read their stdin config")
PYEOF
}

# CP-1 (pre-deploy audit 2026-10-01): the LUKS remote-unlock keys. Dropbear
# must only ever get inbound login keys (never this host's own id_*.pub,
# whose private halves sit on the locked disk), a redeploy keeps the keys
# already there unless LUKS_UNLOCK_SSH_AUTHORIZED_KEYS replaces them, the
# three files are backed up before a rewrite, and an unchanged configuration
# does not rebuild the initramfs. LUKS-FIX (2026-10-11): the control plane now
# writes the one early-boot network file winn-fde-network (DHCP with an EMPTY
# DEVICE, handoff section 42) and verifies the rebuilt initramfs; the data
# plane installer still writes the legacy wins-remote-unlock.
test_luks_unlock_keeps_operator_keys() {
  local d="${work_dir}/luks-unlock" role script unlock_name expected_net
  mkdir -p "${d}"
  ssh-keygen -q -t ed25519 -N '' -C 'operator-laptop' -f "${d}/operator"
  ssh-keygen -q -t ed25519 -N '' -C 'hub-node-mgmt-ed25519' -f "${d}/hub-ed25519"
  ssh-keygen -q -t ed25519 -N '' -C 'hub-node-mgmt-rsa-slot' -f "${d}/hub-rsa"
  for role in control data; do
    case "${role}" in
      control) script="${CONTROL_SCRIPT}"; unlock_name=winn-fde-network; expected_net="IP='dhcp'" ;;
      data) script="${DATA_SCRIPT}"; unlock_name=wins-remote-unlock; expected_net='IP=:::::ts0:dhcp' ;;
    esac
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      NODE_ENV_FILE="${d}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      log() { :; }
      warn() { printf '%s\n' "$*" >> "${d}/warn-${role}"; }
      err() { printf '%s\n' "$*" >> "${d}/err-${role}"; }
      root_backed_by_luks() { return 0; }
      unencrypted_swap_devices() { :; }
      apt_retry() { :; }
      APT_GET=(true)
      update-initramfs() { printf '%s\n' "$*" >> "${d}/initramfs-${role}"; }
      r="${d}/${role}"
      export WINS_ROOT_SSH_DIR="${r}/ssh" WINS_DROPBEAR_INITRAMFS_DIR="${r}/dropbear"
      export WINS_INITRAMFS_UNLOCK_CONF="${r}/conf.d/${unlock_name}" WINS_LUKS_UNLOCK_BACKUP_DIR="${r}/backup"
      LUKS_REMOTE_UNLOCK=1
      if [[ "${role}" == control ]]; then
        # DHCP early boot keeps DEVICE empty; the installer verifies every bootable initramfs after its rebuild.
        export WINS_INITRAMFS_TOOLS_DIR="${r}" WINS_BOOT_DIR="${r}/boot" WINS_MODULES_DIR="${r}/lib/modules"
        install -d "${r}/conf.d" "${r}/scripts/init-premount" "${r}/boot" "${r}/lib/modules/6.8.0-1-generic"
        printf 'initrd' > "${r}/boot/initrd.img-6.8.0-1-generic"
        lsinitramfs() {
          printf '%s\n' scripts/local-top/cryptroot conf/conf.d/winn-fde-network usr/sbin/dropbear \
            usr/sbin/cryptsetup scripts/init-premount/00-winn-fde-network scripts/init-premount/dropbear \
            usr/sbin/ip scripts/init-bottom/zz-winn-fde-network-handoff
        }
        unset LUKS_INITRAMFS_DEVICE
      else
        LUKS_INITRAMFS_DEVICE=ts0
      fi
      unset LUKS_UNLOCK_SSH_AUTHORIZED_KEYS LUKS_UNLOCK_SSH_PORT
      install -d -m 700 "${r}/ssh"
      cp "${d}/hub-ed25519.pub" "${r}/ssh/id_ed25519.pub"
      cp "${d}/hub-rsa.pub" "${r}/ssh/id_rsa.pub"
      cp "${d}/operator.pub" "${r}/ssh/authorized_keys"
      operator="$(<"${d}/operator.pub")"
      initramfs_runs() { if [[ -f "${d}/initramfs-${role}" ]]; then wc -l < "${d}/initramfs-${role}"; else echo 0; fi; }

      # 1. First configuration: the operator's login key only, never a host key.
      configure_luks_root_policy
      [[ "$(<"${r}/dropbear/authorized_keys")" == "${operator}" ]]
      [[ "$(stat -c '%a' "${r}/dropbear/authorized_keys")" == "600" ]]
      grep -Fxq 'DROPBEAR_OPTIONS="-I 180 -j -k -p 2222 -s -c cryptroot-unlock"' "${r}/dropbear/dropbear.conf"
      grep -Fxq "${expected_net}" "${r}/conf.d/${unlock_name}"
      if [[ "${role}" == control ]]; then grep -Fxq "DEVICE=''" "${r}/conf.d/${unlock_name}"; fi
      [[ "$(initramfs_runs)" == "1" ]]
      [[ "$(collect_luks_unlock_authorized_keys)" == "${operator}" ]]

      # 2. Rerun with nothing changed: no initramfs rebuild, no backup.
      configure_luks_root_policy
      [[ "$(initramfs_runs)" == "1" ]]
      [[ ! -e "${r}/backup" ]]

      # 3. The dropbear file already holds other keys (the hub's measured
      #    state: its own id_rsa.pub). Kept as they are, with a warning, and
      #    still no rebuild because nothing changed.
      cp "${d}/hub-rsa.pub" "${r}/dropbear/authorized_keys"
      configure_luks_root_policy
      cmp -s "${d}/hub-rsa.pub" "${r}/dropbear/authorized_keys"
      grep -Fq "include this host's own id_rsa.pub" "${d}/warn-${role}"
      [[ "$(initramfs_runs)" == "1" ]]

      # 4. A port change rewrites dropbear.conf: all three files are backed
      #    up first, the existing keys stay, and the initramfs is rebuilt.
      LUKS_UNLOCK_SSH_PORT=2223 configure_luks_root_policy
      [[ "$(initramfs_runs)" == "2" ]]
      cmp -s "${d}/hub-rsa.pub" "${r}/dropbear/authorized_keys"
      grep -Fq -- '-p 2223 ' "${r}/dropbear/dropbear.conf"
      backup="$(find "${r}/backup" -mindepth 1 -maxdepth 1 -type d -print)"
      [[ -n "${backup}" && "$(wc -l <<<"${backup}")" == "1" ]]
      [[ "$(stat -c '%a' "${backup}")" == "700" ]]
      cmp -s "${d}/hub-rsa.pub" "${backup}/authorized_keys"
      grep -Fq -- '-p 2222 ' "${backup}/dropbear.conf"
      grep -Fxq "${expected_net}" "${backup}/${unlock_name}"

      # 5. Only an explicit LUKS_UNLOCK_SSH_AUTHORIZED_KEYS replaces them.
      LUKS_UNLOCK_SSH_PORT=2223 LUKS_UNLOCK_SSH_AUTHORIZED_KEYS="${operator}" configure_luks_root_policy
      [[ "$(<"${r}/dropbear/authorized_keys")" == "${operator}" ]]
      [[ "$(initramfs_runs)" == "3" ]]

      # 6. No dropbear keys and no authorized_keys: refuse, even though the
      #    host's own public keys are present.
      rm -f "${r}/dropbear/authorized_keys" "${r}/ssh/authorized_keys"
      if (configure_luks_root_policy) >/dev/null 2>&1; then exit 1; fi
      [[ ! -e "${r}/dropbear/authorized_keys" ]]
      if collect_luks_unlock_authorized_keys >/dev/null; then exit 1; fi
      grep -Fq 'LUKS remote unlock needs an SSH public key' "${d}/err-${role}"
      [[ "$(initramfs_runs)" == "3" ]]
    )
  done
  echo "PASS LUKS remote unlock keeps the operator's dropbear keys, never selects host keys, backs up and rebuilds only on change (control, data)"
}

# CP-2: backup pruning never empties a whole Google Drive account's trash.
# On Drive only trashed objects under the hub's own backup prefix are
# permanently deleted; b2 and s3 get `rclone cleanup` on that prefix; nothing
# runs against a remote's root, and an unsupported backend still fails the
# run when pruning is required.
test_backup_prune_trash_scope() {
  local d="${work_dir}/prune-trash-scope" prune mock_bin wrapped rc
  mkdir -p "${d}/local" "${d}/manifests" "${d}/bin"
  prune="${d}/wins-hub-backup-prune"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /usr/local/bin/wins-hub-backup-prune <<'EOF'" EOF > "${prune}"
  bash -n "${prune}"
  mock_bin="${d}/bin"
  : > "${d}/rclone.conf"
  cat > "${mock_bin}/rclone" <<'EOF'
#!/usr/bin/env bash
printf 'rclone %s\n' "$*" >> "${MOCK_RCLONE_LOG:?}"
case "${1:-}" in
  config) jq -nc --arg t "${MOCK_WRAPPED_TYPE:?}" '{GoogleDrive_secured:{type:"crypt",remote:"backing:enc"},backing:{type:$t}}' ;;
  lsjson) printf '[]\n' ;;
  delete|rmdirs|cleanup) exit 0 ;;
  backend)
    case "${2:-}" in
      encode) printf 'encdir/enchost\n' ;;
      cleanup-hidden) exit 0 ;;
      *) exit 1 ;;
    esac
    ;;
  *) echo "unexpected mock rclone command: $*" >&2; exit 64 ;;
esac
EOF
  chmod 700 "${mock_bin}/rclone"
  run_prune() { # run_prune <wrapped type> <log> [VAR=value ...]
    local type="$1" log="$2"
    shift 2
    : > "${log}"
    env PATH="${mock_bin}:${PATH}" MOCK_RCLONE_LOG="${log}" MOCK_WRAPPED_TYPE="${type}" \
      WINS_BACKUP_ENV="${d}/absent-backup.env" WINS_LOCAL_BACKUP_DIR="${d}/local" \
      WINS_BACKUP_MANIFEST_DIR="${d}/manifests" WINS_RCLONE_CONFIG="${d}/rclone.conf" \
      BACKUP_HOST_ID=hub-test RCLONE_REMOTE=GoogleDrive_secured "$@" bash "${prune}" > "${log}.out" 2>&1
  }
  no_root_cleanup() { # nothing may run against a remote's root
    if grep -E '^rclone ((cleanup|delete)|backend cleanup-hidden) [A-Za-z0-9_]+:( |$)' "$1"; then
      echo "backup prune ran an account-wide rclone command" >&2
      return 1
    fi
  }

  run_prune drive "${d}/drive.log"
  grep -Fxq 'rclone delete GoogleDrive_secured:winsvpn-backups/hub-test --drive-trashed-only --drive-use-trash=false' "${d}/drive.log"
  if grep -E '^rclone cleanup ' "${d}/drive.log"; then
    echo "backup prune still empties the Drive trash with rclone cleanup" >&2
    return 1
  fi
  no_root_cleanup "${d}/drive.log"
  # The retention delete itself is unchanged.
  grep -Fxq 'rclone delete GoogleDrive_secured:winsvpn-backups/hub-test --min-age 30d --drive-use-trash=false' "${d}/drive.log"
  # Stage 6 on Drive: nothing to clean, so no cleanup-hidden at all.
  if grep -F 'cleanup-hidden' "${d}/drive.log"; then
    echo "stage 6 ran cleanup-hidden on a Drive remote" >&2
    return 1
  fi

  run_prune drive "${d}/drive-dry.log" BACKUP_PRUNE_DRY_RUN=1
  grep -Fxq 'rclone delete GoogleDrive_secured:winsvpn-backups/hub-test --drive-trashed-only --drive-use-trash=false --dry-run' "${d}/drive-dry.log"
  if grep -E '^rclone delete .*--drive-trashed-only --drive-use-trash=false$' "${d}/drive-dry.log"; then
    echo "a dry run permanently deleted trashed objects" >&2
    return 1
  fi

  for wrapped in b2 s3; do
    run_prune "${wrapped}" "${d}/${wrapped}.log"
    grep -Fxq 'rclone cleanup GoogleDrive_secured:winsvpn-backups/hub-test' "${d}/${wrapped}.log"
    # Stage 6: cleanup-hidden only under the encrypted backup folder.
    grep -Fxq 'rclone backend encode GoogleDrive_secured: winsvpn-backups/hub-test' "${d}/${wrapped}.log"
    grep -Fxq 'rclone backend cleanup-hidden backing:enc/encdir/enchost' "${d}/${wrapped}.log"
    if grep -F -- '--drive-trashed-only' "${d}/${wrapped}.log"; then
      echo "a ${wrapped} backend got the Drive trash delete (it would delete live backups)" >&2
      return 1
    fi
    no_root_cleanup "${d}/${wrapped}.log"
  done

  # An unsupported backend: nothing is emptied, and a required prune fails.
  set +e
  run_prune onedrive "${d}/onedrive.log"
  rc=$?
  set -e
  [[ "${rc}" == "1" ]]
  grep -Fq 'were not removed' "${d}/onedrive.log.out"
  if grep -E '^rclone cleanup |--drive-trashed-only|cleanup-hidden' "${d}/onedrive.log"; then
    echo "an unsupported backend got a trash or cleanup command" >&2
    return 1
  fi
  run_prune onedrive "${d}/onedrive-optional.log" REQUIRE_BACKUP_PRUNING=0
  # Stage 6 cannot be scoped there either: skipped with a warning.
  grep -Fq 'stage 6 skipped' "${d}/onedrive-optional.log.out"
  if grep -F 'cleanup-hidden' "${d}/onedrive-optional.log"; then
    echo "stage 6 ran cleanup-hidden on a backend it cannot scope" >&2
    return 1
  fi
  echo "PASS backup pruning empties only the hub backup prefix's trash, never an account's"
}

# CP-5: the shell schema bootstrap runs against the live database while the
# hub, the prober and Litestream write to it. Every sqlite3 call waits for a
# lock (bounded) instead of failing on the first busy one, and a failed
# schema inspection is an error, not "column absent".
test_sqlite_bootstrap_busy_timeout() {
  local d="${work_dir}/sqlite-bootstrap-busy"
  mkdir -p "${d}"
  (
    WINS_DEFAULTS_FILE="${d}/absent-defaults"
    WINS_SECRETS_FILE="${d}/absent-secrets"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    warn() { :; }
    err() { printf '%s\n' "$*" >> "${d}/err"; }
    APP_DIR="${d}/app"
    DB_PATH="${d}/app/vpn_users.db"
    mkdir -p "${APP_DIR}"
    sqlite3() { printf '%s\n' "$*" >> "${d}/calls"; command sqlite3 "$@"; }

    # A fresh database, then the WAL mode the hub uses.
    write_sqlite_bootstrap
    [[ "$(command sqlite3 "${DB_PATH}" 'PRAGMA journal_mode=WAL;')" == "wal" ]]

    # Every bootstrap connection carries the bounded busy timeout.
    : > "${d}/calls"
    python3 - "${DB_PATH}" "${d}/holding" <<'PYEOF' &
import sqlite3
import sys
import time
from pathlib import Path

conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute("BEGIN IMMEDIATE")
Path(sys.argv[2]).touch()
time.sleep(3)
conn.execute("COMMIT")
PYEOF
    holder=$!
    for _ in $(seq 1 50); do [[ -e "${d}/holding" ]] && break; sleep 0.1; done
    [[ -e "${d}/holding" ]]
    # Another connection holds the write lock for 3 s: the bootstrap waits.
    write_sqlite_bootstrap
    wait "${holder}"
    [[ "$(wc -l < "${d}/calls")" -gt 10 ]]
    if grep -v -- "^-cmd .timeout 30000 ${DB_PATH}" "${d}/calls"; then
      echo "a bootstrap sqlite3 call has no busy timeout" >&2
      exit 1
    fi
    [[ "$(command sqlite3 "${DB_PATH}" "SELECT value FROM system_settings WHERE key='maintenance_mode';")" == "false" ]]

    # A failed inspection is not "column absent": no ALTER is attempted.
    sqlite3() {
      printf '%s\n' "$*" >> "${d}/calls"
      if [[ "$*" == *pragma_table_info* ]]; then
        echo 'Error: database is locked' >&2
        return 5
      fi
      command sqlite3 "$@"
    }
    : > "${d}/calls"
    if (sqlite_add_column_if_missing users paypal_plan_id "TEXT") 2>/dev/null; then exit 1; fi
    if grep -F 'ALTER TABLE' "${d}/calls"; then
      echo "a failed schema inspection was read as a missing column" >&2
      exit 1
    fi
    grep -Fq 'refusing to guess whether paypal_plan_id exists' "${d}/err"
  )
  echo "PASS schema bootstrap waits for a busy live database and never reads a failed inspection as a missing column"
}

# CP-6: the deploy-path Suricata rule update goes through the same staged,
# reviewed updater as the daily run (IA-CP-13), never straight over the
# active ruleset; its deploy form tests before activating nothing, and puts
# the previous ruleset back, including the empty one of a first install.
test_control_ids_install_staged_update() {
  local d="${work_dir}/ids-install-staged" generated fake_bin rules_dir log_file body
  local old_rule='alert tcp any any -> any 80 (msg:"wins-test old"; sid:9100001; rev:1;)'
  local new_rule='alert tcp any any -> any 80 (msg:"wins-test new"; sid:9100002; rev:1;)'
  mkdir -p "${d}"
  # To the next top-level function: its Python heredoc has a column-0 "}".
  body="$(awk '/^install_control_ids_ips\(\) \{$/ {f=1; print; next} f && /^[A-Za-z_][A-Za-z0-9_]*\(\) \{$/ {exit} f {print}' "${CONTROL_SCRIPT}")"
  [[ "${body}" == *'suricata -T -c "${cfg}" -v'* ]]
  if grep -F 'suricata-update --disable-conf' <<<"${body}"; then
    echo "install_control_ids_ips writes suricata-update output straight over the active rules" >&2
    return 1
  fi
  python3 - "${body}" <<'PYEOF'
import sys
body = sys.argv[1]
steps = [
    "chmod 700 /usr/local/bin/wins-suricata-action-policy",
    "\n  write_suricata_update_script\n",
    "WINS_SURICATA_UPDATE_NO_RELOAD=1 /usr/local/bin/wins-suricata-update",
    "if ! /usr/local/bin/wins-suricata-action-policy; then",
    'if ! suricata -T -c "${cfg}" -v; then',
    "systemctl restart suricata",
]
at = [body.find(step) for step in steps]
if -1 in at or at != sorted(at):
    raise SystemExit(f"install path order is not policy writer -> shared updater -> checks -> restart: {at}")
# The last-good config, local rules and imported rules are snapshotted before
# the config is rewritten, and every refusal before the restart restores them.
snap = body.find('suricata_deploy_snapshot "${ids_snapshot}" "${ids_files[@]}"')
write = body.find('python3 - "${cfg}"')
if not (0 <= snap < write):
    raise SystemExit("suricata.yaml is rewritten before its last-good copy is taken")
restore = 'suricata_deploy_restore "${ids_snapshot}" "${ids_files[@]}"'
branches = (
    ("if grep -Eq", "refusing inline activation"),
    ("if ! /usr/local/bin/wins-suricata-action-policy; then", "fail the IPS action policy"),
    ("suricata --build-info | grep -Ei 'NFQ' >/dev/null || {", "lacks NFQUEUE"),
    ('if ! suricata -T -c "${cfg}" -v; then', "fail suricata -T"),
)
for start, marker in branches:
    lo = body.find(start)
    hi = body.find(marker, lo)
    if lo < 0 or hi < 0 or restore not in body[lo:hi]:
        raise SystemExit(f"the refusal '{marker}' leaves the rejected config and rules active")
PYEOF
  generated="${d}/wins-suricata-update"
  extract_heredoc "${CONTROL_SCRIPT}" "cat > /usr/local/bin/wins-suricata-update <<'EOF'" EOF > "${generated}"
  bash -n "${generated}"
  fake_bin="${d}/bin"
  mkdir -p "${fake_bin}"
  cat > "${fake_bin}/suricata-update" <<'EOF'
#!/usr/bin/env bash
printf 'suricata-update %s\n' "$*" >>"${WINS_TEST_LOG}"
while (($#)); do
  if [[ "$1" == --output ]]; then printf '%s\n' "${WINS_TEST_NEW_RULE:?}" > "$2/suricata.rules"; shift; fi
  shift
done
EOF
  cat > "${fake_bin}/suricata" <<'EOF'
#!/usr/bin/env bash
printf 'suricata %s\n' "$*" >>"${WINS_TEST_LOG}"
[[ "${WINS_TEST_SURICATA_CONFIG_FAIL:-0}" != "1" ]]
EOF
  for tool in systemctl suricatasc curl; do
    printf '#!/usr/bin/env bash\nprintf "%s %%s\\n" "$*" >>"${WINS_TEST_LOG}"\n' "${tool}" > "${fake_bin}/${tool}"
  done
  chmod 700 "${fake_bin}"/*
  rules_dir="${d}/rules"
  log_file="${d}/update.log"
  run_deploy_update() { # run_deploy_update <previous ruleset or ""> [VAR=value ...]
    rm -rf -- "${rules_dir}"
    mkdir -p "${rules_dir}"
    printf '%s' "$1" > "${rules_dir}/suricata.rules"
    [[ -z "$1" ]] || printf '\n' >> "${rules_dir}/suricata.rules"
    shift
    : > "${log_file}"
    env PATH="${fake_bin}:${PATH}" WINS_TEST_LOG="${log_file}" WINS_SURICATA_UPDATE_NO_RELOAD=1 \
      WINS_SURICATA_ACTION_POLICY_BIN=/bin/true WINS_SURICATA_RULES_DIR="${rules_dir}" \
      WINS_TEST_NEW_RULE="${new_rule}" "$@" bash "${generated}"
  }
  no_activation() {
    if grep -E '^(systemctl|suricatasc|curl) ' "${log_file}"; then
      echo "the deploy form of the rule update reloaded or restarted Suricata" >&2
      return 1
    fi
  }

  run_deploy_update "${old_rule}"
  [[ "$(<"${rules_dir}/suricata.rules")" == "${new_rule}" ]]
  [[ "$(<"${rules_dir}/suricata.rules.last-good")" == "${old_rule}" ]]
  grep -Fxq 'suricata -T -c /etc/suricata/suricata.yaml' "${log_file}"
  no_activation
  [[ -z "$(find "${rules_dir}" -mindepth 1 -name '.wins-staging.*' -print)" ]]

  if run_deploy_update "${old_rule}" WINS_TEST_SURICATA_CONFIG_FAIL=1; then
    echo "the deploy form accepted a ruleset that failed suricata -T" >&2
    return 1
  fi
  [[ "$(<"${rules_dir}/suricata.rules")" == "${old_rule}" ]]
  no_activation

  # First install: nothing earlier to restore, so the rejected rules must not
  # stay active either.
  if run_deploy_update "" WINS_TEST_SURICATA_CONFIG_FAIL=1; then
    echo "the deploy form accepted a ruleset that failed suricata -T" >&2
    return 1
  fi
  [[ ! -s "${rules_dir}/suricata.rules" ]]
  no_activation
  [[ -z "$(find "${rules_dir}" -mindepth 1 -name '.wins-staging.*' -print)" ]]

  # The snapshot and restore the install path uses: the last-good config,
  # local rules and imported rules come back byte for byte with their modes,
  # and a file that did not exist before is removed again.
  (
    WINS_DEFAULTS_FILE="${d}/absent-defaults"
    WINS_SECRETS_FILE="${d}/absent-secrets"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    mkdir -p "${d}/etc" "${d}/lib"
    printf 'vars: {}\nlast-good: config\n' > "${d}/etc/suricata.yaml"
    chmod 640 "${d}/etc/suricata.yaml"
    printf 'drop http any any -> any any (msg:"old local"; sid:9900001; rev:1;)\n' > "${d}/lib/wins-local.rules"
    rm -f "${d}/lib/suricata.rules"
    files=("${d}/etc/suricata.yaml" "${d}/lib/wins-local.rules" "${d}/lib/suricata.rules")
    cp -p "${d}/etc/suricata.yaml" "${d}/expect-config"
    cp -p "${d}/lib/wins-local.rules" "${d}/expect-local"
    snap="$(mktemp -d)"
    suricata_deploy_snapshot "${snap}" "${files[@]}"
    printf 'rejected: config\n' > "${d}/etc/suricata.yaml"
    chmod 600 "${d}/etc/suricata.yaml"
    printf 'rejected local\n' > "${d}/lib/wins-local.rules"
    printf '%s\n' "${new_rule}" > "${d}/lib/suricata.rules"
    suricata_deploy_restore "${snap}" "${files[@]}"
    cmp -s "${d}/expect-config" "${d}/etc/suricata.yaml"
    [[ "$(stat -c '%a' "${d}/etc/suricata.yaml")" == "640" ]]
    cmp -s "${d}/expect-local" "${d}/lib/wins-local.rules"
    [[ ! -e "${d}/lib/suricata.rules" ]]
    [[ ! -e "${snap}" ]]
    [[ -z "$(find "${d}/etc" "${d}/lib" -name '*.wins-restore' -print)" ]]
  )
  echo "PASS install-time Suricata config and rules go through the staged updater and roll back together without activating"
}

# CP-7: a connector that never reports ready fails the deploy instead of
# passing with every app front on Cloudflare 1033.
test_appcloud_tunnel_readiness_fatal() {
  local d="${work_dir}/appcloud-readiness" mock_ready
  mkdir -p "${d}"
  # mock_ready, not ready: the function under test has a local "ready".
  for mock_ready in 503 200; do
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
      log() { printf '%s\n' "$*" >> "${d}/log-${mock_ready}"; }
      warn() { printf '%s\n' "$*" >> "${d}/warn-${mock_ready}"; }
      err() { printf '%s\n' "$*" >> "${d}/err-${mock_ready}"; }
      install_cloudflared_package() { :; }
      id() { return 0; }
      useradd() { :; }
      install() { :; }
      systemd-analyze() { :; }
      systemctl() { :; }
      sleep() { :; }
      cloudflared() {
        if [[ "$*" == *'ingress rule'* ]]; then printf 'Matched rule #0\n\tservice: http://127.0.0.1:80\n'; fi
        return 0
      }
      curl() { printf '%s' "${mock_ready}"; }
      export CLOUDFLARE_APPCLOUD_ZONE_NAME=example.net
      export APPCLOUD_TUNNEL_ID=0b9a5c3e-1f2d-4c6b-8a7e-9d0c1b2a3f4e
      export APPCLOUD_TUNNEL_CREDENTIALS='{"AccountTag":"a","TunnelID":"0b9a5c3e-1f2d-4c6b-8a7e-9d0c1b2a3f4e","TunnelSecret":"cw=="}'
      export APPCLOUD_TUNNEL_HOSTS=sync.example.net
      if [[ "${mock_ready}" == "200" ]]; then
        configure_appcloud_tunnel_connector
        grep -Fq 'is active and ready' "${d}/log-${mock_ready}"
      else
        if configure_appcloud_tunnel_connector; then
          echo "an app-zone connector that never became ready was accepted" >&2
          exit 1
        fi
        grep -Fq 'not ready after 60 s (metrics /ready=503)' "${d}/err-${mock_ready}"
      fi
    )
  done
  echo "PASS app-zone tunnel readiness timeout fails the deploy"
}

# CP-13: winn_v3_preflight_credentials keeps its own scalar, never the name
# of the arrays called `missing` elsewhere in the installer.
test_winn_v3_preflight_credentials_scalar() {
  local d="${work_dir}/winn3-preflight-scalar" body f
  mkdir -p "${d}/creds"
  body="$(awk '/^winn_v3_preflight_credentials\(\) \{$/ {f=1} f && /^}$/ {print; exit} f {print}' "${CONTROL_SCRIPT}")"
  [[ -n "${body}" ]]
  if grep -E '(^|[^_[:alnum:]])missing([^_[:alnum:]]|$)' <<<"${body}"; then
    echo "winn_v3_preflight_credentials still uses the name 'missing'" >&2
    return 1
  fi
  (
    WINS_DEFAULTS_FILE="${d}/absent-defaults"
    WINS_SECRETS_FILE="${d}/absent-secrets"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    winn_v3_missing_credential() { printf '%s\n' "$1" >> "${d}/missing-report"; }
    WINN_CREDENTIALS_DIR_DEFAULT="${d}/creds"
    for f in server.pem server-key.pem ech-server-keys.json cover.pem cover-key.pem ca.pem \
        state.key audit.key controller-pq.seed device-registry.json; do
      printf 'x\n' > "${d}/creds/${f}"
    done
    winn_v3_preflight_credentials
    rm -f "${d}/creds/audit.key"
    if winn_v3_preflight_credentials; then exit 1; fi
    [[ "$(<"${d}/missing-report")" == "${d}/creds/audit.key" ]]
  )
  echo "PASS winn_v3_preflight_credentials uses its own scalar"
}

# CP-14: the seven OnUnitActiveSec timers. With Persistent=true, a timer
# started after OnBootSec had passed, while its oneshot service had not run
# this boot, went to "elapsed" with no next elapse and never fired again:
# the hub's seven timers, measured 2026-10-01 (P13). Each monotonic timer the
# installer writes is installed here, on this systemd, in exactly that
# situation (fresh service, a stamp from an earlier boot, OnBootSec past) and
# must show a finite next elapse and run. wins_enable_monotonic_timer must
# also revive a timer an older unit already left elapsed. CP-14b: on the hub
# (2026-10-02) the timers were enabled, and stop then start left six of seven
# elapsed: on systemd 255 the timer keeps its last trigger, so OnBootSec=
# stays spent and OnUnitActiveSec= has no base until the service runs. The
# upgrade arm below rebuilds exactly that state before calling the helper.
cleanup_cp14_test_units() {
  local u
  for u in /run/systemd/system/wins-cp14-test-*.timer /run/systemd/system/wins-cp14-test-*.service; do
    [[ -e "${u}" ]] || continue
    systemctl stop "${u##*/}" >/dev/null 2>&1 || true
  done
  rm -f /run/systemd/system/wins-cp14-test-* /etc/systemd/system/timers.target.wants/wins-cp14-test-* \
    /var/lib/systemd/timers/stamp-wins-cp14-test-* /run/wins-cp14-test-*.runs /run/wins-cp14-test-*.release
  systemctl daemon-reload
  systemctl reset-failed >/dev/null 2>&1 || true
}

test_control_monotonic_timers_keep_running() {
  local rc
  cleanup_cp14_test_units
  set +e
  (
    set -Eeuo pipefail
    trap '[[ $- == *e* ]] && echo "FAIL ${BASH_SOURCE[0]##*/}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
    control_monotonic_timers_body
  )
  rc=$?
  set -e
  cleanup_cp14_test_units
  return "${rc}"
}

control_monotonic_timers_body() {
  local d="${work_dir}/monotonic-timers" timer unit n=0 next state runs helper_pid
  local -a units=()
  mkdir -p "${d}/timers"
  # Control plane and data plane: the data plane carried the same shape on
  # wins-node-canary.timer and wins-edge-hardening.timer.
  python3 - "${CONTROL_SCRIPT}" "${DATA_SCRIPT}" "${d}/timers" <<'PYEOF'
import pathlib
import re
import sys

# The timers that used Persistent=true and are enabled by the installer: each
# must go through wins_enable_monotonic_timer, which revives an elapsed one.
# FLEET2: wins-security-alert-monitor.timer is an OnCalendar= timer now and is
# no longer in this set.
HELPER = {
    "wins-paypal-sync.timer", "wins-monero-poll.timer",
    "wins-redemption-outbox.timer", "wins-donor-ack-outbox.timer", "wins-hoppy-agent-outbox.timer",
    "wins-gateway-canary.timer", "wins-node-canary.timer",
}
EXPECTED = {"control": 8, "data": 5}
out = pathlib.Path(sys.argv[3])
for role, path in (("control", sys.argv[1]), ("data", sys.argv[2])):
    src = pathlib.Path(path).read_text(encoding="utf-8")
    found = 0
    pattern = r"^  cat > /etc/systemd/system/([A-Za-z0-9_.-]+\.timer) <<'(\w+)'\n(.*?)\n\2\n"
    for m in re.finditer(pattern, src, re.S | re.M):
        name, body = m.group(1), m.group(3)
        if "\nOnUnitActiveSec=" not in "\n" + body:
            continue
        if "\nPersistent=true" in "\n" + body:
            raise SystemExit(f"{role} {name}: Persistent=true on a monotonic timer leaves it elapsed for good")
        if name in HELPER and f"  wins_enable_monotonic_timer {name}\n" not in src:
            raise SystemExit(f"{role} {name} is not enabled through wins_enable_monotonic_timer")
        (out / f"{role}-{name}").write_text(body + "\n", encoding="utf-8")
        found += 1
    if found != EXPECTED[role]:
        raise SystemExit(f"expected {EXPECTED[role]} {role} monotonic timers, found {found}")
    if role == "data":
        # The gated operator enable for wins-edge-hardening.timer revives it too.
        enable = src.split("cat > /usr/local/sbin/wins-edge-hardening-enable <<'WINS_EDGE_ENABLE_EOF'\n", 1)[1]
        enable = enable.split("\nWINS_EDGE_ENABLE_EOF\n", 1)[0]
        # CP-14b: stop then start does not clear it on systemd 255; a timer
        # elapsed after the enable gets its service started once.
        start = enable.find("\nsystemctl enable --now wins-edge-hardening.timer\n")
        elapsed = enable.find("systemctl show -p SubState --value wins-edge-hardening.timer", max(start, 0))
        kick = enable.find("  systemctl start --no-block wins-edge-hardening.service\n", max(start, 0))
        if not (0 <= start < elapsed < kick):
            raise SystemExit("wins-edge-hardening-enable leaves an elapsed timer without a run")
PYEOF
  scaled_timer() { # scaled_timer <unit> <timer text file>
    sed -e 's/^OnBootSec=.*/OnBootSec=1s/' -e 's/^OnUnitActiveSec=.*/OnUnitActiveSec=3s/' \
      -e "s/^Unit=.*/Unit=$1.service/" -e '/^AccuracySec=/d' -e '/^RandomizedDelaySec=/d' \
      -e 's/^\[Timer\]$/[Timer]\nAccuracySec=1s/' "$2" \
      > "/run/systemd/system/$1.timer"
  }
  install -d -m 755 /var/lib/systemd/timers
  for timer in "${d}"/timers/*.timer; do
    n=$((n + 1))
    unit="wins-cp14-test-${n}"
    units+=("${unit}")
    printf '[Service]\nType=oneshot\nExecStart=/bin/sh -c "echo run >> /run/%s.runs"\n' "${unit}" \
      > "/run/systemd/system/${unit}.service"
    scaled_timer "${unit}" "${timer}"
    touch -d '2026-09-04 10:15:03 UTC' "/var/lib/systemd/timers/stamp-${unit}.timer"
  done
  sleep 2
  systemctl daemon-reload
  for unit in "${units[@]}"; do systemctl start "${unit}.timer"; done
  sleep 1
  systemctl daemon-reload
  for unit in "${units[@]}"; do
    state="$(systemctl show -p SubState --value "${unit}.timer")"
    if [[ "${state}" == "elapsed" ]]; then
      echo "${unit}.timer is elapsed with no next run after start and daemon-reload" >&2
      return 1
    fi
  done
  sleep 4
  for unit in "${units[@]}"; do
    runs=0
    if [[ -f "/run/${unit}.runs" ]]; then runs="$(wc -l < "/run/${unit}.runs")"; fi
    next="$(systemctl show -p NextElapseUSecMonotonic --value "${unit}.timer")"
    state="$(systemctl show -p SubState --value "${unit}.timer")"
    if (( runs < 1 )) || [[ "${state}" == "elapsed" ]]; then
      echo "${unit}.timer ran ${runs} times, state ${state}, next ${next}" >&2
      return 1
    fi
  done

  # The upgrade path: a timer an old unit (Persistent=true) left elapsed,
  # revived by each installer's own wins_enable_monotonic_timer.
  local role script
  for role in control data; do
    case "${role}" in
      control) script="${CONTROL_SCRIPT}" ;;
      data) script="${DATA_SCRIPT}" ;;
    esac
    unit="wins-cp14-test-upgrade-${role}"
    units+=("${unit}")
    # A slow oneshot: the helper must not wait for the run it starts (the
    # hub's first monitor run reads about 186 MB of EVE). The run holds until
    # the test releases it, so the check does not depend on how fast the host is.
    rm -f -- "/run/${unit}.release"
    printf '[Service]\nType=oneshot\nExecStart=/bin/sh -c "while [ ! -e /run/%s.release ]; do sleep 0.1; done; echo run >> /run/%s.runs"\n' "${unit}" "${unit}" \
      > "/run/systemd/system/${unit}.service"
    printf '[Timer]\nOnBootSec=1s\nOnUnitActiveSec=3s\nAccuracySec=1s\nPersistent=true\nUnit=%s.service\n\n[Install]\nWantedBy=timers.target\n' "${unit}" \
      > "/run/systemd/system/${unit}.timer"
    touch -d '2026-09-04 10:15:03 UTC' "/var/lib/systemd/timers/stamp-${unit}.timer"
    systemctl daemon-reload
    # Enabled, as on the hub: the helper's own `enable --now` then changes no
    # symlink and so triggers no implicit daemon-reload of its own.
    systemctl enable "${unit}.timer" >/dev/null 2>&1
    systemctl start "${unit}.timer"
    # Anti-vacuity: the old shape reproduces the hub's state on this systemd.
    [[ "$(systemctl show -p SubState --value "${unit}.timer")" == "elapsed" ]]
    [[ "$(systemctl show -p NextElapseUSecMonotonic --value "${unit}.timer")" == "infinity" ]]
    sed -i 's/^Persistent=true$/Persistent=false/' "/run/systemd/system/${unit}.timer"
    systemctl daemon-reload
    # Anti-vacuity (CP-14b): the new unit text with stop then start, what the
    # hub's 2026-10-02 deploy did, leaves it elapsed with no next run.
    systemctl stop "${unit}.timer"
    systemctl start "${unit}.timer"
    [[ "$(systemctl show -p SubState --value "${unit}.timer")" == "elapsed" ]]
    [[ "$(systemctl show -p NextElapseUSecMonotonic --value "${unit}.timer")" == "infinity" ]]
    [[ ! -e "/run/${unit}.runs" ]]
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      NODE_ENV_FILE="${d}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      log() { :; }
      wins_enable_monotonic_timer "${unit}.timer" >/dev/null 2>&1
    ) &
    helper_pid=$!
    # The run it started is held until released below, so a helper that waited
    # for it would never return: it gets 20 seconds, however slow the host is.
    for _ in $(seq 1 100); do
      kill -0 "${helper_pid}" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 "${helper_pid}" 2>/dev/null; then
      kill "${helper_pid}" 2>/dev/null || true
      wait "${helper_pid}" 2>/dev/null || true
      : > "/run/${unit}.release"
      echo "${role} wins_enable_monotonic_timer waited for the service run it started" >&2
      return 1
    fi
    wait "${helper_pid}"
    state=""
    for _ in $(seq 1 50); do
      state="$(systemctl show -p ActiveState --value "${unit}.service")"
      [[ "${state}" == "activating" ]] && break
      sleep 0.2
    done
    if [[ "${state}" != "activating" || -e "/run/${unit}.runs" ]]; then
      : > "/run/${unit}.release"
      echo "${role} wins_enable_monotonic_timer did not leave the service run it started in progress (state ${state})" >&2
      return 1
    fi
    : > "/run/${unit}.release"
    # Revived: the service ran and the timer waits for a finite next elapse
    # (while it is "running" a second time, NextElapse reads infinity).
    for _ in $(seq 1 20); do
      sleep 0.5
      state="$(systemctl show -p SubState --value "${unit}.timer")"
      next="$(systemctl show -p NextElapseUSecMonotonic --value "${unit}.timer")"
      runs=0
      if [[ -f "/run/${unit}.runs" ]]; then runs="$(wc -l < "/run/${unit}.runs")"; fi
      if [[ "${state}" == "waiting" && "${next}" != "infinity" ]] && (( runs >= 1 )); then break; fi
    done
    if [[ "${state}" != "waiting" || "${next}" == "infinity" ]] || (( runs < 1 )); then
      echo "${role} wins_enable_monotonic_timer left an elapsed timer stuck (state ${state}, next ${next}, ${runs} runs)" >&2
      return 1
    fi

    # A timer that is waiting gets nothing extra from the helper: no stop, no
    # service start of its own.
    : > "${d}/helper-${role}.log"
    (
      WINS_DEFAULTS_FILE="${d}/absent-defaults"
      WINS_SECRETS_FILE="${d}/absent-secrets"
      NODE_ENV_FILE="${d}/absent-node"
      # shellcheck disable=SC1090
      source <(sed '/^main "\$@"$/d' "${script}")
      log() { printf '%s\n' "$*" >> "${d}/helper-${role}.log"; }
      systemctl() {
        [[ "$1" == show ]] || printf 'systemctl %s\n' "$*" >> "${d}/helper-${role}.log"
        command systemctl "$@"
      }
      wins_enable_monotonic_timer "${units[0]}.timer" >/dev/null 2>&1
    )
    if [[ "$(<"${d}/helper-${role}.log")" != "systemctl enable --now ${units[0]}.timer" ]]; then
      echo "${role} wins_enable_monotonic_timer did more than enable a waiting timer:" >&2
      cat "${d}/helper-${role}.log" >&2
      return 1
    fi
  done
  echo "PASS the control and data plane monotonic timers keep a next elapse and run (systemd $(systemctl --version | awk 'NR == 1 {print $2}'))"
}

# CP-17: retiring the app-zone hub records deletes only address records at
# those names; any other record type sharing the name stays.
test_appzone_dns_retirement_types() {
  local d="${work_dir}/appzone-dns-retire"
  mkdir -p "${d}"
  (
    WINS_DEFAULTS_FILE="${d}/absent-defaults"
    WINS_SECRETS_FILE="${d}/absent-secrets"
    # shellcheck disable=SC1090
    source <(sed '/^main "\$@"$/d' "${CONTROL_SCRIPT}")
    log() { :; }
    err() { printf '%s\n' "$*" >> "${d}/err"; }
    curl_bearer() {
      local arg url="" method=GET
      for arg in "$@"; do
        [[ "${arg}" == https://* ]] && url="${arg}"
        [[ "${arg}" == DELETE ]] && method=DELETE
      done
      if [[ "${method}" == DELETE ]]; then
        printf '%s\n' "${url##*/}" >> "${d}/deleted"
        printf '{"success":true}\n'
      else
        printf '%s\n' '{"success":true,"result":[{"id":"rec-a","type":"A"},{"id":"rec-txt","type":"TXT"},{"id":"rec-aaaa","type":"AAAA"},{"id":"rec-mx","type":"MX"},{"id":"rec-cname","type":"CNAME"},{"id":"rec-caa","type":"CAA"}]}'
      fi
    }
    : > "${d}/deleted"
    cloudflare_delete_dns_record_if_present token zone-id sync.example.net
    [[ "$(sort "${d}/deleted" | paste -sd ' ' -)" == "rec-a rec-aaaa rec-cname" ]]
  )
  echo "PASS app-zone DNS retirement deletes only A, AAAA and CNAME records"
}

if [[ "${WINS_RUNTIME_SUITE_KEEP_GOING:-0}" == "1" ]]; then
  run_sections_keep_going "${BASH_SOURCE[0]}"
  exit $?
fi

# Top-level sections (keep-going mode runs each line below).
# shellcheck disable=SC2016
test_suricata_role control "${CONTROL_SCRIPT}" 'python3 - "${cfg}" "${wan_if}" "${hub_cidr}"'
# shellcheck disable=SC2016
test_suricata_role data "${DATA_SCRIPT}" 'python3 - "${cfg}" "${node_cidr}"'
test_data_nfq_postflight_runtime
# shellcheck disable=SC2016
test_suricata_role core "${CORE_SCRIPT}" 'python3 - "${cfg}" "${node_cidr}" "${CORE_INGRESS_CIDR}"'
test_nginx_transport_order plain_first '18080:none,18443:tls'
test_nginx_transport_order tls_first '18443:tls,18080:none'
test_edge_probe_oracle_contract
test_runtime_firewall_fails_closed
test_data_canary_transport_urls
test_data_automatic_stealth_hostname
test_control_transport_parser
test_data_capacity_calculator
test_data_rerun_identity_contract
test_data_pressure_admission
test_data_origin_ca_contract
test_core_origin_ca_contract
test_node_fleet_credential_and_bootstrap_contract
test_control_honeypot_separation
test_cowrie_honeypot_standalone_host_guard
test_shell_escaped_secret_env
test_secret_safe_curl_argv
test_documented_defaults_are_sourceable
test_active_gateway_publisher
test_secrets_file_sourced_without_blanket_export
test_preflight_credentials_not_left_exported
test_paypal_webhook_auto_ensure
test_cloudflare_dns_fail_closed
test_strict_one_touch_secret_contract
test_data_plane_dns_fail_closed
test_data_plane_adguard_policy
test_data_plane_selective_https_redirect
test_rclone_pre_mutation_contracts
test_secure_backup_contracts
test_required_infrastructure_contract_when_strict_disabled
test_control_ssh_preflight_contract
test_adaptive_threat_triage
test_control_host_hardening_contract
test_xray_service_hardening_contract
test_entrypoint_order_and_noninteractive_apt
test_unattended_update_restoration
test_suricata_stable_package_contract
test_core_transport_contract
test_core_exit_xray_fallback_contract
test_core_stale_assignment_cleanup
test_core_stale_stealth_recovery
test_core_exit_handshake_guard
test_core_readiness_registration_order
test_core_assignment_ack_contract
test_control_availability_contract
test_origin_hiding_contract
test_atomic_firewall_rebuild_contract
test_public_ingress_admission_runtime
test_data_edge_queues_boot_reapply
test_inline_route_bypass_postflight
test_winn3_gateway_boot_firewall_runtime
test_windows_preseed_cloudflare_access_contract
test_cloudflare_access_service_token_bootstrap
test_core_management_provider_simulation
test_suricata_daily_update_contract
test_control_fail_closed_cutover_contract
test_control_zram_swap_policy
test_zram_only_swap_policy_all_roles
test_zram_next_boot_config
test_next_boot_kernel_cmdline
test_early_presecret_swap_guards
test_data_plaintext_swap_policy
test_core_plaintext_swap_policy
test_core_package_security_preimage
bash "${ROOT_DIR}/tools/test_core_reboot_pause_failure_hold.sh"
test_control_nginx_capacity_tuning
test_proxy_role_nginx_capacity_tuning data "${DATA_SCRIPT}"
test_proxy_role_nginx_capacity_tuning core "${CORE_SCRIPT}"
test_luks_unlock_keeps_operator_keys
test_backup_prune_trash_scope
test_sqlite_bootstrap_busy_timeout
test_control_ids_install_staged_update
test_appcloud_tunnel_readiness_fatal
test_winn_v3_preflight_credentials_scalar
test_control_monotonic_timers_keep_running
test_appzone_dns_retirement_types
test_suite_has_no_early_exit_grep_pipelines
test_suite_edge_mock_curls_read_stdin_config

echo "Deployment runtime configuration simulation passed."
