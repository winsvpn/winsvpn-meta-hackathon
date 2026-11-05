#!/usr/bin/env bash
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
DATA_PLANE="${HERE}/wins_data_plane_setup_ONETOUCH.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT HUP INT TERM

extract() {
  local needle="$1" output="$2"
  awk -v needle="${needle}" '
    index($0, needle) { capture=1; next }
    capture && $0 == "EOF" { exit }
    capture { print }
  ' "${INSTALL}" > "${output}"
}

bash -n "${INSTALL}"
(
  # shellcheck disable=SC1090
  source "${INSTALL}"
  WINN3_GATEWAY_PATH_MTU=1450
  WINN3_GATEWAY_PLAN=udp
  WINN3_GATEWAY_COVER_CERT=/secrets/cover.pem
  WINN3_GATEWAY_COVER_KEY=/secrets/cover-key.pem
  WINN3_GATEWAY_ECH_KEYS=/secrets/ech.json
  WINN3_GATEWAY_WINN_CERT=/secrets/winn.pem
  WINN3_GATEWAY_WINN_KEY=/secrets/winn-key.pem
  emit_unit_text
) > "${WORK}/gateway-unit"
for required in \
  'LoadCredential=cover.pem:/secrets/cover.pem' \
  'LoadCredential=cover-key.pem:/secrets/cover-key.pem' \
  'LoadCredential=ech-keys.json:/secrets/ech.json' \
  'LoadCredential=winn-leaf.pem:/secrets/winn.pem' \
  'LoadCredential=winn-leaf-key.pem:/secrets/winn-key.pem' \
  '-cert /run/winn3-gateway/winn-leaf.pem' \
  '-key /run/winn3-gateway/winn-leaf-key.pem' \
  '-cover-cert /run/winn3-gateway/cover.pem' \
  '-cover-key /run/winn3-gateway/cover-key.pem' \
  '-ech-keys /run/winn3-gateway/ech-keys.json' \
  'install -m 0400'; do
  grep -Fq -- "${required}" "${WORK}/gateway-unit"
done
extract "cat <<'EOF' # the boot helper: /usr/local/sbin/winn3-gateway-firewall" "${WORK}/firewall"
extract "cat > /etc/systemd/system/winn3-gateway-firewall.service <<'EOF'" "${WORK}/unit"
[[ -s "${WORK}/firewall" && -s "${WORK}/unit" ]]
bash -n "${WORK}/firewall"
chmod 700 "${WORK}/firewall"

grep -Fq 'After=network-online.target wins-vpn-firewall.service' "${WORK}/unit"
grep -Fq 'Before=winn3-gateway.service' "${WORK}/unit"
grep -Fq 'WantedBy=multi-user.target' "${WORK}/unit"
grep -Fq 'Requires=winn3-gateway-firewall.service' "${INSTALL}"
grep -Fq 'After=network-online.target winn3-gateway-firewall.service' "${INSTALL}"
grep -Fq 'source "${WINN3_GATEWAY_ENV_FILE}"' "${DATA_PLANE}"
grep -Fq 'ipt -A WINVPN-INPUT -p udp --dport "${WINN3_GATEWAY_LISTEN_PORT}" -j ACCEPT' "${DATA_PLANE}"
grep -Fq 'ipt -A WINVPN-INPUT -p tcp --dport "${WINN3_GATEWAY_LISTEN_PORT}" -j ACCEPT' "${DATA_PLANE}"

assert_forward_shape() {
  local script="$1"
  grep -Fq -- '-I FORWARD 1 -i "${iface}" -j WINN3GW-FORWARD' "${script}" &&
    grep -Fq -- '-I FORWARD 1 -o "${iface}" -j WINN3GW-FORWARD' "${script}" &&
    grep -Fq -- '-t nat -I POSTROUTING 1 -j WINN3GW-NAT-POSTROUTING' "${script}" &&
    grep -Fq -- '-t nat -A WINN3GW-NAT-POSTROUTING -s "${cidr}" -o "${wan_if}" -j MASQUERADE' "${script}"
}
assert_forward_shape "${WORK}/firewall"
sed '/WINN3GW-NAT-POSTROUTING.*MASQUERADE/d' "${WORK}/firewall" > "${WORK}/firewall-no-nat"
if assert_forward_shape "${WORK}/firewall-no-nat"; then
  echo "negative control unexpectedly retained forwarding NAT contract" >&2
  exit 1
fi

# OI-5 (PQ isolation round, 2026-10-11): the boot helper states client
# isolation as rules, in this order, all ahead of the conntrack accept and
# the egress accept: same-interface drop, pool-to-pool drop, the four
# private and shared-space drops; then the tunnel INPUT drop is proven behind
# the WINN3GW-INPUT jump, and IPv6 on the tunnel interface is dropped in
# ip6tables INPUT and FORWARD, both directions.
line_of() { grep -n -F -- "$2" "$1" | head -1 | cut -d: -f1; }
# line_of_exact: the whole line, for a proof that also appears as a fragment
# inside place_winn3gw_input_jump's odd-form check.
line_of_exact() { grep -n -x -F -- "$2" "$1" | head -1 | cut -d: -f1; }
assert_isolation_shape() {
  local script="$1" same pool private conntrack egress drop v6in v6fi v6fo
  same="$(line_of "${script}" '-A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP')"
  pool="$(line_of "${script}" '-A WINN3GW-FORWARD -s "${cidr}" -d "${cidr}" -j DROP')"
  private="$(line_of "${script}" 'for private in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do')"
  conntrack="$(line_of "${script}" '-A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')"
  egress="$(line_of "${script}" '-A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT')"
  drop="$(line_of_exact "${script}" '  iptables -w 10 -C INPUT -i "${iface}" -j DROP')"
  v6in="$(line_of "${script}" 'ip6tables -w 10 -I INPUT 1 -i "${iface}" -j DROP')"
  v6fi="$(line_of "${script}" 'ip6tables -w 10 -I FORWARD 1 -i "${iface}" -j DROP')"
  v6fo="$(line_of "${script}" 'ip6tables -w 10 -I FORWARD 1 -o "${iface}" -j DROP')"
  [[ -n "${same}" && -n "${pool}" && -n "${private}" && -n "${conntrack}" && -n "${egress}" \
     && -n "${drop}" && -n "${v6in}" && -n "${v6fi}" && -n "${v6fo}" ]] || return 1
  (( same < pool && pool < private && private < conntrack && conntrack < egress )) || return 1
  grep -Fq -- '-A WINN3GW-FORWARD -i "${iface}" -d "${private}" -j DROP' "${script}" || return 1
  # The tunnel INPUT drop is checked after the jump is placed.
  (( drop > $(line_of "${script}" 'place_winn3gw_input_jump "${iface}" "${inner}"') )) || return 1
  # The IPv4 drop is placed right behind the jump, never by position 1 (the
  # ip6tables drops do go to position 1: nothing legitimate precedes them).
  grep -Fq -- '-I INPUT "$((first_jump_at + 1))" -i "${iface}" -j DROP' "${script}" || return 1
  ! grep -Eq -- 'iptables -w 10 -I INPUT 1 -i "\$\{iface\}" -j DROP' "${script}" || return 1
}
assert_isolation_shape "${WORK}/firewall"
# Negative controls: each isolation rule, the INPUT drop proof and each IPv6
# drop must be load-bearing for the assertion above.
for needle in '-s "${cidr}" -d "${cidr}" -j DROP' \
    '-A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP' \
    '-A WINN3GW-FORWARD -i "${iface}" -d "${private}" -j DROP' \
    '-C INPUT -i "${iface}" -j DROP' \
    'ip6tables -w 10 -I FORWARD 1 -o "${iface}" -j DROP'; do
  grep -Fv -- "${needle}" "${WORK}/firewall" > "${WORK}/firewall-mutant"
  if cmp -s "${WORK}/firewall" "${WORK}/firewall-mutant"; then
    echo "negative control did not remove: ${needle}" >&2
    exit 1
  fi
  if assert_isolation_shape "${WORK}/firewall-mutant"; then
    echo "negative control unexpectedly retained the isolation shape without: ${needle}" >&2
    exit 1
  fi
done
# Order control: the isolation drops moved behind the egress accept must fail.
python3 - "${WORK}/firewall" "${WORK}/firewall-reordered" <<'PY'
import sys
text = open(sys.argv[1], encoding="utf-8").read()
start = text.index('  iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP\n')
end = text.index('  iptables -w 10 -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n')
block = text[start:end]
egress = '  iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT\n'
text = text[:start] + text[end:]
text = text.replace(egress, egress + block, 1)
open(sys.argv[2], "w", encoding="utf-8").write(text)
PY
if assert_isolation_shape "${WORK}/firewall-reordered"; then
  echo "order control unexpectedly accepted isolation drops behind the egress accept" >&2
  exit 1
fi

mkdir -p "${WORK}/bin"
# The fake models WINVPN-INPUT as kernel-form (`iptables -S`) rule lines, so
# the helper's positional inserts and deletes land where real iptables would
# put them. tools/test_deployment_runtime_configs.sh runs the same helper
# against real iptables in a private netns.
cat > "${WORK}/bin/iptables" <<'EOF'
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

state = Path(os.environ["WINN3_FW_TEST_STATE"])
with open(os.environ["WINN3_FW_TEST_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[:2] == ["-w", "10"]:
    args = args[2:]
rules = state.read_text(encoding="utf-8").splitlines() if state.exists() else []
has_chain = os.environ.get("WINN3_FW_TEST_HAS_CHAIN") == "1"

def kernel(chain, spec):
    out, i = [f"-A {chain}"], 0
    while i < len(spec):
        out += spec[i:i + 2]
        if spec[i] == "-p" and "--dport" in spec:
            out += ["-m", spec[i + 1]]
        i += 2
    return " ".join(out)

if args == ["-S"]:
    print("-P INPUT DROP")
    if has_chain:
        print("-N WINVPN-INPUT")
        print("\n".join(rules))
elif args == ["-S", "WINVPN-INPUT"] and has_chain:
    print("-N WINVPN-INPUT")
    print("\n".join(rules))
elif len(args) > 2 and args[0] == "-I" and args[1] == "WINVPN-INPUT" and args[2].isdigit():
    rules.insert(int(args[2]) - 1, kernel("WINVPN-INPUT", args[3:]))
    state.write_text("\n".join(rules) + "\n", encoding="utf-8")
elif len(args) > 1 and args[0] == "-D" and args[1] == "WINVPN-INPUT":
    rules.remove(kernel("WINVPN-INPUT", args[2:]))
    state.write_text("\n".join(rules) + "\n", encoding="utf-8")
else:
    sys.exit(2)
EOF
chmod 700 "${WORK}/bin/iptables"
cat > "${WORK}/bin/stat" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"%u:%a"* ]]; then
  printf '0:600\n'
else
  exec /usr/bin/stat "$@"
fi
EOF
chmod 700 "${WORK}/bin/stat"
# The helper holds the shared firewall lock for its whole run (design v17
# 2.2 item 1). macOS has no flock(1), so every host uses the same fake, on a
# lock file inside the work directory.
install -m 700 "${HERE}/testdata/winn3_gateway_fake_flock.py" "${WORK}/bin/flock"

printf 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111\n' > "${WORK}/gateway.env"
chmod 600 "${WORK}/gateway.env"
guards='-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY
-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING
-A WINVPN-INPUT -i lo -j ACCEPT'
udp='-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT'
tcp='-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT'
run_firewall() {
  PATH="${WORK}/bin:${PATH}" \
    WINN3_GATEWAY_ENV_FILE="${WORK}/gateway.env" \
    WINN3_GATEWAY_EDGE_HARDENING="${WORK}/no-edge-hardening" \
    WINS_FIREWALL_LOCK="${WORK}/wins-firewall.lock" \
    WINN3_FW_TEST_STATE="${WORK}/state" \
    WINN3_FW_TEST_LOG="${WORK}/log" \
    WINN3_FW_TEST_HAS_CHAIN=1 \
    bash "${1:-${WORK}/firewall}" > "${WORK}/run.out" 2>&1
}
expected="$(printf '%s\n' "${guards}" "${udp}" '-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT' \
  "${tcp}" '-A WINVPN-INPUT -j DROP')"

# A chain built before the gateway existed, then the live-fleet layout with
# both ACCEPTs above the guards: each ends behind the guards, idempotently.
for layout in fresh live; do
  if [[ "${layout}" == live ]]; then
    printf '%s\n' "${tcp}" "${udp}" "${guards}" > "${WORK}/state"
  else
    printf '%s\n' "${guards}" > "${WORK}/state"
  fi
  printf '%s\n' '-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT' '-A WINVPN-INPUT -j DROP' >> "${WORK}/state"
  : > "${WORK}/log"
  run_firewall
  run_firewall
  [[ "$(cat "${WORK}/state")" == "${expected}" ]]
  [[ "$(grep -Ec '^-w 10 -I WINVPN-INPUT [0-9]+ ' "${WORK}/log")" == 2 ]]
  if [[ "${layout}" == live ]]; then
    [[ "$(grep -Ec '^-w 10 -D WINVPN-INPUT ' "${WORK}/log")" == 2 ]]
  fi
done
# A chain without the guards is refused and left as it was.
printf '%s\n' '-A WINVPN-INPUT -i lo -j ACCEPT' '-A WINVPN-INPUT -j DROP' > "${WORK}/state"
cp "${WORK}/state" "${WORK}/state.before"
if run_firewall; then
  echo "boot firewall accepted a WINVPN-INPUT without the guard jumps" >&2
  exit 1
fi
cmp -s "${WORK}/state" "${WORK}/state.before"

# Negative control: removing TCP placement must be observable.
sed 's/iptables -w 10 -I WINVPN-INPUT "${tcp_at}" -p tcp --dport "${port}" -j ACCEPT/true/' "${WORK}/firewall" > "${WORK}/firewall-no-tcp"
if cmp -s "${WORK}/firewall" "${WORK}/firewall-no-tcp"; then
  echo "negative control did not remove the TCP placement" >&2
  exit 1
fi
printf '%s\n' "${guards}" '-A WINVPN-INPUT -j DROP' > "${WORK}/state"
if run_firewall "${WORK}/firewall-no-tcp" || grep -Fxq -- "${tcp}" "${WORK}/state"; then
  echo "negative control unexpectedly retained TCP" >&2
  exit 1
fi

echo "PASS gateway boot firewall: UDP/TCP 9111 behind the WINVPN-INPUT guards, idempotent, live layout moved, guardless chain refused, systemd ordering, and the OI-5 isolation shape (six drops ahead of the accepts, tunnel INPUT drop behind the jump, IPv6 drops both ways)"
