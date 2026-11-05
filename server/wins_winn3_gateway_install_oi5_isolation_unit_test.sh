#!/usr/bin/env bash
# PQ OI-5 gateway client isolation (PQ-ATTEST 2026-10-10): the winn3 gateway
# block's isolation rules, proven against a stateful fake iptables/ip6tables.
# Presence, order, idempotence and teardown -- the four properties the round
# asks for -- for:
#   - WINN3GW-FORWARD: the six isolation drops (intra-interface, pool-to-pool,
#     10/8, 172.16/12, 192.168/16, 100.64/10) at the HEAD of the chain, ahead
#     of the conntrack accept and the egress accept;
#   - filter/INPUT: the bare `-i IFACE -j DROP` placed immediately behind the
#     WINN3GW-INPUT jump (by place_winn3gw_input_jump itself, so one listing
#     places both), exactly one copy;
#   - ip6tables: `-i IFACE -j DROP` at position 1 of INPUT and both-direction
#     drops at position 1 of FORWARD;
#   - boot-helper parity: the same rules in the emitted helper text, since the
#     helper rebuilds the chains at every start;
#   - teardown: the bare drops removed and positively checked absent, and a
#     second teardown and a re-apply both clean.
#
# Self-contained on purpose: it extracts the block's own functions with awk
# and runs them under fakes, so it needs neither tools/winn3_gateway_test_
# source.py nor the server/testdata fixtures. Mutates nothing outside a temp
# directory. Usage:
#   bash wins_winn3_gateway_install_oi5_isolation_unit_test.sh
#   bash wins_winn3_gateway_install_oi5_isolation_unit_test.sh /path/to/wins_data_plane_setup_ONETOUCH.sh
set -euo pipefail

HERE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DP="${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}"
# OI5_TEST_WORK keeps the work directory across runs, for debugging.
WORK="${OI5_TEST_WORK:-$(mktemp -d)}"
if [[ -z "${OI5_TEST_WORK:-}" ]]; then
  trap 'rm -rf -- "${WORK}"' EXIT HUP INT TERM
fi

bash -n "${DP}"

# Extract the block functions the isolation rules live in, from DP directly.
# The boot helper's own embedded copy of place_winn3gw_input_jump (inside the
# `cat <<'EOF' # the boot helper` heredoc) is skipped, exactly like
# wins_winn3_gateway_install_mangle_teardown_unit_test.sh skips that heredoc.
awk '
  index($0, "cat <<'"'"'EOF'"'"' # the boot helper") { helper=1; next }
  helper { if ($0 == "EOF") helper=0; next }
  /^(apply_forwarding_firewall|apply_forwarding_firewall_locked|apply_winn3gw_input_firewall|place_winn3gw_input_jump|ensure_jump_gw|jump_count_gw|teardown_forwarding_firewall|teardown_forwarding_firewall_locked|teardown_winn3gw_input_firewall)\(\) \{$/ \
    { copy=1; count++ }
  copy { print }
  copy && /^\}$/ { copy=0 }
  END { if (count != 9) exit 1 }
' "${DP}" > "${WORK}/defs.sh"

# Stubs: no lock contention, no speedtest ingest, quiet logs, inert upstream.
wins_fw_lock() { :; }
wins_fw_unlock() { :; }
validate_speedtest_ingest_port() { :; }
winn3gw_log() { :; }
winn3gw_warn() { :; }
winn3gw_err() { printf 'winn3gw_err: %s\n' "$*" >> "${WORK}/errs"; }
ip() {
  [[ "$*" == '-o route show default'* ]] || return 99
  printf '%s\n' 'default via 192.0.2.2 dev testwan'
}
# shellcheck disable=SC1091
source "${WORK}/defs.sh"
declare -F apply_forwarding_firewall_locked >/dev/null
declare -F apply_winn3gw_input_firewall >/dev/null
declare -F teardown_forwarding_firewall >/dev/null

# The fake models kernel-form rule lines ("-A CHAIN" plus flag pairs in
# iptables' own option order, addresses /32-normalized), so `-C`/`-D` match
# rules the apply wrote in another argument order, the way iptables itself
# does, and `-S` output satisfies the literal string matches and the
# `-j TARGET$` anchors the block's readers use.
cat > "${WORK}/fake-iptables.py" <<'PYEOF'
import os
import sys

kind = sys.argv[1]
args = sys.argv[2:]
state_path = os.environ["OI5_FW_STATE_" + kind]
with open(os.environ["OI5_FW_LOG"], "a", encoding="utf-8") as log:
    log.write(kind + " " + " ".join(args) + "\n")

# iptables -S prints options in a fixed order; -j is last, which
# jump_count_gw's `-j TARGET$` anchor depends on.
ORDER = {"-s": 0, "-d": 1, "-i": 2, "-o": 3, "-p": 4, "-m": 5,
         "--ctstate": 6, "--icmp-type": 7, "--dport": 8,
         "--tcp-flags": 9, "--reject-with": 10, "-j": 11, "-g": 12}


def load():
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as fh:
            return [line for line in fh.read().split("\n") if line]
    return []


def save(rules):
    with open(state_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rules) + ("\n" if rules else ""))


def canon(spec):
    out, i, plain = [], 0, []
    tokens = spec.split()
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-m", "-p", "-j", "-g") and i + 1 < len(tokens):
            out.append((tok, tokens[i + 1]))
            i += 2
        elif tok in ("-i", "-o", "-s", "-d", "--ctstate", "--dport",
                     "--icmp-type", "--reject-with") and i + 1 < len(tokens):
            val = tokens[i + 1]
            if tok in ("-s", "-d") and val.count(".") == 3 and "/" not in val:
                val += "/32"
            out.append((tok, val))
            i += 2
        elif tok == "--tcp-flags" and i + 2 < len(tokens):
            out.append((tok, tokens[i + 1] + " " + tokens[i + 2]))
            i += 3
        else:
            plain.append(tok)
            i += 1
    out.sort(key=lambda kv: ORDER.get(kv[0], 99))
    parts = ["%s %s" % kv for kv in out]
    parts.extend(plain)
    return " ".join(parts)


def kernel(chain, spec):
    return "-A " + chain + " " + canon(spec)


rules = load()
table = "filter"
i = 0
while i < len(args) and args[i] == "-t":
    table = args[i + 1]
    i += 2
rest = args[i:]
op = rest[0] if rest else ""
if op == "-S":
    base = rest[1] if len(rest) > 1 else None
    if base == "FORWARD":
        print("-P FORWARD ACCEPT")
    for line in rules:
        if line.split(" ", 2)[1] == base:
            print(line)
elif op == "-L":
    base = rest[1] if len(rest) > 1 else None
    sys.exit(0 if any(line.split(" ", 2)[1] == base for line in rules) else 1)
elif op == "-N" or op == "-P":
    pass
elif op == "-F" or op == "-X":
    target = rest[1]
    rules = [line for line in rules if line.split(" ", 2)[1] != target]
    save(rules)
elif op == "-A":
    rules.append(kernel(rest[1], " ".join(rest[2:])))
    save(rules)
elif op == "-I":
    chain, pos, spec = rest[1], int(rest[2]), " ".join(rest[3:])
    idx = [j for j, line in enumerate(rules) if line.split(" ", 2)[1] == chain]
    at = idx[pos - 1] if pos - 1 < len(idx) else (idx[-1] + 1 if idx else len(rules))
    rules.insert(at, kernel(chain, spec))
    save(rules)
elif op == "-C":
    want = "-A " + rest[1] + " " + canon(" ".join(rest[2:]))
    sys.exit(0 if want in rules else 1)
elif op == "-D":
    want = "-A " + rest[1] + " " + canon(" ".join(rest[2:]))
    if want in rules:
        rules.remove(want)
        save(rules)
        sys.exit(0)
    sys.exit(1)
else:
    sys.exit(2)
PYEOF
chmod 700 "${WORK}/fake-iptables.py"

ipt_gw() { python3 "${WORK}/fake-iptables.py" v4 "$@"; }
ipt6_gw() { python3 "${WORK}/fake-iptables.py" v6 "$@"; }

WINN3_GATEWAY_FORWARD_IF=winn3gw0
WINN3_GATEWAY_FORWARD_CIDR=10.64.0.0/24
WINN3_GATEWAY_INNER_V4=10.64.0.1
WINN3_GATEWAY_WAN_IF=testwan
WINN3_GATEWAY_RESOLVER=0
WINN3_GATEWAY_SPEEDTEST_INGEST_PORT=0
WINN3_GATEWAY_AWG_CIDR=198.51.100.0/24
export OI5_FW_LOG="${WORK}/calls.log"

PASS=0
FAIL=0
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }

seed() {
  # The live-fleet INPUT layout: the 9111 listener accept, the guards, a
  # terminal host DROP; plus awg0's chain and NAT rule the teardown
  # positively re-confirms. The v6 filter table starts empty. Lines are
  # stored kernel-form; chain names are unique across tables, which is all
  # this fake's single per-family state file needs.
  cat > "${WORK}/v4" <<'RULES'
-A INPUT -p udp -m udp --dport 9111 -j ACCEPT
-A INPUT -j WINVPN-SSH-RECOVERY
-A INPUT -j WINVPN-LOCAL-SERVING
-A INPUT -i lo -j ACCEPT
-A INPUT -j DROP
-A WINVPN-FORWARD -j ACCEPT
-A WINVPN-NAT-POSTROUTING -s 198.51.100.0/24 -o testwan -j MASQUERADE
RULES
  : > "${WORK}/v6"
}

apply() {
  : > "${WORK}/errs"
  OI5_FW_STATE_v4="${WORK}/v4" OI5_FW_STATE_v6="${WORK}/v6" \
    apply_forwarding_firewall || return 1
}

teardown() {
  : > "${WORK}/errs"
  OI5_FW_STATE_v4="${WORK}/v4" OI5_FW_STATE_v6="${WORK}/v6" \
    teardown_forwarding_firewall || return 1
}

forward_lines() {
  python3 - "${WORK}/v4" <<'PYEOF'
import sys
try:
    lines = [line for line in open(sys.argv[1], encoding="utf-8").read().split("\n") if line]
except FileNotFoundError:
    lines = []
for line in lines:
    if line.split(" ", 2)[1] == "WINN3GW-FORWARD":
        print(line)
PYEOF
}

line_of() { grep -n -F -- "$2" "$1" | head -1 | cut -d: -f1; }
line_of_exact() { grep -n -x -F -- "$2" "$1" | head -1 | cut -d: -f1; }

seed
if apply; then
  pass "apply_forwarding_firewall exits 0 with the isolation rules"
else
  fail "apply_forwarding_firewall refused: $(cat "${WORK}/errs")"
fi

# Presence and order: the live chain equals the expected sequence exactly,
# in the fake's canonical (order-insensitive per rule) form, positions 1
# through 9. The six isolation drops sit at the HEAD, ahead of both accepts:
# a drop behind the conntrack accept would let a pre-existing (pre-upgrade
# conntrack entry) client-to-client flow keep flowing until its expiry.
expected_forward=(
'-A WINN3GW-FORWARD -i winn3gw0 -o winn3gw0 -j DROP'
'-A WINN3GW-FORWARD -s 10.64.0.0/24 -d 10.64.0.0/24 -j DROP'
'-A WINN3GW-FORWARD -d 10.0.0.0/8 -i winn3gw0 -j DROP'
'-A WINN3GW-FORWARD -d 172.16.0.0/12 -i winn3gw0 -j DROP'
'-A WINN3GW-FORWARD -d 192.168.0.0/16 -i winn3gw0 -j DROP'
'-A WINN3GW-FORWARD -d 100.64.0.0/10 -i winn3gw0 -j DROP'
'-A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
'-A WINN3GW-FORWARD -s 10.64.0.0/24 -i winn3gw0 -o testwan -j ACCEPT'
'-A WINN3GW-FORWARD -j DROP'
)
mapfile -t got_forward < <(forward_lines)
order_ok=1
if [[ "${#got_forward[@]}" != "${#expected_forward[@]}" ]]; then
  order_ok=0
  fail "WINN3GW-FORWARD holds ${#got_forward[@]} rules, want ${#expected_forward[@]}:"
  printf '%s\n' "${got_forward[@]}" | sed 's/^/  /'
else
  for i in "${!expected_forward[@]}"; do
    if [[ "${got_forward[${i}]}" != "${expected_forward[${i}]}" ]]; then
      order_ok=0
      fail "WINN3GW-FORWARD position $((i + 1)) = ${got_forward[${i}]}, want ${expected_forward[${i}]}"
    fi
  done
fi
if [[ "${order_ok}" == 1 ]]; then
  pass "WINN3GW-FORWARD: the six OI-5 drops first, then the conntrack accept, the egress accept, the default drop"
fi

# INPUT: the bare drop sits IMMEDIATELY behind the WINN3GW-INPUT jump, and
# the jump right behind the SSH-recovery guard. Behind WINVPN-INPUT is not
# good enough: that chain accepts the 9111 listener, so a tunnel packet to
# the WAN address's 9111 would be accepted ahead of a later drop.
recovery_at="$(grep -n -- '-A INPUT -j WINVPN-SSH-RECOVERY' "${WORK}/v4" | cut -d: -f1)"
jump_at="$(grep -c -F -- '-A INPUT -d 10.64.0.1/32 -i winn3gw0 -j WINN3GW-INPUT' "${WORK}/v4" || true)"
drop_count="$(grep -c -F -- '-A INPUT -i winn3gw0 -j DROP' "${WORK}/v4" || true)"
if [[ -n "${recovery_at}" && "${jump_at}" == "1" && "${drop_count}" == "1" ]]; then
  jump_pos="$(grep -n -F -- '-A INPUT -d 10.64.0.1/32 -i winn3gw0 -j WINN3GW-INPUT' "${WORK}/v4" | cut -d: -f1)"
  drop_pos="$(grep -n -F -- '-A INPUT -i winn3gw0 -j DROP' "${WORK}/v4" | cut -d: -f1)"
  if [[ "${jump_pos}" == "$((recovery_at + 1))" && "${drop_pos}" == "$((jump_pos + 1))" ]]; then
    pass "INPUT: jump right behind the SSH-recovery guard (${recovery_at}), bare drop immediately behind the jump (${drop_pos})"
  else
    fail "INPUT order wrong: recovery=${recovery_at} jump=${jump_pos} drop=${drop_pos}"
  fi
else
  fail "INPUT jump or bare drop missing or duplicated (recovery=${recovery_at} jump=${jump_at} drop=${drop_count})"
fi

# ip6tables: one drop at position 1 of INPUT, and FORWARD carries -o first
# then -i (each went in at position 1, -i first).
v6_input="$(grep -c -- '^ -A INPUT -i winn3gw0 -j DROP' "${WORK}/v6" 2>/dev/null || true)"
v6_o_pos="$(grep -n -F -- '-A FORWARD -o winn3gw0 -j DROP' "${WORK}/v6" | cut -d: -f1)"
v6_i_pos="$(grep -n -F -- '-A FORWARD -i winn3gw0 -j DROP' "${WORK}/v6" | cut -d: -f1)"
v6_lines="$(grep -c -- '-j DROP' "${WORK}/v6" || true)"
if [[ "${v6_lines}" == "3" && -n "${v6_o_pos}" && -n "${v6_i_pos}" && "${v6_o_pos}" -lt "${v6_i_pos}" ]] \
   && grep -q -F -- '-A INPUT -i winn3gw0 -j DROP' "${WORK}/v6"; then
  pass "ip6tables: INPUT -i drop, FORWARD -o before -i, position 1 each"
else
  fail "ip6tables drops wrong (${v6_lines} lines, o=${v6_o_pos} i=${v6_i_pos}):"
  sed 's/^/  /' "${WORK}/v6"
fi

# Idempotence: a second apply leaves the same rule set. The comparison is
# order-insensitive because the fake's flat state file relocates a flushed
# and rebuilt chain's lines; rule order is asserted by the sequence check
# above, and duplicates by the counts below.
cp "${WORK}/v4" "${WORK}/v4.first"
cp "${WORK}/v6" "${WORK}/v6.first"
if ! apply; then
  fail "second apply refused: $(cat "${WORK}/errs")"
fi
if cmp -s <(sort "${WORK}/v4.first") <(sort "${WORK}/v4") \
   && cmp -s <(sort "${WORK}/v6.first") <(sort "${WORK}/v6"); then
  pass "second apply is idempotent: the same rule set, no additions or removals"
else
  fail "second apply changed the rule set"
  diff <(sort "${WORK}/v4.first") <(sort "${WORK}/v4") | sed 's/^/  v4 /'
  diff <(sort "${WORK}/v6.first") <(sort "${WORK}/v6") | sed 's/^/  v6 /'
fi
if [[ "$(grep -c -F -- '-A INPUT -i winn3gw0 -j DROP' "${WORK}/v4" || true)" == "1" ]]; then
  pass "exactly one bare INPUT drop after two applies"
else
  fail "bare INPUT drop count after two applies is not 1"
fi

# Boot-helper parity: the emitted helper text carries the same rules (the
# helper rebuilds the chains at every start, so a rule only the installer
# writes would vanish at the first reboot). The INPUT drop is placed by the
# helper's own copy of place_winn3gw_input_jump, so its needle is the
# walker's insert line and the proof line behind the call.
awk '
  index($0, "cat <<'"'"'EOF'"'"' # the boot helper") { helper=1; next }
  helper && $0 == "EOF" { helper=0; next }
  helper { print }
' "${DP}" > "${WORK}/helper.txt"
parity_ok=1
while IFS= read -r needle; do
  if ! grep -Fq -- "${needle}" "${WORK}/helper.txt"; then
    parity_ok=0
    fail "boot helper lacks: ${needle}"
  fi
done <<'NEEDLES'
iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP
iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -d "${cidr}" -j DROP
iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -d "${private}" -j DROP
iptables -w 10 -I INPUT "$((first_jump_at + 1))" -i "${iface}" -j DROP
ip6tables -w 10 -I INPUT 1 -i "${iface}" -j DROP
ip6tables -w 10 -I FORWARD 1 -i "${iface}" -j DROP
ip6tables -w 10 -I FORWARD 1 -o "${iface}" -j DROP
NEEDLES
if [[ "${parity_ok}" == 1 ]]; then
  pass "boot helper text carries the OI-5 rules"
fi
accept_line="$(line_of "${WORK}/helper.txt" 'iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT')"
first_drop_line="$(line_of "${WORK}/helper.txt" 'iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP')"
private_for_line="$(line_of "${WORK}/helper.txt" 'for private in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do')"
conntrack_line="$(line_of "${WORK}/helper.txt" 'iptables -w 10 -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')"
if [[ -n "${accept_line}" && -n "${first_drop_line}" && -n "${private_for_line}" && -n "${conntrack_line}" \
      && "${first_drop_line}" -lt "${private_for_line}" && "${private_for_line}" -lt "${conntrack_line}" \
      && "${conntrack_line}" -lt "${accept_line}" ]]; then
  pass "boot helper places all six isolation drops ahead of both accepts"
else
  fail "boot helper rule order wrong: drop=${first_drop_line} for=${private_for_line} conntrack=${conntrack_line} accept=${accept_line}"
fi
jump_call_line="$(line_of "${WORK}/helper.txt" 'place_winn3gw_input_jump "${iface}" "${inner}"')"
input_proof_line="$(line_of_exact "${WORK}/helper.txt" '  iptables -w 10 -C INPUT -i "${iface}" -j DROP')"
if [[ -n "${jump_call_line}" && -n "${input_proof_line}" && "${input_proof_line}" -gt "${jump_call_line}" ]]; then
  pass "boot helper proves the bare INPUT drop only after placing the jump (${jump_call_line} < ${input_proof_line})"
else
  fail "boot helper INPUT drop proof order wrong: jump=${jump_call_line} proof=${input_proof_line}"
fi

# Teardown: the chains go, the bare drops go with them, and absence is
# positively checked by the code under test itself.
if teardown; then
  pass "teardown_forwarding_firewall exits 0"
else
  fail "teardown_forwarding_firewall refused: $(cat "${WORK}/errs")"
fi
if grep -q 'WINN3GW' "${WORK}/v4"; then
  fail "WINN3GW rules remain after teardown:"
  grep 'WINN3GW' "${WORK}/v4" | sed 's/^/  /'
else
  pass "no WINN3GW rule remains in the filter state"
fi
if grep -q -F -- '-A INPUT -i winn3gw0 -j DROP' "${WORK}/v4"; then
  fail "the bare INPUT drop survived teardown"
else
  pass "the bare INPUT drop is gone"
fi
if grep -q 'winn3gw0' "${WORK}/v6"; then
  fail "ip6tables drops survived teardown:"
  grep 'winn3gw0' "${WORK}/v6" | sed 's/^/  /'
else
  pass "the ip6tables drops are gone"
fi
if teardown; then
  pass "second teardown is idempotent"
else
  fail "second teardown refused: $(cat "${WORK}/errs")"
fi

# Re-apply after teardown rebuilds everything, isolation included.
if apply; then
  if grep -q -F -- '-A WINN3GW-FORWARD -d 100.64.0.0/10 -i winn3gw0 -j DROP' "${WORK}/v4" \
     && grep -q -F -- '-A INPUT -i winn3gw0 -j DROP' "${WORK}/v4" \
     && grep -q -F -- '-A FORWARD -i winn3gw0 -j DROP' "${WORK}/v6"; then
    pass "re-apply after teardown restores the isolation rules"
  else
    fail "re-apply lost isolation rules"
  fi
else
  fail "re-apply after teardown refused: $(cat "${WORK}/errs")"
fi

printf '%s\n' "oi5 isolation unit: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" == 0 ]]
