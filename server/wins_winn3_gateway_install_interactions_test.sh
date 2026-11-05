#!/usr/bin/env bash
# Design v17 slice S2 (2026-10-05): the standalone gateway installer's
# interaction defects, fixed before its gateway block moves into the data
# plane (DESIGN_V17.md 1.3, 2.2 items 1 to 5 and 7; test plan 5.5 "lock and
# insert position; /etc/winn mode; backup prefix"; mutants 5.6 "Helper
# inserts at position 1", "Any firewall writer without the lock", "Backup
# variable collision" and "/etc/winn at 755").
#
# Sections, each run against the live installer and then against a mutant of
# it that must turn that section red:
#   copies    the lock functions and the backup host resolver are the data
#             plane's, byte for byte
#   lock      the boot helper (boot run, --listen-only) and the installer's
#             apply_forwarding_firewall and teardown_forwarding_firewall make
#             every iptables change while the shared lock is held, and none
#             at all, not even a read, while another process holds it;
#             --check-layout takes no lock and creates no file; a caller that
#             holds the lock passes WINS_FIREWALL_LOCK_HELD=1 and is not made
#             to wait
#   insert    both WINN3GW-INPUT jump builders put the jump immediately
#             behind the last -j WINVPN-SSH-RECOVERY, so a tunnel packet
#             reaches it even when a chain ending in a DROP follows (a copy
#             further down is replaced), move a position-1 copy behind it
#             without a window with no copy, put it first when INPUT has no
#             recovery jump, repeat as a no-op, survive a Fail2Ban insert at
#             position 1 between their read and their insert, refuse a jump
#             whose position they cannot read, and take their own insert out
#             again when they refuse
#   split     --install renders and enables the helper without running it,
#             and its closing hint restarts both units when the helper unit
#             is already active; --start renders, then runs it, then writes
#             the gateway unit
#   etcwinn   /etc/winn is 0750 root:winn3-gateway in both writers
#   backup    the backup env carries the data plane's BACKUP_HOST_ID, never
#             gateway-$(hostname -s), and the backup script refuses to run
#             without it
#   elf       the staged binary's architecture comes from its ELF header,
#             read with od (ELF64, little endian); `file` is never run
#   order     the helper unit runs after netfilter-persistent, the
#             local-serving latch and systemd-tmpfiles, and may write only
#             /run/lock and /run/xtables.lock
#   xtables   prepare_wins_xtables_lock pins /run/xtables.lock as a root-owned
#             regular file through tmpfiles.d, and the helper is never
#             rendered without it
#
# The iptables fake keeps every table in a JSON state file, prints rules in
# kernel (iptables -S) form, and logs each call. For each change it records
# whether the shared lock file was locked at that moment by opening it afresh
# and trying a non-blocking flock, which conflicts with any holder.
set -euo pipefail
# In the bash macOS ships as /bin/bash (3.2.57) a failing [[ ]] does not stop
# set -e, which would silence every assertion below. Refuse such a bash.
if "${BASH}" -c 'set -e; [[ 1 == 2 ]]; exit 0'; then
  printf 'refusing to run: in %s (%s) a failing [[ ]] does not stop set -e\n' "${BASH}" "${BASH_VERSION}" >&2
  exit 2
fi
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
DATA_PLANE="${HERE}/wins_data_plane_setup_ONETOUCH.sh"
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-${HERE}/testdata/winn3_gateway_meminfo/large}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/winn3-s2-interactions.XXXXXX")"
HOLDER=""
cleanup() {
  [[ -z "${HOLDER}" ]] || kill "${HOLDER}" 2>/dev/null || true
  rm -rf -- "${WORK}"
}
trap cleanup EXIT HUP INT TERM

# The two split patches deliberately use different unreadable-table contracts.
# Override this only when comparing both contracts against the same tree.
OI5_IPV6_UNREADABLE_EXPECT="${OI5_IPV6_UNREADABLE_EXPECT:-skip}"
[[ "${OI5_IPV6_UNREADABLE_EXPECT}" == skip || "${OI5_IPV6_UNREADABLE_EXPECT}" == strict ]] || exit 2
PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
SFAIL=0
SPASS=0
spass() { SPASS=$((SPASS + 1)); printf '  PASS: %s\n' "$*"; }
sfail() { SFAIL=$((SFAIL + 1)); printf '  FAIL: %s\n' "$*"; }

[[ -f "${INSTALL}" ]] || { echo "missing installer: ${INSTALL}" >&2; exit 2; }
bash -n "${INSTALL}"

mkdir -p "${WORK}/bin"
install -m 700 "${HERE}/testdata/winn3_gateway_fake_flock.py" "${WORK}/bin/flock"
cat > "${WORK}/bin/iptables" <<'EOF'
#!/usr/bin/env python3
import fcntl
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["WINN3_S2_STATE"])
lock_path = os.environ.get("WINS_FIREWALL_LOCK", "")
args = sys.argv[1:]
call = " ".join(args)
if args[:2] == ["-w", "10"]:
    args = args[2:]
# IPv6 controls affect the IPv6 fake only, never the IPv4 fake.
if state_path.name == "state6.json":
    fail6 = os.environ.get("WINN3_OI5_FAIL6", "")
    if fail6 == "backend" or (args[:1] == ["-S"] and fail6 in ("all", args[1])):
        sys.exit(2)
    if os.environ.get("WINN3_OI5_NO_D6") == "1" and args[:1] == ["-D"]:
        sys.exit(2)
table = "filter"
if args[:1] == ["-t"]:
    table, args = args[1], args[2:]
state = json.loads(state_path.read_text(encoding="utf-8"))
chains = state["tables"].setdefault(table, {})
if state_path.name == "state6.json" and state.get("oi5_read_fail") and args[:1] == ["-S"]:
    sys.exit(2)
BUILTIN = {"filter": ["INPUT", "FORWARD", "OUTPUT"], "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
           "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]}
for name in BUILTIN.get(table, []):
    chains.setdefault(name, [])


def lock_held():
    if not lock_path or not os.path.exists(lock_path):
        return False
    fd = os.open(lock_path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def canon(chain, spec):
    src = dst = iif = oif = proto = None
    rest, target, i = [], [], 0
    while i < len(spec):
        t = spec[i]
        if t in ("-s", "-d", "-i", "-o", "-p") and i + 1 < len(spec):
            value = spec[i + 1]
            if t == "-s":
                src = value
            elif t == "-d":
                dst = value
            elif t == "-i":
                iif = value
            elif t == "-o":
                oif = value
            else:
                proto = value
            i += 2
        elif t in ("-j", "-g"):
            target = spec[i:]
            break
        else:
            rest.append(t)
            i += 1
    cidr = lambda a: a if "/" in a else a + "/32"
    out = ["-A", chain]
    if src:
        out += ["-s", cidr(src)]
    if dst:
        out += ["-d", cidr(dst)]
    if iif:
        out += ["-i", iif]
    if oif:
        out += ["-o", oif]
    if proto:
        out += ["-p", proto]
        if proto in ("tcp", "udp") and ("--dport" in rest or "--sport" in rest) and rest[:2] != ["-m", proto]:
            out += ["-m", proto]
    return " ".join(out + rest + target)


def stored(chain, line):
    return canon(chain, line.split()[2:])


def save():
    if state_path.name == "state6.json" and os.environ.get("WINN3_OI5_FAIL6_AFTER_WRITE") == "1":
        state["oi5_read_fail"] = True
    state_path.write_text(json.dumps(state), encoding="utf-8")


def log(kind):
    with open(os.environ["WINN3_S2_LOG"], "a", encoding="utf-8") as stream:
        stream.write(f"{kind} {call}\n")


def snapshot():
    with open(os.environ["WINN3_S2_LOG"] + ".input", "a", encoding="utf-8") as stream:
        stream.write(" | ".join(state["tables"]["filter"]["INPUT"]) + "\n")


op = args[0] if args else ""
chain = args[1] if len(args) > 1 else ""
user = sorted(c for c in chains if c not in BUILTIN.get(table, []))
if op == "-S" and len(args) == 1:
    log("READ")
    for name in BUILTIN.get(table, []):
        print(f"-P {name} ACCEPT")
    for name in user:
        print(f"-N {name}")
    for name in BUILTIN.get(table, []) + user:
        for line in chains[name]:
            print(line)
    sys.exit(0)
if op in ("-S", "-L", "-C"):
    log("READ")
    if chain not in chains:
        sys.stderr.write("iptables: No chain/target/match by that name.\n")
        sys.exit(1)
    if op == "-S":
        print(f"-P {chain} ACCEPT" if chain in BUILTIN.get(table, []) else f"-N {chain}")
        for line in chains[chain]:
            print(line)
        if table == "filter" and chain == "INPUT" and os.environ.get("WINN3_S2_RACE") == "1" \
                and not state.get("raced"):
            # Fail2Ban restarting between this read and the caller's insert.
            chains["INPUT"].insert(0, "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd")
            state["raced"] = True
            save()
        sys.exit(0)
    if op == "-L":
        sys.exit(0)
    want = canon(chain, args[2:])
    sys.exit(0 if any(stored(chain, line) == want for line in chains[chain]) else 1)
log("LOCKED" if lock_held() else "UNLOCKED")
if op == "-N":
    if chain in chains:
        sys.exit(1)
    chains[chain] = []
elif op == "-F":
    if chain not in chains:
        sys.exit(1)
    chains[chain] = []
elif op == "-X":
    if chain not in chains or chains[chain] or chain in BUILTIN.get(table, []) \
            or any(line.endswith(f" -j {chain}") for rules in chains.values() for line in rules):
        sys.exit(1)
    del chains[chain]
elif op == "-A":
    if chain not in chains:
        sys.exit(1)
    chains[chain].append(canon(chain, args[2:]))
elif op == "-I":
    if chain not in chains:
        sys.exit(1)
    spec, at = args[2:], 1
    if spec and spec[0].isdigit():
        at, spec = int(spec[0]), spec[1:]
    if state_path.name == "state6.json" and os.environ.get("WINN3_OI5_APPEND6") == "1":
        at = len(chains[chain]) + 1
    if at > len(chains[chain]) + 1:
        sys.exit(1)
    line = canon(chain, spec)
    if os.environ.get("WINN3_S2_ODD_FORM") == "1" and chain == "INPUT" and line.endswith(" -j WINN3GW-INPUT"):
        # An iptables that prints this jump -i first: -C and -D still match it.
        line = line.replace(" -d 10.10.0.1/32 -i winn3gw0 ", " -i winn3gw0 -d 10.10.0.1/32 ")
    chains[chain].insert(at - 1, line)
elif op == "-D":
    if chain not in chains:
        sys.exit(1)
    want = canon(chain, args[2:])
    for index, line in enumerate(chains[chain]):
        if stored(chain, line) == want:
            del chains[chain][index]
            break
    else:
        sys.exit(1)
else:
    sys.exit(2)
save()
if table == "filter" and chain == "INPUT":
    snapshot()
EOF
cat > "${WORK}/bin/ip" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == "-o route show default" ]]; then
  printf '%s\n' 'default via 192.0.2.2 dev testwan proto static'
fi
exit 0
EOF
cat > "${WORK}/bin/stat" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"%u:%a"* ]]; then
  printf '0:600\n'
else
  exec /usr/bin/stat "$@"
fi
EOF
# lockstate PATH prints held or free, by the same non-blocking probe.
cat > "${WORK}/bin/lockstate" <<'EOF'
#!/usr/bin/env python3
import fcntl, os, sys
if not os.path.exists(sys.argv[1]):
    print("absent"); sys.exit(0)
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print("free")
except BlockingIOError:
    print("held")
EOF
chmod 700 "${WORK}/bin/iptables" "${WORK}/bin/ip" "${WORK}/bin/stat" "${WORK}/bin/lockstate"
LOCK="${WORK}/wins-firewall.lock"

printf '%s\n' 'WINN3_GATEWAY_LISTEN=0.0.0.0:9111' 'WINN3_GATEWAY_FORWARD=1' \
  'WINN3_GATEWAY_FORWARD_IF=winn3gw0' 'WINN3_GATEWAY_FORWARD_CIDR=10.10.0.0/24' \
  'WINN3_GATEWAY_WAN_IF=testwan' 'WINN3_GATEWAY_INNER_V4=10.10.0.1' \
  'WINN3_GATEWAY_RESOLVER=1' > "${WORK}/gateway.env"
chmod 600 "${WORK}/gateway.env"

R='-A INPUT -j WINVPN-SSH-RECOVERY'
J='-A INPUT -j WINVPN-INPUT'
W='-A INPUT -d 10.10.0.1/32 -i winn3gw0 -j WINN3GW-INPUT'
# OI-5: the tunnel INPUT drop both builders place immediately behind W.
D='-A INPUT -i winn3gw0 -j DROP'
F2B='-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd'

# OI-5: the ip6tables fake is the iptables fake on its own state file and
# its own INPUT snapshot file, sharing the call log (so the lock section sees
# its writes under the lock too). The two never share a chain.
sed -e 's/WINN3_S2_STATE"\]/WINN3_S2_STATE6"]/' -e 's/\] + "\.input"/] + ".input6"/' \
  -e 's/^call = " "\.join(args)$/call = "ip6tables " + " ".join(args)/' \
  "${WORK}/bin/iptables" > "${WORK}/bin/ip6tables"
chmod 700 "${WORK}/bin/ip6tables"
grep -Fq 'WINN3_S2_STATE6' "${WORK}/bin/ip6tables"
grep -Fq '.input6' "${WORK}/bin/ip6tables"
grep -Fq 'call = "ip6tables " + " ".join(args)' "${WORK}/bin/ip6tables"

# mkstate INPUT-RULE...: a filter table whose WINVPN-INPUT carries the data
# plane's guards (UDP/TCP 9111 still to be placed) and whose INPUT is the
# given rules; the IPv6 filter table starts empty.
mkstate() {
  python3 - "${WORK}/state.json" "$@" <<'PY'
import json, sys
guards = ["-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY", "-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING",
          "-A WINVPN-INPUT -i lo -j ACCEPT", "-A WINVPN-INPUT -p udp -m udp --dport 9110 -j ACCEPT",
          "-A WINVPN-INPUT -j DROP"]
filt = {"INPUT": list(sys.argv[2:]), "FORWARD": [], "OUTPUT": [], "WINVPN-INPUT": guards,
        "WINVPN-SSH-RECOVERY": [], "WINVPN-LOCAL-SERVING": []}
open(sys.argv[1], "w").write(json.dumps({"tables": {"filter": filt}}))
PY
  printf '%s\n' '{"tables": {"filter": {"INPUT": [], "FORWARD": [], "OUTPUT": []}}}' > "${WORK}/state6.json"
  : > "${WORK}/log"
  : > "${WORK}/log.input"
  : > "${WORK}/log.input6"
}
input_rules() {
  python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["tables"]["filter"]["INPUT"]))' "${WORK}/state.json"
}
# chain_rules STATE TABLE CHAIN: the chain's rules in the fake's kernel form,
# one per line; nothing when the chain does not exist.
chain_rules() {
  python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))["tables"].get(sys.argv[2], {}); print("\n".join(t.get(sys.argv[3], [])))' "$1" "$2" "$3"
}
# has_chain STATE TABLE CHAIN
has_chain() {
  python3 -c 'import json,sys; sys.exit(0 if sys.argv[3] in json.load(open(sys.argv[1]))["tables"].get(sys.argv[2], {}) else 1)' "$1" "$2" "$3"
}
expect_input() {  # expect_input LABEL RULE...
  local label="$1" got want
  shift
  got="$(input_rules)"
  want="$(printf '%s\n' "$@")"
  if [[ "${got}" == "${want}" ]]; then
    spass "${label}: INPUT is as expected"
  else
    sfail "${label}: INPUT is [${got//$'\n'/ | }], want [${want//$'\n'/ | }]"
  fi
}
changes() { grep -Ec '^(LOCKED|UNLOCKED) ' "${WORK}/log" || true; }
# jump_changes: INPUT inserts and deletes of the WINN3GW-INPUT jump, without
# the delete of the legacy TCP/53-only jump that every run attempts.
jump_changes() {
  { grep -E '^(LOCKED|UNLOCKED) .* -[ID] INPUT .*WINN3GW-INPUT' "${WORK}/log" || true; } \
    | { grep -vc -- '--dport 53' || true; }
}
# drop_changes: IPv4 INPUT inserts and deletes of the OI-5 tunnel drop (the
# ip6tables fake tags its lines, and its INPUT drop is a different rule).
drop_changes() {
  { grep -E '^(LOCKED|UNLOCKED) .* -[ID] INPUT .*-i winn3gw0 -j DROP$' "${WORK}/log" || true; } \
    | { grep -vc 'ip6tables' || true; }
}
# input_listings: IPv4 `-S INPUT` reads, without the ip6tables fake's.
input_listings() {
  { grep -- '-S INPUT$' "${WORK}/log" || true; } | { grep -vc 'ip6tables' || true; }
}
unlocked() { grep -Ec '^UNLOCKED ' "${WORK}/log" || true; }
calls() { grep -c . "${WORK}/log" || true; }
# reaches_winn3gw: a tunnel packet (UDP to 10.10.0.1:53 on winn3gw0) walks the
# state file's filter INPUT, into user chains, and meets the WINN3GW-INPUT
# jump before any ACCEPT, DROP or REJECT. A matcher the walker does not know
# counts as matching, so it can only make the jump look unreachable, never
# reachable (implementation review T1, Sol-S2-T1-1).
reaches_winn3gw() {
  python3 - "${WORK}/state.json" <<'PY'
import ipaddress, json, sys
chains = json.load(open(sys.argv[1]))["tables"]["filter"]
pkt = {"-i": "winn3gw0", "-s": "10.10.0.2", "-d": "10.10.0.1", "-p": "udp", "--dport": "53"}


def matches(tokens):
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-j", "-g", "!"):
            return True
        value = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("-s", "-d"):
            if ipaddress.ip_address(pkt[t]) not in ipaddress.ip_network(value, strict=False):
                return False
        elif t in ("-i", "-p", "--dport"):
            if value != pkt[t]:
                return False
        elif t == "-o":
            return False
        elif t == "--dports":
            if pkt["--dport"] not in value.split(","):
                return False
        elif t != "-m":
            i += 1
            continue
        i += 2
    return True


def walk(name, depth):
    for line in chains.get(name, []):
        tokens = line.split()[2:]
        if not matches(tokens) or "-j" not in tokens:
            continue
        target = tokens[tokens.index("-j") + 1]
        if target == "WINN3GW-INPUT":
            return "WINN3GW-INPUT"
        if target in ("ACCEPT", "DROP", "REJECT"):
            return f"{target} in {name}"
        if target == "RETURN":
            return None
        if target in chains and depth < 8:
            verdict = walk(target, depth + 1)
            if verdict:
                return verdict
    return None


verdict = walk("INPUT", 0) or "the INPUT policy"
print(verdict)
sys.exit(0 if verdict == "WINN3GW-INPUT" else 1)
PY
}

extract_helper() {  # extract_helper SCRIPT OUT
  awk "/^  cat <<'EOF' # the boot helper: \\/usr\\/local\\/sbin\\/winn3-gateway-firewall\$/{f=1; next} f && /^EOF\$/{exit} f{print}" "$1" > "$2"
}
run_helper() {  # run_helper HELPER [ARGS...]
  local helper="$1"
  shift
  PATH="${WORK}/bin:${PATH}" WINN3_GATEWAY_ENV_FILE="${WORK}/gateway.env" \
    WINN3_GATEWAY_EDGE_HARDENING="${WORK}/no-edge-hardening" \
    WINS_FIREWALL_LOCK="${LOCK}" WINN3_S2_STATE="${WORK}/state.json" WINN3_S2_LOG="${WORK}/log" \
    WINN3_S2_STATE6="${WORK}/state6.json" \
    bash "${helper}" "$@" > "${WORK}/run.out" 2>&1
}
# run_installer SCRIPT CODE: CODE runs in a shell that sourced SCRIPT, with a
# forwarding resolver configuration and the fakes first on PATH.
run_installer() {
  PATH="${WORK}/bin:${PATH}" WINS_FIREWALL_LOCK="${LOCK}" \
    WINN3_S2_STATE="${WORK}/state.json" WINN3_S2_LOG="${WORK}/log" \
    WINN3_S2_STATE6="${WORK}/state6.json" \
    bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      WINN3_GATEWAY_FORWARD=1 WINN3_GATEWAY_RESOLVER=1 WINN3_GATEWAY_FORWARD_IF=winn3gw0
      WINN3_GATEWAY_FORWARD_CIDR=10.10.0.0/24 WINN3_GATEWAY_WAN_IF=testwan
      WINN3_GATEWAY_INNER_V4=10.10.0.1 WINN3_GATEWAY_SPEEDTEST_INGEST_PORT=0
      WINN3_GATEWAY_AWG_CIDR=10.8.0.0/16
      eval "$2"
    ' _ "$1" "$2" > "${WORK}/run.out" 2>&1
}
hold_lock() {  # hold_lock: another process holds the lock until release_lock
  rm -f "${WORK}/held"
  python3 - "${LOCK}" "${WORK}/held" <<'PY' &
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(600)
PY
  HOLDER=$!
  local i
  for ((i = 0; i < 200; i++)); do
    [[ -e "${WORK}/held" ]] && return 0
    sleep 0.05
  done
  echo "the lock holder never took the lock" >&2
  exit 2
}
release_lock() {
  kill "${HOLDER}" 2>/dev/null || true
  wait "${HOLDER}" 2>/dev/null || true
  HOLDER=""
}

# function_text FILE NAME: one top-level definition, outside the helper heredoc.
function_text() {
  awk -v name="$2" '
    index($0, "# the boot helper: /usr/local/sbin/winn3-gateway-firewall") { helper=1; next }
    helper { if ($0 == "EOF") helper=0; next }
    $0 == name "() {" { p=1 }
    p { print }
    p && $0 == "}" { exit }
  ' "$1"
}

# ---------------------------------------------------------------------------
section_copies() {
  local script="$1" helper="${WORK}/copies-helper" ours verdict name
  extract_helper "${script}" "${helper}"
  for name in wins_fw_lock wins_fw_unlock; do
    ours="$(function_text "${script}" "${name}")"
    verdict="$(python3 - "${DATA_PLANE}" "${name}" "${ours}" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
copies, i = [], 0
while i < len(lines):
    if lines[i] == sys.argv[2] + "() {":
        j = lines.index("}", i)
        copies.append("\n".join(lines[i:j + 1]))
        i = j
    i += 1
same = sum(copy == sys.argv[3] for copy in copies)
print(f"{same} {len(copies)}")
PY
)"
    if [[ "${verdict%% *}" == "${verdict##* }" && "${verdict%% *}" -ge 4 ]]; then
      spass "copies: installer ${name} equals all ${verdict##* } data-plane copies"
    else
      sfail "copies: installer ${name} equals ${verdict%% *} of ${verdict##* } data-plane copies"
    fi
  done
  ours="$(awk '$0 == "wins_fw_lock() {" { p=1 } p { print } p && $0 == "}" { exit }' "${helper}")"
  [[ -n "${ours}" && "${ours}" == "$(function_text "${script}" wins_fw_lock)" ]] \
    && spass "copies: the boot helper's wins_fw_lock is the data plane's" \
    || sfail "copies: the boot helper's wins_fw_lock differs or is missing"
  grep -Fxq 'WINS_FIREWALL_LOCK="${WINS_FIREWALL_LOCK:-/run/lock/wins-firewall.lock}"' "${helper}" \
    && [[ "$(grep -Fxc 'WINS_FIREWALL_LOCK="${WINS_FIREWALL_LOCK:-/run/lock/wins-firewall.lock}"' "${script}")" == 2 ]] \
    && spass "copies: helper and installer default to the data plane's lock file" \
    || sfail "copies: the lock file default is not /run/lock/wins-firewall.lock in both"
  [[ "$(function_text "${script}" resolve_node_backup_host_id)" == "$(function_text "${DATA_PLANE}" resolve_node_backup_host_id | sed -e 's/err /winn3gw_err /g' -e 's/log /winn3gw_log /g')" ]] \
    && spass "copies: resolve_node_backup_host_id is the data plane's under the logging rename" \
    || sfail "copies: resolve_node_backup_host_id differs from the data plane's"
}

section_lock() {
  local script="$1" helper="${WORK}/lock-helper"
  extract_helper "${script}" "${helper}"
  # Boot run with forwarding: every change under the lock, released at exit.
  rm -f "${LOCK}"
  mkstate "${R}" "${J}"
  if run_helper "${helper}" && [[ "$(changes)" -gt 10 && "$(unlocked)" == 0 ]]; then
    spass "lock: helper boot run made $(changes) changes, all under the shared lock"
  else
    sfail "lock: helper boot run rc/changes/unlocked = $(changes)/$(unlocked): $(tail -2 "${WORK}/run.out" | tr '\n' ' ')"
  fi
  [[ "$("${WORK}/bin/lockstate" "${LOCK}")" == free ]] && spass "lock: released when the helper exits" \
    || sfail "lock: still held after the helper exited"
  # --listen-only on a chain that needs both ACCEPTs.
  mkstate "${R}" "${J}"
  if run_helper "${helper}" --listen-only && [[ "$(changes)" == 2 && "$(unlocked)" == 0 ]]; then
    spass "lock: --listen-only placed both ACCEPTs under the shared lock"
  else
    sfail "lock: --listen-only changes/unlocked = $(changes)/$(unlocked)"
  fi
  # --check-layout reads only: no lock file, no change.
  rm -f "${LOCK}"
  mkstate "${R}" "${J}"
  if run_helper "${helper}" --check-layout 9111 && [[ ! -e "${LOCK}" && "$(changes)" == 0 ]]; then
    spass "lock: --check-layout created no lock file and changed nothing"
  else
    sfail "lock: --check-layout created the lock file or changed a rule"
  fi
  # Busy: the boot run waits WINS_FIREWALL_LOCK_WAIT, then refuses before any read.
  mkstate "${R}" "${J}"
  cp "${WORK}/state.json" "${WORK}/state.before"
  hold_lock
  if ! WINS_FIREWALL_LOCK_WAIT=1 run_helper "${helper}" \
      && grep -Fq 'shared firewall lock' "${WORK}/run.out" && [[ "$(calls)" == 0 ]] \
      && cmp -s "${WORK}/state.json" "${WORK}/state.before"; then
    spass "lock: with the lock busy the helper refused before its first iptables call"
  else
    sfail "lock: with the lock busy the helper made $(calls) iptables call(s) or did not refuse"
  fi
  release_lock
  # The installer's writers.
  mkstate "${R}" "${J}"
  if run_installer "${script}" 'apply_forwarding_firewall; lockstate "${WINS_FIREWALL_LOCK}"' \
      && [[ "$(changes)" -gt 10 && "$(unlocked)" == 0 ]] && [[ "$(tail -1 "${WORK}/run.out")" == free ]]; then
    spass "lock: apply_forwarding_firewall made $(changes) changes under the lock and released it"
  else
    sfail "lock: apply_forwarding_firewall changes/unlocked = $(changes)/$(unlocked): $(tail -2 "${WORK}/run.out" | tr '\n' ' ')"
  fi
  : > "${WORK}/log"
  if run_installer "${script}" 'teardown_forwarding_firewall; lockstate "${WINS_FIREWALL_LOCK}"' \
      && [[ "$(changes)" -gt 5 && "$(unlocked)" == 0 ]] && [[ "$(tail -1 "${WORK}/run.out")" == free ]]; then
    spass "lock: teardown_forwarding_firewall made $(changes) changes under the lock and released it"
  else
    sfail "lock: teardown_forwarding_firewall changes/unlocked = $(changes)/$(unlocked): $(tail -2 "${WORK}/run.out" | tr '\n' ' ')"
  fi
  local fn
  for fn in apply_forwarding_firewall teardown_forwarding_firewall; do
    mkstate "${R}" "${J}"
    cp "${WORK}/state.json" "${WORK}/state.before"
    hold_lock
    if ! run_installer "${script}" "WINS_FIREWALL_LOCK_WAIT=1 ${fn}" \
        && grep -Fq 'firewall lock' "${WORK}/run.out" && [[ "$(calls)" == 0 ]] \
        && cmp -s "${WORK}/state.json" "${WORK}/state.before"; then
      spass "lock: with the lock busy ${fn} refused before its first iptables call"
    else
      sfail "lock: with the lock busy ${fn} made $(calls) iptables call(s) or did not refuse"
    fi
    # A caller that holds the lock passes WINS_FIREWALL_LOCK_HELD=1.
    mkstate "${R}" "${J}"
    if run_installer "${script}" "WINS_FIREWALL_LOCK_HELD=1 WINS_FIREWALL_LOCK_WAIT=1 ${fn}" \
        && [[ "$(unlocked)" == 0 ]]; then
      spass "lock: ${fn} nests under a caller's lock (WINS_FIREWALL_LOCK_HELD=1)"
    else
      sfail "lock: ${fn} did not nest under a caller's lock: $(tail -2 "${WORK}/run.out" | tr '\n' ' ')"
    fi
    release_lock
  done
}

# insert_case BUILDER LABEL [race] -- INITIAL... -- EXPECTED...
insert_case() {
  local builder="$1" label="$2" race="" rc=0
  shift 2
  [[ "$1" == race ]] && { race=1; shift; }
  shift
  local -a initial=() expected=()
  while [[ "$1" != -- ]]; do initial+=("$1"); shift; done
  shift
  expected=("$@")
  mkstate "${initial[@]}"
  if [[ "${builder}" == helper ]]; then
    WINN3_S2_RACE="${race}" run_helper "${WORK}/insert-helper" || rc=$?
  else
    WINN3_S2_RACE="${race}" run_installer "${INSERT_SCRIPT}" \
      'WINS_FIREWALL_LOCK_HELD=1; apply_winn3gw_input_firewall' || rc=$?
  fi
  [[ "${rc}" == 0 ]] || { sfail "${builder} ${label}: rc ${rc}: $(tail -2 "${WORK}/run.out" | tr '\n' ' ')"; return 0; }
  expect_input "${builder} ${label}" "${expected[@]}"
  if reaches_winn3gw > "${WORK}/reach.out"; then
    spass "${builder} ${label}: a tunnel packet to the inner address reaches WINN3GW-INPUT"
  else
    sfail "${builder} ${label}: a tunnel packet to the inner address ends at $(cat "${WORK}/reach.out") before WINN3GW-INPUT"
  fi
  # No snapshot of INPUT after a change lacks the jump once it existed.
  if awk -v w="${W}" 'index($0, w) { seen=1; next } seen { bad=1 } END { exit bad }' "${WORK}/log.input"; then
    spass "${builder} ${label}: the jump never left INPUT once placed"
  else
    sfail "${builder} ${label}: INPUT lost the jump between two changes"
  fi
}

section_insert() {
  local script="$1" builder rc
  INSERT_SCRIPT="${script}"
  extract_helper "${script}" "${WORK}/insert-helper"
  for builder in helper installer; do
    # OI-5: every placed jump W is followed by the tunnel INPUT drop D.
    insert_case "${builder}" "behind the recovery jump" -- "${R}" "${J}" -- "${R}" "${W}" "${D}" "${J}"
    insert_case "${builder}" "moved from position 1" -- "${W}" "${R}" "${J}" -- "${R}" "${W}" "${D}" "${J}"
    insert_case "${builder}" "first without a recovery jump" -- "${J}" -- "${W}" "${D}" "${J}"
    insert_case "${builder}" "drop placed behind a jump that is already placed" -- "${R}" "${W}" "${J}" -- "${R}" "${W}" "${D}" "${J}"
    insert_case "${builder}" "kept where it already is" -- "${R}" "${W}" "${D}" "${J}" -- "${R}" "${W}" "${D}" "${J}"
    [[ "$(jump_changes)" == 0 && "$(drop_changes)" == 0 ]] \
      && spass "${builder}: a placed jump and drop are not inserted or deleted again" \
      || sfail "${builder}: a placed jump or drop was inserted or deleted again"
    # One INPUT listing, parsed in the shell, is all a placed jump costs
    # (implementation review T1, Gemini's single-pass proposal).
    [[ "$(input_listings)" == 1 ]] \
      && spass "${builder}: a placed jump costs one INPUT listing" \
      || sfail "${builder}: a placed jump took $(input_listings) INPUT listings"
    insert_case "${builder}" "Fail2Ban inserted at 1 mid-placement" race -- "${R}" "${J}" -- "${F2B}" "${R}" "${W}" "${D}" "${J}"
    # Implementation review T1 (Sol-S2-T1-1): only the rule right behind the
    # last recovery jump counts. WINVPN-INPUT ends in a DROP, so a copy behind
    # it is never reached; a new copy goes in front of it and the old one
    # stays behind, unreached.
    insert_case "${builder}" "moved ahead of a chain that ends in DROP" -- "${R}" "${J}" "${W}" -- "${R}" "${W}" "${D}" "${J}" "${W}"
    insert_case "${builder}" "moved from ahead of the recovery jump and from behind a DROP chain" \
      -- "${W}" "${R}" "${J}" "${W}" -- "${R}" "${W}" "${D}" "${J}" "${W}"
    insert_case "${builder}" "first ahead of a DROP chain without a recovery jump" -- "${J}" "${W}" -- "${W}" "${D}" "${J}" "${W}"
    insert_case "${builder}" "behind the last of two recovery jumps" -- "${R}" "${R}" "${J}" -- "${R}" "${R}" "${W}" "${D}" "${J}"
    insert_case "${builder}" "moved behind the last of two recovery jumps" -- "${R}" "${W}" "${R}" "${J}" -- "${R}" "${R}" "${W}" "${D}" "${J}"
    # OI-5: a drop ahead of the jump would shadow it (the walker below ends
    # at that DROP), so it is removed; a drop behind the jump but not right
    # behind it is left unreached and a new copy goes right behind the jump.
    insert_case "${builder}" "drop moved from ahead of the jump" -- "${D}" "${R}" "${W}" "${J}" -- "${R}" "${W}" "${D}" "${J}"
    insert_case "${builder}" "drop moved from between the recovery jump and the jump" -- "${R}" "${D}" "${W}" "${J}" -- "${R}" "${W}" "${D}" "${W}" "${J}"
    insert_case "${builder}" "drop placed right behind the jump ahead of a stray copy" -- "${R}" "${W}" "${J}" "${D}" -- "${R}" "${W}" "${D}" "${J}" "${D}"
    # A real nf_tables INPUT (iptables v1.8.10, france-fr1, 2026-09-23): its
    # jump is read as placed and only the OI-5 drop is added behind it
    # (implementation review T1, S2-Q4). No iptables-legacy capture exists to
    # pin that backend.
    local -a nft_input
    mapfile -t nft_input < <(grep '^-A INPUT ' "${HERE}/testdata/winn3_gateway_input_dumps/nft-1.8.10-france")
    insert_case "${builder}" "a real nf_tables dump is read as placed" -- "${nft_input[@]}" -- "${nft_input[0]}" "${D}" "${nft_input[1]}"
    [[ "${#nft_input[@]}" == 2 && "$(jump_changes)" == 0 ]] \
      && spass "${builder}: the real nf_tables jump is not inserted or deleted again" \
      || sfail "${builder}: the real nf_tables jump was inserted or deleted again"
    # A jump whose iptables -S form is not the expected one is refused unchanged.
    mkstate "${R}" '-A INPUT -i winn3gw0 -d 10.10.0.1/32 -j WINN3GW-INPUT' "${J}"
    rc=0
    if [[ "${builder}" == helper ]]; then
      run_helper "${WORK}/insert-helper" || rc=$?
    else
      run_installer "${script}" 'WINS_FIREWALL_LOCK_HELD=1; apply_winn3gw_input_firewall' || rc=$?
    fi
    if [[ "${rc}" != 0 ]] && grep -Fq 'its position cannot be read' "${WORK}/run.out" \
        && [[ "$(jump_changes)" == 0 ]]; then
      spass "${builder}: an unreadable jump form is refused without an INPUT change"
    else
      sfail "${builder}: an unreadable jump form was not refused cleanly (rc ${rc})"
    fi
  done
  # Implementation review T1 (Claude-S2-T1-1): our own insert reads back in
  # another form. The refusal takes that copy out again, so INPUT is left as
  # it was found.
  for builder in helper installer; do
    mkstate "${R}" "${J}"
    rc=0
    if [[ "${builder}" == helper ]]; then
      WINN3_S2_ODD_FORM=1 run_helper "${WORK}/insert-helper" || rc=$?
    else
      WINN3_S2_ODD_FORM=1 run_installer "${script}" 'WINS_FIREWALL_LOCK_HELD=1; apply_winn3gw_input_firewall' || rc=$?
    fi
    if [[ "${rc}" != 0 ]] && grep -Fq 'the copy this run inserted was deleted again' "${WORK}/run.out"; then
      spass "${builder}: its own insert read back in another form is refused"
    else
      sfail "${builder}: its own insert read back in another form was not refused (rc ${rc})"
    fi
    expect_input "${builder} odd form" "${R}" "${J}"
  done
  if grep -Eq -- '-I INPUT 1 .*WINN3GW-INPUT|ensure_jump_gw filter INPUT WINN3GW-INPUT' "${script}"; then
    sfail "insert: a position-1 WINN3GW-INPUT insert is still in the installer"
  else
    spass "insert: no position-1 WINN3GW-INPUT insert remains"
  fi
}

# run_main SCRIPT MODE: main with every step stubbed to a record.
run_main() {
  : > "${WORK}/main.log"
  REC="${WORK}/main.log" bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    rec() { printf "%s\n" "$*" >> "${REC}"; }
    for fn in warn_retired_winn_protocol_v3_enable_flag require_root refuse_on_hub resolve_gateway_memory \
        mark_winn3_role require_supported_production_os validate_config check_gateway_egress_mtu \
        preflight_forwarding preflight_gateway_listen_layout verify_staged_binary \
        invalidate_gateway_code_stamp ensure_service_user install_binary ensure_peer_registry \
        write_env_file ensure_udp_socket_buffers validate_cover validate_dual_auth \
        normalize_credential_cert_modes ensure_ip_forward ensure_conntrack_max apply_forwarding_firewall \
        preflight_resolver winn3gw_render_helper winn3gw_activate write_unit enable_service \
        install_gateway_maintenance report_firewall write_owned_paths_manifest record_gateway_code_stamp \
        report_unknown_owned_paths apply_listen_firewall start_service announce_non_forwarding_gateway; do
      eval "${fn}() { rec ${fn}; }"
    done
    systemctl() {
      rec "systemctl $*"
      [[ "$1" != is-active ]] || return "${HELPER_ACTIVE_RC:-3}"
    }
    WINN3_GATEWAY_FORWARD=0 WINN3_GATEWAY_MANAGE_FIREWALL=0
    main "$2"
  ' _ "$1" "$2" > "${WORK}/main.out" 2>&1
}
line_in_main_log() { grep -nx -- "$1" "${WORK}/main.log" | head -1 | cut -d: -f1; }

section_split() {
  local script="$1" render activate
  render="$(function_text "${script}" winn3gw_render_helper)"
  activate="$(function_text "${script}" winn3gw_activate)"
  if [[ -n "${render}" ]] && grep -Fq 'systemctl daemon-reload' <<<"${render}" \
      && grep -Fq 'systemctl enable winn3-gateway-firewall.service' <<<"${render}" \
      && ! grep -Eq 'systemctl[^#]*(start|restart|reload-or-restart|try-restart)' <<<"${render}"; then
    spass "split: winn3gw_render_helper reloads and enables and never starts the helper"
  else
    sfail "split: winn3gw_render_helper is missing or starts the helper"
  fi
  grep -Fq 'systemctl restart winn3-gateway-firewall.service' <<<"${activate}" \
    && spass "split: winn3gw_activate runs the helper" || sfail "split: winn3gw_activate does not run the helper"
  ! grep -Eq '^write_gateway_listen_firewall_unit\(\)' "${script}" \
    && spass "split: the combined writer is gone" || sfail "split: write_gateway_listen_firewall_unit still exists"
  if run_main "${script}" --install && [[ -n "$(line_in_main_log winn3gw_render_helper)" ]] \
      && [[ -z "$(line_in_main_log winn3gw_activate)" ]]; then
    spass "split: --install renders the helper and does not run it (this run has forwarding and the managed listen firewall off)"
  else
    sfail "split: --install did not render, or ran the helper: $(tr '\n' ' ' < "${WORK}/main.log")"
  fi
  # Implementation review T1 (S2-Q8): over an active helper unit
  # (RemainAfterExit=yes) `systemctl start winn3-gateway` would not run the
  # re-rendered helper, so the hint restarts both units.
  if HELPER_ACTIVE_RC=0 run_main "${script}" --install \
      && grep -Fq 'Reload with: systemctl restart winn3-gateway-firewall winn3-gateway' "${WORK}/main.out" \
      && ! grep -Fq 'Start with: systemctl start winn3-gateway' "${WORK}/main.out"; then
    spass "split: --install over an active helper unit says to restart both units"
  else
    sfail "split: --install over an active helper unit printed: $(grep -F -- '(--install)' "${WORK}/main.out" | tr '\n' ' ')"
  fi
  if HELPER_ACTIVE_RC=3 run_main "${script}" --install \
      && grep -Fq 'Start with: systemctl start winn3-gateway' "${WORK}/main.out" \
      && ! grep -Fq 'Reload with:' "${WORK}/main.out"; then
    spass "split: --install with the helper unit not active says to start the gateway"
  else
    sfail "split: --install with the helper unit not active printed: $(grep -F -- '(--install)' "${WORK}/main.out" | tr '\n' ' ')"
  fi
  local r a u
  if run_main "${script}" --start; then
    r="$(line_in_main_log winn3gw_render_helper)"
    a="$(line_in_main_log winn3gw_activate)"
    u="$(line_in_main_log write_unit)"
    if [[ -n "${r}" && -n "${a}" && -n "${u}" && "${r}" -lt "${a}" && "${a}" -lt "${u}" ]]; then
      spass "split: --start renders, then runs the helper, then writes the gateway unit"
    else
      sfail "split: --start order is wrong: $(tr '\n' ' ' < "${WORK}/main.log")"
    fi
  else
    sfail "split: main --start failed: $(tail -2 "${WORK}/main.out" | tr '\n' ' ')"
  fi
}

section_etcwinn() {
  local script="$1"
  : > "${WORK}/install.log"
  if INSTALL_LOG="${WORK}/install.log" bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      install() { printf "%s\n" "$*" >> "${INSTALL_LOG}"; }
      resolve_replay_journal_env() { :; }
      preserve_replay_journal_env_value() { :; }
      provision_replay_journal() { :; }
      emit_env_text() { printf "%s\n" WINN3_GATEWAY_LISTEN=0.0.0.0:9111; }
      WINN3_GATEWAY_FORWARD=1 WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT=1
      WINN3_GATEWAY_PEER_REGISTRY_PATH="$2/registry/winn3-peers.json"
      ensure_peer_registry
      write_env_file
    ' _ "${script}" "${WORK}" > "${WORK}/run.out" 2>&1; then
    if grep -Fxq -- '-d -m 750 -o root -g winn3-gateway /etc/winn' "${WORK}/install.log"; then
      spass "etcwinn: write_env_file makes /etc/winn 0750 root:winn3-gateway"
    else
      sfail "etcwinn: write_env_file does not make /etc/winn 0750 root:winn3-gateway: $(tr '\n' ' ' < "${WORK}/install.log")"
    fi
    if grep -Eq -- '^-d -m 0?750 -o root -g winn3-gateway .*/registry$' "${WORK}/install.log"; then
      spass "etcwinn: ensure_peer_registry agrees (0750, group winn3-gateway)"
    else
      sfail "etcwinn: ensure_peer_registry no longer agrees"
    fi
  else
    sfail "etcwinn: write_env_file failed: $(tail -2 "${WORK}/run.out" | tr '\n' ' ')"
  fi
  if grep -Eq -- 'install -d -m 0?755 .*/etc/winn( |$)' "${script}"; then
    sfail "etcwinn: an install -d -m 755 of /etc/winn remains"
  else
    spass "etcwinn: no writer sets /etc/winn to 0755"
  fi
}

# backup_env SCRIPT ID_FILE [VAR=VALUE...]: write the gateway backup env.
backup_env() {
  local script="$1" id_file="$2"
  shift 2
  rm -f "${WORK}/gateway-backup.env"
  env -u BACKUP_HOST_ID -u NODE_SLUG "$@" bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    install() { :; }
    chown() { :; }
    WINN3_GATEWAY_BACKUP_ENV="$2/gateway-backup.env"
    BACKUP_HOST_ID_FILE="$3"
    write_gateway_backup_env
  ' _ "${script}" "${WORK}" "${id_file}" > "${WORK}/run.out" 2>&1
}
backup_id() { sed -n 's/^BACKUP_HOST_ID=//p' "${WORK}/gateway-backup.env"; }
# backup_script_run SCRIPT ENV_LINE...: the rendered wins-gateway-backup, run
# against a scratch root whose gateway-backup.env holds ENV_LINE....
backup_script_run() {
  local script="$1" root="${WORK}/broot"
  shift
  rm -rf -- "${root}"
  mkdir -p "${root}/etc/winsvpn" "${root}/run"
  printf '%s\n' "$@" > "${root}/etc/winsvpn/gateway-backup.env"
  awk "index(\$0, \"cat > /usr/local/bin/wins-gateway-backup <<'EOF'\") {f=1; next} f && \$0 == \"EOF\" {exit} f {print}" \
    "${script}" > "${WORK}/gateway-backup.sh"
  env -u BACKUP_HOST_ID WINS_BACKUP_SOURCE_ROOT="${root}" WINS_BACKUP_RUNTIME_ROOT="${root}/run" \
    bash "${WORK}/gateway-backup.sh" > "${WORK}/run.out" 2>&1
}

section_backup() {
  local script="$1" first second
  printf 'spain-0123456789ab\n' > "${WORK}/id-a"
  printf 'kansas-ba9876543210\n' > "${WORK}/id-b"
  if backup_env "${script}" "${WORK}/id-a" && [[ "$(backup_id)" == spain-0123456789ab ]]; then
    spass "backup: the data plane's pinned BACKUP_HOST_ID is used"
  else
    sfail "backup: pinned id not used: $(tail -1 "${WORK}/run.out")"
  fi
  first="$(backup_id 2>/dev/null || true)"
  backup_env "${script}" "${WORK}/id-b" || true
  second="$(backup_id 2>/dev/null || true)"
  if [[ -n "${first}" && -n "${second}" && "${first}" != "${second}" && "${first}" != gateway-* ]]; then
    spass "backup: two hosts with one hostname get two prefixes (${first}, ${second})"
  else
    sfail "backup: prefixes collide or fall back to gateway-<hostname> (${first:-none}, ${second:-none})"
  fi
  if backup_env "${script}" "${WORK}/id-a" BACKUP_HOST_ID=explicit-node-1 && [[ "$(backup_id)" == explicit-node-1 ]]; then
    spass "backup: an explicit BACKUP_HOST_ID wins, as in the data plane"
  else
    sfail "backup: an explicit BACKUP_HOST_ID was not used"
  fi
  printf 'not a valid id!\n' > "${WORK}/id-bad"
  if ! backup_env "${script}" "${WORK}/id-bad" && [[ ! -e "${WORK}/gateway-backup.env" ]]; then
    spass "backup: an invalid pinned id refuses and writes no backup env"
  else
    sfail "backup: an invalid pinned id was accepted"
  fi
  rm -f "${WORK}/id-new"
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    if backup_env "${script}" "${WORK}/id-new" NODE_SLUG=test-node \
        && [[ "$(backup_id)" =~ ^test-node-[0-9a-f]{12}$ && "$(tr -d '[:space:]' < "${WORK}/id-new")" == "$(backup_id)" ]]; then
      first="$(backup_id)"
      backup_env "${script}" "${WORK}/id-new" NODE_SLUG=other-slug || true
      [[ "$(backup_id)" == "${first}" ]] && spass "backup: a minted id is pinned and reused" \
        || sfail "backup: a second run did not reuse the pinned id"
    else
      sfail "backup: no id was minted and pinned: $(tail -1 "${WORK}/run.out")"
    fi
  else
    if ! backup_env "${script}" "${WORK}/id-new" NODE_SLUG=test-node && [[ ! -e "${WORK}/gateway-backup.env" ]]; then
      spass "backup: without /proc/sys/kernel/random/uuid (non-Linux host) minting fails closed (mint case runs on Linux)"
    else
      sfail "backup: minting without a uuid source did not fail closed"
    fi
  fi
  # Implementation review T1 (S2-Q7): the backup script itself has no
  # gateway-$(hostname -s) fallback; without BACKUP_HOST_ID it refuses.
  local rc=0
  backup_script_run "${script}" 'RCLONE_REMOTE=GoogleDrive_secured' 'REQUIRE_REMOTE_BACKUP=0' || rc=$?
  if [[ "${rc}" != 0 ]] && grep -Fq 'BACKUP_HOST_ID missing; re-run the installer' "${WORK}/run.out" \
      && [[ -z "$(ls -A "${WORK}/broot/run")" ]]; then
    spass "backup: the backup script refuses to run without BACKUP_HOST_ID and leaves nothing behind"
  else
    sfail "backup: without BACKUP_HOST_ID the backup script went on (rc ${rc}): $(tail -1 "${WORK}/run.out")"
  fi
  backup_script_run "${script}" 'RCLONE_REMOTE=GoogleDrive_secured' 'BACKUP_HOST_ID=spain-0123456789ab' || true
  if ! grep -Fq 'BACKUP_HOST_ID missing' "${WORK}/run.out" && grep -Fq 'fresh-install recovery contract' "${WORK}/run.out"; then
    spass "backup: with BACKUP_HOST_ID the backup script passes that check (and stops at the next, the absent recovery contract)"
  else
    sfail "backup: with BACKUP_HOST_ID the backup script did not reach its next check: $(tail -1 "${WORK}/run.out")"
  fi
  if grep -v '^[[:space:]]*#' "${WORK}/gateway-backup.sh" | grep -Eq 'BACKUP_HOST_ID:-|gateway-\$\{HOST\}|gateway-\$\(hostname'; then
    sfail "backup: the backup script still falls back to a hostname prefix"
  else
    spass "backup: the backup script has no hostname fallback"
  fi
}

# elf_fixture NAME CLASS MACHINE_LOW [DATA]: a 64-byte header, then filler.
# DATA is the encoding byte, 01 (little endian) unless given.
elf_fixture() {
  python3 - "${WORK}/stage/$1" "$2" "$3" "${4:-01}" <<'PY'
import sys
path, klass, machine, data = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
header = bytearray(64)
header[0:4] = b"\x7fELF"
header[4], header[5], header[6] = klass, data, 1
header[18:20] = machine.to_bytes(2, "little")
open(path, "wb").write(bytes(header) + b"fixture body\n")
PY
}
verify_as() {  # verify_as SCRIPT HOST_ARCH NAME
  ( cd "${WORK}/stage" && shasum -a 256 "$3" 2>/dev/null > "$3.sha256" || sha256sum "$3" > "$3.sha256" )
  bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    host_arch_value="$2"
    uname() { printf "%s\n" "${host_arch_value}"; }
    file() { printf "%s\n" unexpected-file-command >&2; return 97; }
    WINN3_GATEWAY_STAGING_DIR="$3"
    WINN3_GATEWAY_BIN_NAME="$4"
    verify_staged_binary
  ' _ "$1" "$2" "${WORK}/stage" "$3" > "${WORK}/run.out" 2>&1
}

section_elf() {
  local script="$1" host name want
  mkdir -p "${WORK}/stage"
  elf_fixture amd64 02 3e
  elf_fixture arm64 02 b7
  elf_fixture i386 01 03
  elf_fixture x32 01 3e
  # Big endian (data byte 02) with the little-endian e_machine bytes of each
  # supported machine (implementation review T1, S2-Q6).
  elf_fixture amd64be 02 3e 02
  elf_fixture arm64be 02 b7 02
  printf 'not an elf at all, just text\n' > "${WORK}/stage/text"
  printf '\177ELF\002\001\001\000\000\000' > "${WORK}/stage/short"
  for host in x86_64 aarch64; do
    for name in amd64 arm64 i386 x32 amd64be arm64be text short; do
      want=refuse
      [[ "${host}/${name}" == x86_64/amd64 || "${host}/${name}" == aarch64/arm64 ]] && want=accept
      if verify_as "${script}" "${host}" "${name}"; then
        if [[ "${want}" == accept ]] && grep -Fq "(${host})" "${WORK}/run.out"; then
          spass "elf: ${host} host accepts ${name}"
        else
          sfail "elf: ${host} host accepted ${name}"
        fi
      elif [[ "${want}" == refuse ]] && grep -Fq "Host is ${host} but the staged binary is" "${WORK}/run.out"; then
        spass "elf: ${host} host refuses ${name}"
      else
        sfail "elf: ${host} host ${name}: want ${want}: $(tail -1 "${WORK}/run.out")"
      fi
      if grep -Fq unexpected-file-command "${WORK}/run.out"; then
        sfail "elf: ${host}/${name} ran file(1)"
      fi
    done
  done
  grep -Eq '(^|[^[:alnum:]_-])file -b ' "${script}" && sfail "elf: file -b remains in the installer" \
    || spass "elf: the installer no longer runs file -b"
}

section_order() {
  local script="$1" unit after
  unit="$(awk "index(\$0, \"cat > /etc/systemd/system/winn3-gateway-firewall.service <<'EOF'\") {f=1; next} f && \$0 == \"EOF\" {exit} f {print}" "${script}")"
  after="$(sed -n 's/^After=//p' <<<"${unit}")"
  local want ok=1
  for want in network-online.target wins-vpn-firewall.service netfilter-persistent.service \
      wins-node-local-serving.service systemd-tmpfiles-setup.service; do
    [[ " ${after} " == *" ${want} "* ]] || { ok=0; sfail "order: helper unit After= lacks ${want}"; }
  done
  [[ "${ok}" == 1 ]] && spass "order: helper unit runs after netfilter-persistent, the latch, wins-vpn-firewall and systemd-tmpfiles"
  grep -Fxq 'Before=winn3-gateway.service' <<<"${unit}" && spass "order: helper unit runs before the gateway" \
    || sfail "order: helper unit lost Before=winn3-gateway.service"
  if grep -Fxq 'ProtectSystem=strict' <<<"${unit}" && [[ "$(grep -c '^ReadWritePaths=' <<<"${unit}")" == 1 ]] \
      && grep -Fxq 'ReadWritePaths=/run/lock /run/xtables.lock' <<<"${unit}"; then
    spass "order: helper unit stays ProtectSystem=strict with only /run/lock (shared lock) and /run/xtables.lock (iptables-legacy lock) writable"
  else
    sfail "order: helper unit cannot open the shared lock and the xtables lock under ProtectSystem=strict, or may write more"
  fi
}

# xtables_setup: a PATH with only what prepare_wins_xtables_lock runs, and a
# systemd-tmpfiles stand-in kept in a directory of its own.
xtables_setup() {
  local tool
  mkdir -p "${WORK}/xbase" "${WORK}/xtmpfiles"
  for tool in cat chmod mkdir; do
    ln -sf "$(command -v "${tool}")" "${WORK}/xbase/${tool}"
  done
  # Launch Python through its installed path. A scratch symlink makes the
  # macOS interpreter try to resolve an inaccessible ancestor at startup.
  python3 -B - "${WORK}/xbase/python3" "$(command -v python3)" <<'PY'
from pathlib import Path
import os
import shlex
import sys
path = Path(sys.argv[1])
path.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.argv[2]) + ' "$@"\n')
os.chmod(path, 0o700)
PY
  ln -sf "${BASH}" "${WORK}/xbase/bash"
  cat > "${WORK}/xbase/stat" <<'EOF'
#!/usr/bin/env bash
# stat -c %u PATH: the owner the case sets (the test does not run as root).
[[ "$1" == -c && "$2" == %u && -e "$3" ]] || exit 1
printf '%s\n' "${WINN3_S2_XT_UID:-0}"
EOF
  cat > "${WORK}/xtmpfiles/systemd-tmpfiles" <<'EOF'
#!/usr/bin/env bash
# systemd-tmpfiles --create CONF, for `f` lines only: create the file when it
# is absent (never truncate it), then set its mode.
printf '%s\n' "$*" >> "${WINN3_S2_XT_LOG}"
[[ "$1" == --create && -f "$2" ]] || exit 1
while read -r type path mode _; do
  [[ "${type}" == f ]] || exit 1
  [[ -e "${path}" ]] || : > "${path}"
  chmod "${mode}" "${path}"
done < "$2"
EOF
  chmod 700 "${WORK}/xbase/stat" "${WORK}/xtmpfiles/systemd-tmpfiles"
}
xtables_reset() {
  rm -rf -- "${WORK}/xroot" "${WORK}/xt.log"
  mkdir -p "${WORK}/xroot/run" "${WORK}/xroot/etc"
  : > "${WORK}/xt.log"
}
# xtables_run SCRIPT TMPFILES(yes|no) [VAR=VALUE...]: SCRIPT's
# prepare_wins_xtables_lock, its two absolute paths moved under ${WORK}/xroot.
xtables_run() {
  local script="$1" with="$2" fn path="${WORK}/xbase"
  shift 2
  fn="$(function_text "${script}" prepare_wins_xtables_lock \
    | sed -e "s#/etc/tmpfiles.d#${WORK}/xroot/etc/tmpfiles.d#g" -e "s#/run/xtables.lock#${WORK}/xroot/run/xtables.lock#g")"
  [[ "${with}" == yes ]] && path="${WORK}/xtmpfiles:${path}"
  env -i LC_ALL=C HOME="${WORK}" "$@" PATH="${path}" WINN3_S2_XT_LOG="${WORK}/xt.log" "${BASH}" -c '
    set -euo pipefail
    install() { local dir; for dir; do :; done; mkdir -p -- "${dir}"; }
    eval "$1"
    prepare_wins_xtables_lock
  ' _ "${fn}" > "${WORK}/run.out" 2>&1
}
mode_of() { python3 -c 'import os, stat, sys; print(format(stat.S_IMODE(os.stat(sys.argv[1]).st_mode), "o"))' "$1"; }
# render_run SCRIPT PREPARE_RC: SCRIPT's winn3gw_render_helper with its paths
# moved under ${WORK}/xroot and prepare_wins_xtables_lock answering PREPARE_RC.
render_run() {
  local fn
  fn="$(function_text "$1" winn3gw_render_helper \
    | sed -e "s#/usr/local/sbin/#${WORK}/xroot/sbin/#g" -e "s#/etc/systemd/system/#${WORK}/xroot/units/#g")"
  rm -rf -- "${WORK}/xroot"
  mkdir -p "${WORK}/xroot/sbin" "${WORK}/xroot/units"
  : > "${WORK}/render.log"
  REC="${WORK}/render.log" bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    rec() { printf "%s\n" "$*" >> "${REC}"; }
    prepare_rc="$3"
    prepare_wins_xtables_lock() { rec prepare; return "${prepare_rc}"; }
    systemctl() { rec "systemctl $*"; }
    winn3gw_die() { rec "winn3gw_die $*"; exit 3; }
    eval "$2"
    winn3gw_render_helper
  ' _ "$1" "${fn}" "$2" > "${WORK}/run.out" 2>&1
}

section_xtables() {
  local script="$1" rc
  local conf="${WORK}/xroot/etc/tmpfiles.d/wins-xtables-lock.conf" lock="${WORK}/xroot/run/xtables.lock"
  xtables_setup
  xtables_reset
  if xtables_run "${script}" yes && [[ -f "${lock}" && ! -L "${lock}" ]] \
      && [[ "$(cat "${conf}")" == "f ${lock} 0600 root root -" ]] \
      && [[ "$(mode_of "${conf}")" == 644 && "$(mode_of "${lock}")" == 600 ]] \
      && grep -Fxq -- "--create ${conf}" "${WORK}/xt.log"; then
    spass "xtables: the tmpfiles.d entry is written 0644 and applied, and the lock is a 0600 regular file"
  else
    sfail "xtables: prepare_wins_xtables_lock did not pin the lock: $(tail -1 "${WORK}/run.out")"
  fi
  if [[ "$(function_text "${script}" prepare_wins_xtables_lock | grep -cFx 'f /run/xtables.lock 0600 root root -')" == 1 ]]; then
    spass "xtables: the entry is type f (create, never truncate a lock in use), 0600 root:root"
  else
    sfail "xtables: the tmpfiles.d entry is not 'f /run/xtables.lock 0600 root root -'"
  fi
  xtables_reset
  rc=0
  xtables_run "${script}" no || rc=$?
  if [[ "${rc}" != 0 ]] && grep -Fq 'systemd-tmpfiles is required' "${WORK}/run.out" && [[ ! -e "${conf}" && ! -e "${lock}" ]]; then
    spass "xtables: without systemd-tmpfiles it refuses and writes nothing"
  else
    sfail "xtables: without systemd-tmpfiles rc ${rc}: $(tail -1 "${WORK}/run.out")"
  fi
  xtables_reset
  : > "${WORK}/xroot/elsewhere"
  ln -s "$(CDPATH='' cd -- "${WORK}/xroot" && pwd -P)/elsewhere" "${lock}"
  rc=0
  xtables_run "${script}" yes || rc=$?
  if [[ "${rc}" != 0 ]] && grep -Fq 'must be a regular file' "${WORK}/run.out"; then
    spass "xtables: a symlinked lock is refused"
  else
    sfail "xtables: a symlinked lock was accepted (rc ${rc})"
  fi
  xtables_reset
  rc=0
  xtables_run "${script}" yes WINN3_S2_XT_UID=1000 || rc=$?
  if [[ "${rc}" != 0 ]] && grep -Fq 'must be owned by root' "${WORK}/run.out"; then
    spass "xtables: a lock not owned by root is refused"
  else
    sfail "xtables: a lock not owned by root was accepted (rc ${rc})"
  fi
  rc=0
  render_run "${script}" 1 || rc=$?
  if [[ "${rc}" == 3 ]] && grep -Fq 'winn3gw_die Could not prepare /run/xtables.lock' "${WORK}/render.log" \
      && [[ ! -e "${WORK}/xroot/sbin/winn3-gateway-firewall" && ! -e "${WORK}/xroot/units/winn3-gateway-firewall.service" ]]; then
    spass "xtables: the helper is not rendered when the lock cannot be prepared"
  else
    sfail "xtables: the helper was rendered without the lock (rc ${rc}): $(tr '\n' ' ' < "${WORK}/render.log")"
  fi
  rc=0
  render_run "${script}" 0 || rc=$?
  if [[ "${rc}" == 0 && "$(head -1 "${WORK}/render.log")" == prepare ]] \
      && [[ -s "${WORK}/xroot/sbin/winn3-gateway-firewall" && -s "${WORK}/xroot/units/winn3-gateway-firewall.service" ]] \
      && grep -Fxq 'systemctl enable winn3-gateway-firewall.service' "${WORK}/render.log"; then
    spass "xtables: the renderer prepares the lock first, then writes and enables the helper"
  else
    sfail "xtables: the renderer did not prepare the lock first (rc ${rc}): $(tr '\n' ' ' < "${WORK}/render.log")"
  fi
}

# ---------------------------------------------------------------------------
# OI-5 (PQ isolation round, 2026-10-11): both builders write the six client
# isolation drops at the head of WINN3GW-FORWARD in the agreed order, ahead of
# the conntrack accept and the egress accept; place the tunnel INPUT drop
# right behind the WINN3GW-INPUT jump; and drop IPv6 on the tunnel interface
# in both directions at position 1 of ip6tables INPUT and FORWARD. A second
# run changes nothing. The installer's teardown removes all of it, and a
# teardown with nothing applied succeeds.
FWD_EXPECTED=(
  '-A WINN3GW-FORWARD -i winn3gw0 -o winn3gw0 -j DROP'
  '-A WINN3GW-FORWARD -s 10.10.0.0/24 -d 10.10.0.0/24 -j DROP'
  '-A WINN3GW-FORWARD -d 10.0.0.0/8 -i winn3gw0 -j DROP'
  '-A WINN3GW-FORWARD -d 172.16.0.0/12 -i winn3gw0 -j DROP'
  '-A WINN3GW-FORWARD -d 192.168.0.0/16 -i winn3gw0 -j DROP'
  '-A WINN3GW-FORWARD -d 100.64.0.0/10 -i winn3gw0 -j DROP'
  '-A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
  '-A WINN3GW-FORWARD -s 10.10.0.0/24 -i winn3gw0 -o testwan -j ACCEPT'
  '-A WINN3GW-FORWARD -j DROP'
)
V6_INPUT_EXPECTED=('-A INPUT -i winn3gw0 -j DROP')
# Both inserted at position 1, -i first, so -o reads first.
V6_FORWARD_EXPECTED=('-A FORWARD -o winn3gw0 -j DROP' '-A FORWARD -i winn3gw0 -j DROP')
expect_chain() {  # expect_chain LABEL STATE TABLE CHAIN [RULE...]
  local label="$1" state="$2" table="$3" chain="$4" got want
  shift 4
  got="$(chain_rules "${state}" "${table}" "${chain}")"
  want="$(printf '%s\n' "$@")"
  if [[ "${got}" == "${want}" ]]; then
    spass "${label}: ${table}/${chain} is as expected"
  else
    sfail "${label}: ${table}/${chain} is [${got//$'\n'/ | }], want [${want//$'\n'/ | }]"
  fi
}
isolation_checks() {  # isolation_checks LABEL: the applied state, both families
  local label="$1"
  expect_chain "${label}" "${WORK}/state.json" filter WINN3GW-FORWARD "${FWD_EXPECTED[@]}"
  expect_input "${label}" "${R}" "${W}" "${D}" "${J}"
  if reaches_winn3gw > "${WORK}/reach.out"; then
    spass "${label}: a tunnel packet to the inner address still reaches WINN3GW-INPUT ahead of the drop"
  else
    sfail "${label}: a tunnel packet to the inner address ends at $(cat "${WORK}/reach.out")"
  fi
  expect_chain "${label}" "${WORK}/state6.json" filter INPUT "${V6_INPUT_EXPECTED[@]}"
  expect_chain "${label}" "${WORK}/state6.json" filter FORWARD "${V6_FORWARD_EXPECTED[@]}"
}
isolation_rerun_unchanged() {  # isolation_rerun_unchanged LABEL BUILDER-COMMAND...
  local label="$1" rc=0
  shift
  cp "${WORK}/state.json" "${WORK}/state.first"
  cp "${WORK}/state6.json" "${WORK}/state6.first"
  "$@" || rc=$?
  [[ "${rc}" == 0 ]] && spass "${label}: second run succeeded" \
    || sfail "${label}: second run rc ${rc}: $(tail -3 "${WORK}/run.out" | tr '\n' ' ')"
  if cmp -s "${WORK}/state.json" "${WORK}/state.first" && cmp -s "${WORK}/state6.json" "${WORK}/state6.first"; then
    spass "${label}: a second run changed nothing (no duplicate rule, both families)"
  else
    sfail "${label}: a second run changed the ruleset"
  fi
}
section_isolation() {
  local script="$1" helper="${WORK}/isolation-helper" rc chain
  extract_helper "${script}" "${helper}"
  mkstate "${R}" "${J}"
  rc=0
  run_helper "${helper}" || rc=$?
  [[ "${rc}" == 0 ]] && spass "helper: boot run succeeded" \
    || sfail "helper: boot run rc ${rc}: $(tail -3 "${WORK}/run.out" | tr '\n' ' ')"
  isolation_checks "helper first run"
  isolation_rerun_unchanged "helper" run_helper "${helper}"
  isolation_checks "helper second run"

  mkstate "${R}" "${J}"
  rc=0
  run_installer "${script}" 'apply_forwarding_firewall' || rc=$?
  [[ "${rc}" == 0 ]] && spass "installer: apply_forwarding_firewall succeeded" \
    || sfail "installer: apply rc ${rc}: $(tail -3 "${WORK}/run.out" | tr '\n' ' ')"
  isolation_checks "installer first apply"
  grep -Fq '6 isolation drops, then accept' "${WORK}/run.out" \
    && spass "installer: the apply log names the six isolation drops" \
    || sfail "installer: the apply log does not name the isolation drops"
  grep -Fq 'IPv6 drops applied for winn3gw0' "${WORK}/run.out" \
    && spass "installer: the apply log names the IPv6 drops" \
    || sfail "installer: the apply log does not name the IPv6 drops"
  isolation_rerun_unchanged "installer" run_installer "${script}" 'apply_forwarding_firewall'
  isolation_checks "installer second apply"

  rc=0
  run_installer "${script}" 'teardown_forwarding_firewall' || rc=$?
  [[ "${rc}" == 0 ]] && spass "installer: teardown_forwarding_firewall succeeded" \
    || sfail "installer: teardown rc ${rc}: $(tail -3 "${WORK}/run.out" | tr '\n' ' ')"
  expect_input "installer teardown" "${R}" "${J}"
  for chain in WINN3GW-FORWARD WINN3GW-INPUT; do
    if has_chain "${WORK}/state.json" filter "${chain}"; then
      sfail "installer teardown: filter/${chain} survived"
    else
      spass "installer teardown: filter/${chain} is gone"
    fi
  done
  if has_chain "${WORK}/state.json" nat WINN3GW-NAT-POSTROUTING; then
    sfail "installer teardown: nat/WINN3GW-NAT-POSTROUTING survived"
  else
    spass "installer teardown: nat/WINN3GW-NAT-POSTROUTING is gone"
  fi
  expect_chain "installer teardown" "${WORK}/state6.json" filter INPUT
  expect_chain "installer teardown" "${WORK}/state6.json" filter FORWARD
  # Idempotent teardown: nothing applied, still a success and still nothing.
  rc=0
  run_installer "${script}" 'teardown_forwarding_firewall' || rc=$?
  [[ "${rc}" == 0 ]] && spass "installer: a second teardown succeeds with nothing to remove" \
    || sfail "installer: a second teardown rc ${rc}"
  expect_input "installer second teardown" "${R}" "${J}"
}

# Shadow controls require repair even under the probe-and-skip contract.
ipv6_builder_apply() {  # BUILDER SCRIPT HELPER
  if [[ "$1" == helper ]]; then
    run_helper "$3"
  else
    run_installer "$2" 'apply_forwarding_firewall'
  fi
}
ipv6_seed_shadow() {
  python3 - "${WORK}/state6.json" <<'PY6'
import json, sys
state = {"tables": {"filter": {
    "INPUT": ["-A INPUT -j ACCEPT", "-A INPUT -i winn3gw0 -j DROP",
              "-A INPUT -i othertun -j DROP", "-A INPUT -i winn3gw0 -j DROP"],
    "FORWARD": ["-A FORWARD -j ACCEPT", "-A FORWARD -i winn3gw0 -j DROP",
                "-A FORWARD -o winn3gw0 -j DROP", "-A FORWARD -i othertun -j DROP",
                "-A FORWARD -i winn3gw0 -j DROP", "-A FORWARD -o winn3gw0 -j DROP"],
    "OUTPUT": []}}}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(state, stream)
PY6
}
section_ipv6shadow() {
  local script="$1" helper="${WORK}/ipv6-shadow-helper" rc builder
  extract_helper "${script}" "${helper}"
  for builder in helper installer; do
    mkstate "${R}" "${J}"
    ipv6_seed_shadow
    export WINN3_OI5_NO_D6=1
    rc=0
    ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
    unset WINN3_OI5_NO_D6
    [[ "${rc}" != 0 ]] && spass "${builder}: blocked deletion refuses shadowed drops" \
      || sfail "${builder}: blocked deletion falsely reported success"

    mkstate "${R}" "${J}"
    ipv6_seed_shadow
    rc=0
    ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
    [[ "${rc}" == 0 ]] && spass "${builder}: shadow repair succeeded" \
      || sfail "${builder}: shadow repair rc ${rc}"
    expect_chain "${builder} shadow repair" "${WORK}/state6.json" filter INPUT \
      "${V6_INPUT_EXPECTED[@]}" '-A INPUT -j ACCEPT' '-A INPUT -i othertun -j DROP'
    expect_chain "${builder} shadow repair" "${WORK}/state6.json" filter FORWARD \
      "${V6_FORWARD_EXPECTED[@]}" '-A FORWARD -j ACCEPT' '-A FORWARD -i othertun -j DROP'
    cp "${WORK}/state6.json" "${WORK}/state6.repaired"
    rc=0
    ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
    [[ "${rc}" == 0 ]] && spass "${builder}: repaired re-apply succeeded" \
      || sfail "${builder}: repaired re-apply rc ${rc}"
    cmp -s "${WORK}/state6.json" "${WORK}/state6.repaired" \
      && spass "${builder}: repaired re-apply preserves order and has no duplicates" \
      || sfail "${builder}: repaired re-apply changed IPv6 state"

    # Even drops already at the head can have a second copy further down.
    # A failed delete must not leave those duplicates certified by the head.
    mkstate "${R}" "${J}"
    python3 - "${WORK}/state6.json" <<'PY6'
import json, sys
state = {"tables": {"filter": {
    "INPUT": ["-A INPUT -i winn3gw0 -j DROP", "-A INPUT -j ACCEPT",
              "-A INPUT -i winn3gw0 -j DROP"],
    "FORWARD": ["-A FORWARD -o winn3gw0 -j DROP", "-A FORWARD -i winn3gw0 -j DROP",
                "-A FORWARD -j ACCEPT", "-A FORWARD -i winn3gw0 -j DROP",
                "-A FORWARD -o winn3gw0 -j DROP"], "OUTPUT": []}}}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(state, stream)
PY6
    export WINN3_OI5_NO_D6=1
    rc=0
    ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
    unset WINN3_OI5_NO_D6
    [[ "${rc}" != 0 ]] && spass "${builder}: blocked deletion refuses duplicate drops at the head" \
      || sfail "${builder}: duplicate drops at the head falsely reported success"

    # A backend can accept an insert but place the rule behind ACCEPT.
    # Presence checks alone must not certify that state.
    mkstate "${R}" "${J}"
    ipv6_seed_shadow
    export WINN3_OI5_APPEND6=1
    rc=0
    ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
    unset WINN3_OI5_APPEND6
    [[ "${rc}" != 0 ]] && spass "${builder}: misplaced inserts are refused" \
      || sfail "${builder}: misplaced inserts falsely reported success"

    # A successful initial probe does not excuse a failed verification read.
    mkstate "${R}" "${J}"
    export WINN3_OI5_FAIL6_AFTER_WRITE=1
    rc=0
    ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
    unset WINN3_OI5_FAIL6_AFTER_WRITE
    [[ "${rc}" != 0 ]] && spass "${builder}: failed post-write listing is refused" \
      || sfail "${builder}: failed post-write listing falsely reported success"
  done
}

# Unreadable controls have their own contract and counts. A read failure is
# injected separately into INPUT, FORWARD, both reads, and the whole backend.
section_ipv6unreadable() {
  local script="$1" helper="${WORK}/ipv6-unreadable-helper" rc builder fault
  extract_helper "${script}" "${helper}"
  for builder in helper installer; do
    for fault in INPUT FORWARD all backend; do
      mkstate "${R}" "${J}"
      cp "${WORK}/state6.json" "${WORK}/state6.before"
      export WINN3_OI5_FAIL6="${fault}"
      rc=0
      ipv6_builder_apply "${builder}" "${script}" "${helper}" || rc=$?
      unset WINN3_OI5_FAIL6
      if [[ "${OI5_IPV6_UNREADABLE_EXPECT}" == skip ]]; then
        [[ "${rc}" == 0 ]] && spass "${builder} ${fault}: unreadable IPv6 skips apply" \
          || sfail "${builder} ${fault}: skip contract rc ${rc}"
        grep -Fq 'the IPv6 drops for winn3gw0 were not installed' "${WORK}/run.out" \
          && spass "${builder} ${fault}: skip warning is explicit" \
          || sfail "${builder} ${fault}: skip warning is absent"
        has_chain "${WORK}/state.json" filter WINN3GW-FORWARD \
          && spass "${builder} ${fault}: IPv4 apply completes under skip contract" \
          || sfail "${builder} ${fault}: IPv4 apply did not complete"
      else
        [[ "${rc}" != 0 ]] && spass "${builder} ${fault}: unreadable IPv6 refuses apply" \
          || sfail "${builder} ${fault}: unreadable IPv6 was accepted"
        if grep -Fq 'the IPv6 drops for winn3gw0 were not installed' "${WORK}/run.out"; then
          sfail "${builder} ${fault}: refusal was described as a skip"
        else
          spass "${builder} ${fault}: refusal is not described as a skip"
        fi
        if has_chain "${WORK}/state.json" filter WINN3GW-FORWARD; then
          sfail "${builder} ${fault}: IPv6 preflight allowed IPv4 forwarding writes"
        else
          spass "${builder} ${fault}: IPv6 preflight precedes IPv4 forwarding writes"
        fi
      fi
      cmp -s "${WORK}/state6.json" "${WORK}/state6.before" \
        && spass "${builder} ${fault}: unreadable IPv6 state is untouched" \
        || sfail "${builder} ${fault}: unreadable IPv6 state was changed"
    done
  done
}

SECTIONS=(copies lock insert split etcwinn backup elf order xtables isolation ipv6shadow ipv6unreadable)
run_section() {  # run_section NAME SCRIPT: SFAIL and SPASS hold its counts
  SFAIL=0
  SPASS=0
  "section_$1" "$2"
}

# Optional focused mode uses the exact same sections as the full suite.
# Usage: bash SCRIPT SOURCE --ipv6-adverse-only
if [[ "${2:-}" == --ipv6-adverse-only ]]; then
  for section in ipv6shadow ipv6unreadable; do
    run_section "${section}" "${INSTALL}"
    printf 'ADVERSE %s contract=%s pass=%s fail=%s\n' "${section}" "${OI5_IPV6_UNREADABLE_EXPECT}" "${SPASS}" "${SFAIL}"
    PASS=$((PASS + SPASS))
    FAIL=$((FAIL + SFAIL))
  done
  printf 'ADVERSE TOTAL pass=%s fail=%s\n' "${PASS}" "${FAIL}"
  [[ "${FAIL}" == 0 ]]
  exit
fi

echo "=== live installer ==="
for section in "${SECTIONS[@]}"; do
  run_section "${section}" "${INSTALL}"
  if [[ "${SFAIL}" == 0 ]]; then
    pass "${section}: ${SPASS} checks"
  else
    fail "${section}: ${SFAIL} of $((SFAIL + SPASS)) checks failed"
  fi
done

# mutant NAME SECTION FROM TO: a copy of the live installer with FROM replaced
# by TO (at least once); SECTION must go red on it.
mutant() {
  local name="$1" section="$2" copy="${WORK}/mutant-$1.sh"
  python3 - "${INSTALL}" "${copy}" "$3" "$4" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
new = src.replace(sys.argv[3], sys.argv[4])
if new == src:
    sys.exit("mutant: the text to replace was not found")
open(sys.argv[2], "w", encoding="utf-8").write(new)
PY
  echo "=== mutant ${name} (section ${section} must go red) ==="
  run_section "${section}" "${copy}" > "${WORK}/mutant.out" 2>&1 || true
  if [[ "${SFAIL}" -ge 1 ]]; then
    pass "control ${name}: section ${section} went red (fail=${SFAIL})"
  else
    fail "control ${name}: section ${section} stayed green"
  fi
}
mutant helper-unlocked lock \
  '  wins_fw_lock || {
    echo "winn3 gateway firewall: the shared firewall lock' \
  '  true || {
    echo "winn3 gateway firewall: the shared firewall lock'
mutant apply-unlocked lock \
  '  wins_fw_lock || { winn3gw_err "The shared firewall lock ${WINS_FIREWALL_LOCK} is unavailable; the forwarding firewall was not changed."; return 1; }
  local rc=0
  apply_forwarding_firewall_locked' \
  '  local rc=0
  apply_forwarding_firewall_locked'
mutant teardown-unlocked lock \
  '  wins_fw_lock || { winn3gw_err "The shared firewall lock ${WINS_FIREWALL_LOCK} is unavailable; the forwarding firewall was not changed."; return 1; }
  local rc=0
  teardown_forwarding_firewall_locked' \
  '  local rc=0
  teardown_forwarding_firewall_locked'
mutant lock-copy-drift copies \
  'flock -w "${WINS_FIREWALL_LOCK_WAIT:-60}" 7' 'flock -w "${WINS_FIREWALL_LOCK_WAIT:-30}" 7'
mutant insert-at-1 insert '"$((recovery_at + 1))"' '1'
# Implementation review T1: Sol-S2-T1-1 (adjacency) and Claude-S2-T1-1 (the
# refusal takes its own insert out).
mutant insert-anywhere-behind insert \
  'if (( ahead == 0 && first_jump_at == recovery_at + 1 )); then' 'if (( ahead == 0 && behind > 0 )); then'
mutant insert-no-replace insert \
  'if (( behind == 0 || first_jump_at != recovery_at + 1 )); then' 'if (( behind == 0 )); then'
mutant odd-form-kept insert \
  ' -D INPUT -i "${iface}" -d "${inner}" -j WINN3GW-INPUT 2>/dev/null; then' \
  ' -D INPUT -i "${iface}" -d "${inner}" -j WINN3GW-INPUT-KEPT 2>/dev/null; then'
mutant render-restarts split \
  '  systemctl enable winn3-gateway-firewall.service
}' \
  '  systemctl enable winn3-gateway-firewall.service
  systemctl restart winn3-gateway-firewall.service
}'
mutant install-activates split \
  '  if [[ "${WINN3_GATEWAY_MODE}" == "start" ]]; then
    winn3gw_activate
  fi' \
  '  winn3gw_activate'
mutant install-stale-hint split \
  'if systemctl is-active --quiet winn3-gateway-firewall.service 2>/dev/null; then' 'if false; then'
mutant etc-winn-755 etcwinn \
  'install -d -m 750 -o root -g "${WINN3_GATEWAY_SERVICE_USER}" /etc/winn' 'install -d -m 755 -o root -g root /etc/winn'
mutant backup-hostname backup 'BACKUP_HOST_ID=${RESOLVED_BACKUP_HOST_ID}' 'BACKUP_HOST_ID=gateway-$(hostname -s)'
mutant backup-runtime-fallback backup \
  'HOST_ID="${BACKUP_HOST_ID:?BACKUP_HOST_ID missing; re-run the installer}"' 'HOST_ID="${BACKUP_HOST_ID:-gateway-$(hostname -s)}"'
mutant elf-any-machine elf '[[ "${elf_arch}" == x86_64 ]]' 'true'
mutant elf-any-encoding elf '"${data}" == 01 && ' ''
mutant order-no-netfilter order ' netfilter-persistent.service wins-node-local-serving.service' ''
mutant order-no-tmpfiles order ' systemd-tmpfiles-setup.service
Before=winn3-gateway.service' '
Before=winn3-gateway.service'
mutant order-no-lock-path order 'ReadWritePaths=/run/lock /run/xtables.lock
' 'ReadWritePaths=/run/xtables.lock
'
mutant order-no-xtables-path order 'ReadWritePaths=/run/lock /run/xtables.lock
' 'ReadWritePaths=/run/lock
'
mutant xtables-not-prepared xtables '  prepare_wins_xtables_lock \
    || winn3gw_die "Could not prepare /run/xtables.lock for the gateway firewall helper; the helper was not rendered."
' ''
mutant xtables-truncating xtables 'f /run/xtables.lock 0600 root root -' 'F /run/xtables.lock 0600 root root -'
mutant xtables-any-owner xtables "[[ \"\$(stat -c '%u' /run/xtables.lock)\" == \"0\" ]] || {" 'true || {'
# OI-5 controls: each isolation rule, its order, the tunnel INPUT drop in
# both builders, the IPv6 drops and the teardown of each must be load-bearing.
mutant isolation-installer-no-pool-drop isolation \
  '    "-s ${cidr} -d ${cidr}"
' ''
mutant isolation-helper-no-pool-drop isolation \
  '  iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -d "${cidr}" -j DROP
' ''
mutant isolation-helper-no-private-drops isolation \
  '    iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -d "${private}" -j DROP
' ''
mutant isolation-installer-drops-behind-accept isolation \
  '  for isolation_rule in "${isolation_rules[@]}"; do
    read -r -a isolation_words <<<"${isolation_rule}"
    ipt_gw -A WINN3GW-FORWARD "${isolation_words[@]}" -j DROP \
      || { winn3gw_err "WINN3GW-FORWARD isolation drop (${isolation_rule}) failed"; return 1; }
  done
  ipt_gw -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
    || { winn3gw_err "WINN3GW-FORWARD conntrack-accept rule failed"; return 1; }
  ipt_gw -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT \
    || { winn3gw_err "WINN3GW-FORWARD egress-accept rule failed"; return 1; }
' \
  '  ipt_gw -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
    || { winn3gw_err "WINN3GW-FORWARD conntrack-accept rule failed"; return 1; }
  ipt_gw -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT \
    || { winn3gw_err "WINN3GW-FORWARD egress-accept rule failed"; return 1; }
  for isolation_rule in "${isolation_rules[@]}"; do
    read -r -a isolation_words <<<"${isolation_rule}"
    ipt_gw -A WINN3GW-FORWARD "${isolation_words[@]}" -j DROP \
      || { winn3gw_err "WINN3GW-FORWARD isolation drop (${isolation_rule}) failed"; return 1; }
  done
'
mutant isolation-helper-drops-behind-accept isolation \
  '  iptables -w 10 -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT
  iptables -w 10 -A WINN3GW-FORWARD -j DROP
' \
  '  iptables -w 10 -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT
  iptables -w 10 -A WINN3GW-FORWARD -i "${iface}" -o "${iface}" -j DROP
  iptables -w 10 -A WINN3GW-FORWARD -j DROP
'
mutant isolation-helper-no-input-drop insert \
  '        iptables -w 10 -I INPUT "$((first_jump_at + 1))" -i "${iface}" -j DROP || return 1
' '        true
'
mutant isolation-installer-no-input-drop insert \
  '        ipt_gw -I INPUT "$((first_jump_at + 1))" -i "${iface}" -j DROP || return 1
' '        true
'
mutant isolation-installer-input-drop-at-1 insert \
  '        ipt_gw -I INPUT "$((first_jump_at + 1))" -i "${iface}" -j DROP || return 1
' '        ipt_gw -I INPUT 1 -i "${iface}" -j DROP || return 1
'
mutant isolation-installer-no-v6-forward-o isolation \
  '    ipt6_gw -I FORWARD 1 -o "${iface}" -j DROP \
' '    : \
'
mutant isolation-helper-no-v6-input isolation \
  '    ip6tables -w 10 -I INPUT 1 -i "${iface}" -j DROP
' ''
mutant isolation-teardown-keeps-input-drop isolation \
  '  while ipt_gw -D INPUT -i "${WINN3_GATEWAY_FORWARD_IF}" -j DROP 2>/dev/null; do :; done
' ''
mutant isolation-teardown-keeps-v6 isolation \
  '    while ipt6_gw -D INPUT -i "${WINN3_GATEWAY_FORWARD_IF}" -j DROP 2>/dev/null; do :; done
' ''

echo
echo "SUMMARY pass=${PASS} fail=${FAIL}"
[[ "${FAIL}" == 0 ]]
