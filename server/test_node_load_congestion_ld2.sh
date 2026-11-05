#!/usr/bin/env bash
# Round LD2 (lane L102): exercise the load-input block of wins-node-register.
#
# Usage: bash test_node_load_congestion_ld2.sh [installer-or-register-script]
#   default: wins_data_plane_setup_ONETOUCH.sh next to this file (the register
#   script is extracted from its heredoc). Linux only (needs /proc, stat -c).
#
# The block runs exactly as extracted, under the script's own
# `set -Eeuo pipefail`. docker is a shell function; systemctl and journalctl are
# stub executables on PATH (the block calls them as external commands). What it
# proves:
#   * active users are counted across ALL transports (AWG handshakes in 180 s,
#     which include Xray stealth users, minus Double VPN core-to-exit system
#     peers in 10.8.255.0/24, plus winn3-gateway sessions that are CARRYING);
#   * user capacity is a planning policy derived from the CPU count
#     (90 x min(vCPUs, 3)), capped by max_peers, replaceable by
#     NODE_SESSION_CAPACITY, and floored at 40 LAST, whatever the cap says;
#   * a REFLECTOR gateway unit (no -forward, no -peer-registry) is a known zero:
#     it accepts every client key, so `carrying` there is forgeable;
#   * the v3 slot term is carrying / max(-max-sessions, 40): the `sessions`
#     census (forgeable by anyone holding the admission key, and reclaimable by
#     the gateway) is never read; an unreadable -max-sessions on a running
#     gateway makes the figure unknown; the figure is unknown unless both the
#     users term and the slot term are known;
#   * the users figure is computable with no WAN capacity configured;
#   * every failure of a sampler is null, never a counted zero, and the
#     heartbeat never aborts.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${1:-${here}/wins_data_plane_setup_ONETOUCH.sh}"
work="$(mktemp -d /tmp/ld2-node-XXXXXX)"
trap 'rm -rf "${work}"' EXIT
script="${work}/wins-node-register"
if grep -q "^  cat > /usr/local/bin/wins-node-register <<'EOF'" "${target}"; then
  awk "/^  cat > \\/usr\\/local\\/bin\\/wins-node-register <<'EOF'/{on=1; next} on && /^EOF\$/{exit} on" "${target}" > "${script}"
else
  cp "${target}" "${script}"
fi
block="${work}/block.sh"
awk '/^# Load inputs for the per-server load bar/{on=1} /^# Data-plane code provenance, recomputed/{on=0} on' "${script}" > "${block}"
[[ -s "${block}" ]] || { echo "FAIL extract: load block not found in ${target}"; exit 1; }
fails=0
passes=0
echo "input sha256: installer=$(sha256sum "${target}" | cut -c1-16) test=$(sha256sum "${BASH_SOURCE[0]}" | cut -c1-16) block=$(sha256sum "${block}" | cut -c1-16)"

stub="${work}/stubbin"
mkdir -p "${stub}"
cat > "${stub}/systemctl" <<'STUB'
#!/bin/bash
case "$1" in
  is-active)
    case "${STUB_V3:-none}" in
      active) echo active ;;
      inactive) echo inactive; exit 3 ;;
      failed) echo failed; exit 3 ;;
      activating) echo activating; exit 3 ;;
      *) exit 1 ;;
    esac ;;
  show)
    max="${STUB_V3_MAX:+ -max-sessions ${STUB_V3_MAX}}"
    # systemd's real format: argv joined with single spaces, then " ; ignore_errors=..." and the timestamps
    head="ExecStart={ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve -plan udp${max}"
    tail=" ; ignore_errors=no ; start_time=[Mon 2026-09-28 10:00:00 UTC] ; stop_time=[n/a] ; pid=1234 ; code=(null) ; status=0/0 }"
    case "${STUB_V3_EXEC:-forward}" in
      empty) exit 0 ;;
      reflector) echo "${head} -status-json /run/winn3-gateway/status.json${tail}" ;;
      forwardif) echo "${head} -forward-if winn3gw0 -forward-cidr 10.10.0.0/24${tail}" ;;
      forward-last) echo "${head} -peer-registry /var/lib/winn3/peers.json -forward${tail}" ;;
      forward-eq) echo "${head} -forward=true -peer-registry /var/lib/winn3/peers.json${tail}" ;;
      forward-semi) echo "${head} -peer-registry /var/lib/winn3/peers.json -forward; ignore_errors=no }" ;;
      forward-eol) echo "${head} -peer-registry /var/lib/winn3/peers.json -forward" ;;
      *) echo "${head} -forward -accept-transit=true -forward-if winn3gw0 -forward-cidr 10.10.0.0/24 -peer-registry /var/lib/winn3/peers.json${tail}" ;;
    esac
    exit 0 ;;
esac
STUB
cat > "${stub}/journalctl" <<'STUB'
#!/bin/bash
status_line() {
  printf '{"event":"posture","ready":true,"replay_journal_status":"ok","sessions_built":99,"x_carrying":99,"sessions":%s,"admitted":4,"carrying":%s,"promoted":0,"carriage_proven":false,"session_states":["carrying"]}\n' "$1" "$2"
}
case "${STUB_JOURNAL:-line}" in
  line) status_line "${STUB_V3_SESSIONS:-0}" "${STUB_V3_CARRYING:-0}" ;;
  trailing-noise) status_line "${STUB_V3_SESSIONS:-0}" "${STUB_V3_CARRYING:-0}"; echo "winn3-gateway: replay-journal status=ok" ;;
  older-then-newer) status_line 60 60; status_line "${STUB_V3_SESSIONS:-0}" "${STUB_V3_CARRYING:-0}" ;;
  none) : ;;
  garbage) echo "winn3-gateway: something odd"; echo '{"foo":1}' ;;
  no-carrying) echo '{"event":"posture","ready":true,"sessions":3}' ;;
  huge) echo '{"event":"posture","sessions":12345678,"carrying":12345678}' ;;
  fail) exit 1 ;;
esac
STUB
cat > "${stub}/grep" <<'STUB'
#!/bin/bash
# STUB_GREP_FAIL=<rc>: the -forward test's grep fails with that status (2 = error, 127 = missing binary).
if [[ -n "${STUB_GREP_FAIL:-}" && "$*" == *"-forward"* ]]; then cat >/dev/null; exit "${STUB_GREP_FAIL}"; fi
exec /usr/bin/grep "$@"
STUB
chmod +x "${stub}/systemctl" "${stub}/journalctl" "${stub}/grep"

run_case() {
  # $1 name; remaining args: env assignments. Prints "cpu=.. net=.. sess=.." and rc.
  local name="$1"; shift
  env -i PATH="${stub}:/usr/bin:/bin" HOME="${work}" "$@" bash -c '
    set -Eeuo pipefail
    docker() {
      local now i; now=$(command date +%s)
      case "${STUB_DOCKER:-}" in
        peers|edge|no-hsend|bad-allowed|malformed)
          local recent="${STUB_AWG_RECENT:-0}" sys="${STUB_AWG_SYS:-0}" mixed="${STUB_AWG_MIXED:-0}"
          if [[ "${STUB_DOCKER}" == edge ]]; then
            printf "a\t%s\nb\t%s\nc\t%s\n" "$((now - 179))" "$((now - 185))" "$((now - 5))"
          else
            for ((i = 0; i < recent; i++)); do printf "r%s\t%s\n" "$i" "$((now - 5 - i % 100))"; done
            for ((i = 0; i < ${STUB_AWG_OLD:-0}; i++)); do printf "o%s\t%s\n" "$i" "$((now - 400 - i))"; done
            printf "never\t0\n"
          fi
          [[ "${STUB_DOCKER}" == malformed ]] && printf "warning: something odd\n"
          [[ "${STUB_DOCKER}" == no-hsend ]] || echo __wins_awg_hs_end__
          if [[ "${STUB_DOCKER}" == edge ]]; then
            printf "a\t10.8.1.2/32\nb\t10.8.1.3/32\nc\t10.8.1.4/32\n"
          else
            for ((i = 0; i < recent; i++)); do
              if ((i < sys)); then printf "r%s\t10.8.255.%s/32\n" "$i" "$((i + 2))"
              elif ((i < sys + mixed)); then printf "r%s\t10.8.255.%s/32 10.8.1.%s/32\n" "$i" "$((i + 2))" "$((i % 200 + 2))"
              else printf "r%s\t10.8.1.%s/32\n" "$i" "$((i % 200 + 2))"; fi
            done
            for ((i = 0; i < ${STUB_AWG_OLD:-0}; i++)); do printf "o%s\t(none)\n" "$i"; done
            printf "never\t(none)\n"
          fi
          [[ "${STUB_DOCKER}" == bad-allowed ]] && printf "r0\n"
          echo __wins_awg_ok__ ;;
        zero) echo __wins_awg_hs_end__; echo __wins_awg_ok__ ;;
        no-marker) printf "r\t%s\n" "$((now - 5))"; echo __wins_awg_hs_end__; printf "r\t10.8.1.2/32\n" ;;
        no-phase2) printf "r\t%s\n" "$((now - 5))"; echo __wins_awg_ok__ ;;
        fail) return 1 ;;
        fail-after-output) printf "k1\t%s\n" "$((now - 5))"; return 125 ;;
        empty) return 0 ;;
      esac
    }
    if [[ "${STUB_DATE:-}" == "fail" ]]; then date() { return 1; }; fi
    if [[ -n "${STUB_PYTHON:-}" ]]; then python3() { cat >/dev/null; printf "%s\n" "${STUB_PYTHON}"; }; fi
    active_awg_container="${ACTIVE-amnezia-awg2}"
    wan_iface="${WAN:-eth0}"
    cores="${CORES-}"
    source "'"${block}"'"
    printf "cpu=%s net=%s sess=%s\n" "${load_cpu_pct}" "${load_net_pct}" "${load_sessions_pct}"
  ' 2>&1
  echo "rc=$?"
}

check() {
  local name="$1" out="$2" pattern="$3"
  if grep -Eq -e "${pattern}" <<<"${out}"; then
    echo "PASS ${name}: $(tr '\n' ' ' <<<"${out}")"
    passes=$((passes + 1))
  else
    echo "FAIL ${name}: expected /${pattern}/ got: $(tr '\n' ' ' <<<"${out}")"
    fails=$((fails + 1))
  fi
}

NUM='[0-9]{1,3}\.[0-9]{3}'
state="${work}/state/node-load.state"
base=(NODE_LOAD_STATE="${state}" STUB_DOCKER=peers STUB_V3=inactive)

# CPU sampler and state file (unchanged behaviour), no capacity configured.
out="$(run_case first "${base[@]}" CORES=6 STUB_AWG_RECENT=27)"
check "first run: cpu numeric, no WAN capacity, users computed (27 of 270 = 10 %)" "${out}" "^cpu=${NUM} net=null sess=10\.000$"
check "first run exit 0" "${out}" "^rc=0$"
mode="$(stat -c %a "${state}" 2>/dev/null || echo missing)"
if [[ "${mode}" == "600" ]]; then echo "PASS state file mode 600"; passes=$((passes + 1)); else echo "FAIL state file mode ${mode}"; fails=$((fails + 1)); fi
sleep 6
out="$(run_case second "${base[@]}" CORES=6 STUB_AWG_RECENT=27 NODE_LINK_CAPACITY_MBPS=1000)"
check "with a link capacity the WAN term appears too" "${out}" "^cpu=${NUM} net=${NUM} sess=10\.000$"

# Capacity arithmetic: 90 x min(vCPUs, 3).
for spec in "1:9:10" "2:18:10" "3:27:10" "4:27:10" "6:27:10" "64:27:10" "6:135:50" "6:270:100" "6:400:100" "6:0:0"; do
  IFS=: read -r c users want <<<"${spec}"
  out="$(run_case "cap-${spec}" "${base[@]}" CORES="${c}" STUB_AWG_RECENT="${users}")"
  check "capacity: ${c} vCPU, ${users} users -> ${want} %" "${out}" "sess=${want}\.000$"
done
out="$(run_case cores-unset "${base[@]}" STUB_AWG_RECENT=9)"
check "vCPU count unknown: treated as 1 vCPU (capacity 90), 9 users = 10 %" "${out}" "sess=10\.000$"
out="$(run_case cores-junk "${base[@]}" CORES=lots STUB_AWG_RECENT=9)"
check "vCPU count junk: treated as 1 vCPU" "${out}" "sess=10\.000$"

# Overrides, floor and max_peers cap.
out="$(run_case override-big "${base[@]}" CORES=6 NODE_SESSION_CAPACITY=1000 STUB_AWG_RECENT=100)"
check "NODE_SESSION_CAPACITY=1000 replaces the derived 270: 100 users = 10 %" "${out}" "sess=10\.000$"
out="$(run_case override-small "${base[@]}" CORES=6 NODE_SESSION_CAPACITY=10 STUB_AWG_RECENT=20)"
check "override below the floor is raised to 40: 20 users = 50 %" "${out}" "sess=50\.000$"
out="$(run_case override-junk "${base[@]}" CORES=6 NODE_SESSION_CAPACITY=abc STUB_AWG_RECENT=27)"
check "junk override ignored, derived 270 used" "${out}" "sess=10\.000$"
out="$(run_case override-zero "${base[@]}" CORES=6 NODE_SESSION_CAPACITY=0 STUB_AWG_RECENT=27)"
check "zero override ignored, derived 270 used" "${out}" "sess=10\.000$"
out="$(run_case maxpeers-cap "${base[@]}" CORES=6 NODE_MAX_PEERS=100 STUB_AWG_RECENT=25)"
check "max_peers 100 caps capacity 270 to 100: 25 users = 25 %" "${out}" "sess=25\.000$"
out="$(run_case maxpeers-below-floor "${base[@]}" CORES=6 NODE_MAX_PEERS=20 STUB_AWG_RECENT=10)"
check "max_peers 20 cannot push capacity below the floor of 40 (floor applied last): 10 users = 25 %" "${out}" "sess=25\.000$"
out="$(run_case maxpeers-tiny "${base[@]}" CORES=6 NODE_MAX_PEERS=2 STUB_AWG_RECENT=1)"
check "max_peers 2: one person is 2.5 % (capacity 40), not an exact head count" "${out}" "sess=2\.500$"
out="$(run_case maxpeers-tiny-full "${base[@]}" CORES=6 NODE_MAX_PEERS=1 STUB_AWG_RECENT=2)"
check "max_peers 1: two people are 5 %, not full" "${out}" "sess=5\.000$"
out="$(run_case maxpeers-large "${base[@]}" CORES=6 NODE_MAX_PEERS=43632 STUB_AWG_RECENT=27)"
check "a large max_peers changes nothing" "${out}" "sess=10\.000$"
out="$(run_case maxpeers-junk "${base[@]}" CORES=6 NODE_MAX_PEERS=x STUB_AWG_RECENT=27)"
check "junk max_peers ignored" "${out}" "sess=10\.000$"

# Handshake window: 179 s counts, 180 s counts, 181 s does not; old and never-connected peers do not.
out="$(run_case window "${base[@]}" CORES=6 NODE_SESSION_CAPACITY=40 STUB_DOCKER=edge)"
check "handshake window: 179 s and 5 s count, 185 s does not (2 of 40 = 5 %)" "${out}" "sess=5\.000$"
out="$(run_case stale-peers "${base[@]}" CORES=6 STUB_AWG_RECENT=5 STUB_AWG_OLD=200)"
check "peers with old or zero handshakes are not active users" "${out}" "sess=1\.852$"

# All transports: v3 carrying sessions add to AWG users; stealth users are AWG peers.
out="$(run_case v3-adds "${base[@]}" CORES=2 STUB_AWG_RECENT=10 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=8 STUB_V3_CARRYING=8 STUB_V3_MAX=1000)"
check "10 AWG (stealth included) + 8 v3 carrying = 18 users of 180 = 10 %" "${out}" "sess=10\.000$"
out="$(run_case v3-only "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "v3 users alone count" "${out}" "sess=10\.000$"
out="$(run_case v3-census-not-users "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=50 STUB_V3_CARRYING=0 STUB_V3_MAX=64)"
check "v3 sessions that are not carrying (50 of 64 slots in the census) are not users and not slots: 0 %" "${out}" "sess=0\.000$"
out="$(run_case v3-sessions-key "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=7 STUB_V3_CARRYING=7 STUB_V3_MAX=1000)"
check "the decoy key x_carrying (99) is not read as carrying: 7 of 180 users = 3.889 %" "${out}" "sess=3\.889$"
out="$(run_case v3-trailing-noise "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=trailing-noise STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "a non-JSON journal line after the status line is skipped" "${out}" "sess=10\.000$"
out="$(run_case v3-newest-line "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=older-then-newer STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "the newest status line wins" "${out}" "sess=10\.000$"

# Double VPN core-to-exit system peers (allowed-ips inside 10.8.255.0/24) are not users.
out="$(run_case sys-peers "${base[@]}" CORES=6 STUB_AWG_RECENT=10 STUB_AWG_SYS=3)"
check "3 of 10 recent peers are core-to-exit links: 7 users of 270 = 2.593 %" "${out}" "sess=2\.593$"
out="$(run_case sys-mixed "${base[@]}" CORES=6 STUB_AWG_RECENT=10 STUB_AWG_SYS=3 STUB_AWG_MIXED=2)"
check "2 peers holding a reserved AND a customer address still count: 3 excluded, 7 users of 270 = 2.593 %" "${out}" "sess=2\.593$"
out="$(run_case sys-all "${base[@]}" CORES=6 STUB_AWG_RECENT=4 STUB_AWG_SYS=4)"
check "only system peers: zero users" "${out}" "sess=0\.000$"
out="$(run_case no-hsend "${base[@]}" CORES=6 STUB_AWG_RECENT=4 STUB_DOCKER=no-hsend)"
check "phase marker missing: unknown" "${out}" "sess=null$"
out="$(run_case no-phase2 "${base[@]}" CORES=6 STUB_DOCKER=no-phase2)"
check "handshake lines and the success marker but no allowed-ips section: unknown" "${out}" "sess=null$"
out="$(run_case bad-allowed "${base[@]}" CORES=6 STUB_AWG_RECENT=4 STUB_DOCKER=bad-allowed)"
check "allowed-ips line without addresses: unknown" "${out}" "sess=null$"

# v3 slot term: CARRYING sessions against the gateway's own ceiling, never below 40.
out="$(run_case v3-slots "${base[@]}" CORES=6 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=48 STUB_V3_CARRYING=48 STUB_V3_MAX=64)"
check "48 carrying of 64 slots = 75 % although 48 users are only 17.8 % of 270" "${out}" "sess=75\.000$"
out="$(run_case v3-forged-slots "${base[@]}" CORES=6 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=64 STUB_V3_CARRYING=2 STUB_V3_MAX=64)"
check "forged initiations fill all 64 slots (sessions 64, carrying 2): 3.125 %, not full" "${out}" "sess=3\.125$"
out="$(run_case v3-slots-low "${base[@]}" CORES=6 STUB_AWG_RECENT=100 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=2 STUB_V3_CARRYING=2 STUB_V3_MAX=64)"
check "slots below the users figure do not lower it (102 of 270 = 37.778 %)" "${out}" "sess=37\.778$"
out="$(run_case v3-max-tiny "${base[@]}" CORES=6 STUB_AWG_RECENT=0 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=4 STUB_V3_CARRYING=4 STUB_V3_MAX=8)"
check "-max-sessions 8 is floored to 40: 4 carrying = 10 %, not 50 %" "${out}" "sess=10\.000$"
out="$(run_case v3-max-junk "${base[@]}" CORES=6 STUB_AWG_RECENT=9 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=2 STUB_V3_CARRYING=2 STUB_V3_MAX=lots)"
check "unreadable -max-sessions on a running gateway: unknown, term never silently dropped" "${out}" "sess=null$"
out="$(run_case v3-max-absent "${base[@]}" CORES=6 STUB_AWG_RECENT=9 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=2 STUB_V3_CARRYING=2)"
check "-max-sessions absent from the unit: unknown" "${out}" "sess=null$"
out="$(run_case v3-max-zero "${base[@]}" CORES=6 STUB_AWG_RECENT=9 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=2 STUB_V3_CARRYING=2 STUB_V3_MAX=0)"
check "-max-sessions 0: unknown" "${out}" "sess=null$"
out="$(run_case v3-stopped-max-absent "${base[@]}" CORES=6 STUB_AWG_RECENT=9 STUB_V3=inactive)"
check "stopped gateway needs no -max-sessions: 9 of 270 = 3.333 %" "${out}" "sess=3\.333$"

# Reflector units (no -forward, hence no -peer-registry) accept every client key
# and forward nothing: anyone with the admission key can make `carrying` grow, and
# there are no real users. Known zero, whatever the journal says.
out="$(run_case v3-reflector "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_V3_EXEC=reflector STUB_JOURNAL=line STUB_V3_SESSIONS=64 STUB_V3_CARRYING=64 STUB_V3_MAX=64)"
check "reflector unit with 64 forged carrying sessions: v3 counts zero, AWG 9 of 90 = 10 %" "${out}" "sess=10\.000$"
out="$(run_case v3-reflector-nojournal "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_V3_EXEC=reflector STUB_JOURNAL=none)"
check "reflector unit needs no status line and no -max-sessions: known zero" "${out}" "sess=10\.000$"
out="$(run_case v3-forwardif-only "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_V3_EXEC=forwardif STUB_JOURNAL=line STUB_V3_SESSIONS=64 STUB_V3_CARRYING=64 STUB_V3_MAX=64)"
check "-forward-if and -forward-cidr alone do not make a forwarding unit" "${out}" "sess=10\.000$"
out="$(run_case v3-forward-last "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_V3_EXEC=forward-last STUB_JOURNAL=line STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "-forward as the last argument before the unit text ends counts as forwarding" "${out}" "sess=10\.000$"
out="$(run_case v3-forward-eq "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_V3_EXEC=forward-eq STUB_JOURNAL=line STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "-forward=true counts as forwarding" "${out}" "sess=10\.000$"
out="$(run_case v3-forward-semi "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_V3_EXEC=forward-semi STUB_JOURNAL=line STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "-forward directly followed by ; still counts (the ; alternative, defensive)" "${out}" "sess=10\.000$"
out="$(run_case v3-forward-eol "${base[@]}" CORES=2 STUB_AWG_RECENT=0 STUB_V3=active STUB_V3_EXEC=forward-eol STUB_JOURNAL=line STUB_V3_SESSIONS=18 STUB_V3_CARRYING=18 STUB_V3_MAX=1000)"
check "-forward as the very last characters of the unit text still counts (the \$ alternative, defensive)" "${out}" "sess=10\.000$"
for rc in 2 127; do
  out="$(run_case "v3-grep-fails-${rc}" "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=64 STUB_V3_CARRYING=64 STUB_V3_MAX=64 STUB_GREP_FAIL="${rc}")"
  check "a forwarding unit whose grep fails with status ${rc}: unknown, not a reflector zero" "${out}" "sess=null$"
  check "grep failure ${rc} does not abort the heartbeat" "${out}" "^rc=0$"
done
out="$(run_case v3-grep-fails-reflector "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_V3_EXEC=reflector STUB_V3_MAX=64 STUB_GREP_FAIL=2)"
check "a reflector unit whose grep fails: still unknown (the failure is not read as no match)" "${out}" "sess=null$"
out="$(run_case v3-exec-unreadable "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_V3_EXEC=empty STUB_JOURNAL=line STUB_V3_SESSIONS=2 STUB_V3_CARRYING=2 STUB_V3_MAX=64)"
check "running gateway whose unit text cannot be read: unknown, not a reflector zero" "${out}" "sess=null$"

# v3 gateway not running: known zero. Running without a status line: unknown.
for st in inactive failed; do
  out="$(run_case "v3-${st}" "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3="${st}")"
  check "v3 gateway ${st}: carries nobody, AWG users still count (9 of 90 = 10 %)" "${out}" "sess=10\.000$"
done
out="$(run_case v3-absent-unit "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=none)"
check "no systemd answer at all: unknown, not zero" "${out}" "sess=null$"
out="$(run_case v3-activating "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=activating)"
check "v3 activating: unknown, not zero" "${out}" "sess=null$"
for j in none garbage no-carrying huge fail; do
  out="$(run_case "v3-journal-${j}" "${base[@]}" CORES=1 STUB_AWG_RECENT=9 STUB_V3=active STUB_V3_MAX=64 STUB_JOURNAL="${j}")"
  check "v3 active but journal '${j}': unknown, never a counted zero" "${out}" "sess=null$"
  check "v3 journal '${j}' does not abort the heartbeat" "${out}" "^rc=0$"
done

# AWG failures are unknown too (the OI-9 rule), whatever v3 says.
out="$(run_case no-container "${base[@]}" CORES=6 ACTIVE= STUB_V3=inactive)"
check "no AWG container: unknown" "${out}" "sess=null$"
out="$(run_case docker-fails "${base[@]}" CORES=6 STUB_DOCKER=fail STUB_V3=inactive)"
check "docker exec fails with no output: unknown (was a counted 0)" "${out}" "sess=null$"
check "docker exec failure does not abort heartbeat" "${out}" "^rc=0$"
check "unknown users leave the CPU figure intact (independent failure)" "${out}" "^cpu=${NUM} net=null sess=null$"
out="$(run_case docker-fails-after-output "${base[@]}" CORES=6 STUB_DOCKER=fail-after-output STUB_V3=inactive)"
check "docker exec prints then fails: unknown" "${out}" "sess=null$"
out="$(run_case zero-peers "${base[@]}" CORES=6 STUB_DOCKER=zero STUB_V3=inactive)"
check "no peers at all, awg exited 0 (marker only): a real zero, not unknown" "${out}" "sess=0\.000$"
out="$(run_case no-marker "${base[@]}" CORES=6 STUB_DOCKER=no-marker STUB_V3=inactive)"
check "handshake lines without the awg-success marker: unknown" "${out}" "sess=null$"
out="$(run_case docker-empty "${base[@]}" CORES=6 STUB_DOCKER=empty STUB_V3=inactive)"
check "docker exec succeeds with empty output: unknown" "${out}" "sess=null$"
out="$(run_case docker-malformed "${base[@]}" CORES=6 STUB_DOCKER=malformed STUB_V3=inactive)"
check "one malformed handshake line: unknown, not a partial count" "${out}" "sess=null$"
out="$(run_case date-fails "${base[@]}" CORES=6 STUB_AWG_RECENT=5 STUB_DATE=fail STUB_V3=inactive)"
check "date fails: unknown (an empty now would count every peer)" "${out}" "sess=null$"
check "date failure does not abort heartbeat" "${out}" "^rc=0$"
out="$(run_case awg-unknown-v3-known "${base[@]}" CORES=6 STUB_DOCKER=fail STUB_V3=active STUB_JOURNAL=line STUB_V3_SESSIONS=64 STUB_V3_CARRYING=64 STUB_V3_MAX=64)"
check "AWG unknown while the v3 slot term reads full (64 of 64): published as unknown, not full" "${out}" "sess=null$"
out="$(run_case awg-known-v3-unknown "${base[@]}" CORES=6 STUB_AWG_RECENT=200 STUB_V3=active STUB_JOURNAL=none STUB_V3_MAX=64)"
check "v3 term unknown while AWG reads 74 %: unknown" "${out}" "sess=null$"

# Sampler-level failures.
out="$(run_case bad-iface "${base[@]}" WAN=doesnotexist0 STUB_V3=inactive)"
check "sampler exception reports all null" "${out}" "^cpu=null net=null sess=null$"
check "sampler exception does not abort heartbeat" "${out}" "^rc=0$"
out="$(run_case garbage NODE_LOAD_STATE="${state}" STUB_PYTHON='1e9 abc -5')"
check "non-numeric sampler output is narrowed to null" "${out}" "^cpu=null net=null sess=null$"
out="$(run_case over NODE_LOAD_STATE="${state}" STUB_PYTHON='1000.000 100.000 7')"
check "4-digit value rejected, 100.000 and integer kept" "${out}" "^cpu=null net=100\.000 sess=7$"
printf 'not json' > "${state}"
out="$(run_case corrupt "${base[@]}" CORES=6 STUB_AWG_RECENT=27 STUB_V3=inactive)"
check "corrupt state treated as no prior; users unaffected" "${out}" "^cpu=${NUM} net=null sess=10\.000$"
out="$(env -i PATH="/nonexistent" HOME="${work}" /usr/bin/bash -c '
  set -Eeuo pipefail
  active_awg_container=""; wan_iface=eth0; cores=6
  source "'"${block}"'"
  printf "cpu=%s net=%s sess=%s\n" "${load_cpu_pct}" "${load_net_pct}" "${load_sessions_pct}"' 2>&1; echo "rc=$?")"
check "python3 absent: all null" "${out}" "^cpu=null net=null sess=null$"
check "python3 absent: exit 0" "${out}" "^rc=0$"

# Static pins on the block itself.
code="$(grep -v '^[[:space:]]*#' "${block}")"
if ! grep -q -i 'xray\|10085\|ss -' <<<"${code}"; then
  echo "PASS static: no Xray connection counting (stealth users are AWG peers; counting both would double count)"; passes=$((passes + 1))
else
  echo "FAIL static: the block reads Xray state"; fails=$((fails + 1))
fi

if grep -q "awg show awg0 latest-handshakes && echo __wins_awg_hs_end__ && awg show awg0 allowed-ips && echo __wins_awg_ok__" <<<"${code}"; then
  echo "PASS static: the real docker command requests both phase markers and the success marker (the stub cannot see them)"; passes=$((passes + 1))
else
  echo "FAIL static: the docker command no longer echoes the marker lines"; fails=$((fails + 1))
fi
if ! grep -q '"sessions"' <<<"${code}"; then
  echo "PASS static: the forgeable v3 sessions census is never read"; passes=$((passes + 1))
else
  echo "FAIL static: the block reads the sessions census"; fails=$((fails + 1))
fi
if grep -q -- 'max(v3_max, SLOT_FLOOR)' <<<"${code}" && grep -q 'return max(capacity, CAPACITY_FLOOR)' <<<"${code}"; then
  echo "PASS static: both floors are the last operation"; passes=$((passes + 1))
else
  echo "FAIL static: a floor is no longer applied last"; fails=$((fails + 1))
fi

if [[ -f "${target}" ]] && grep -q "wins-node-register.timer <<'EOF'" "${target}"; then
  timer="$(awk "/wins-node-register.timer <<'EOF'/{on=1; next} on && /^EOF\$/{exit} on" "${target}")"
  if grep -q '^OnUnitActiveSec=120s$' <<<"${timer}" && grep -q '^AccuracySec=1s$' <<<"${timer}"; then
    echo "PASS static: the register timer is 120 s with AccuracySec=1s (one unknown report spans at most about 250 s)"; passes=$((passes + 1))
  else
    echo "FAIL static: the register timer lost OnUnitActiveSec=120s or AccuracySec=1s"; fails=$((fails + 1))
  fi
fi
if grep -F -q -- '[[:space:]]-forward(=true|=1)?([[:space:]]|;|$)' <<<"${code}"; then
  echo "PASS static: the forwarding test anchors -forward as its own word"; passes=$((passes + 1))
else
  echo "FAIL static: the -forward test changed"; fails=$((fails + 1))
fi

if grep -F -q -- 'case "${v3_fwd_rc}" in' <<<"${code}" && ! grep -F -q -- 'elif ! grep' <<<"${code}"; then
  echo "PASS static: the forwarding test branches on grep's exit status (0 forward, 1 reflector, else unknown)"; passes=$((passes + 1))
else
  echo "FAIL static: the forwarding test is not a three-way branch on grep's status"; fails=$((fails + 1))
fi

echo "passes=${passes} fails=${fails}"
exit $(( fails > 0 ))
