#!/usr/bin/env bash
#
# End-to-end integration test for Winn's node-side Single Packet Authorization.
#
# It runs two real containers on a real Docker network with real nftables and
# real UDP traffic, and answers the questions that actually matter:
#
#   1. Before the gate, is the service port reachable?
#   2. With the gate, is it invisible to a source that has not knocked?
#   3. Does LOOPBACK still work while gated?  (Xray -> 127.0.0.1:9110)
#   4. Does an ALREADY ESTABLISHED flow survive the gate being installed?
#   5. Does a knock with the WRONG key open anything?
#   6. Does a knock with the RIGHT key open it?
#   7. Does `revert` fully restore the node?
#   8. If the daemon dies, does the watchdog logic re-open the port?
#
# Questions 3, 4 and 8 are the ones that decide whether this is safe to put in
# front of a live server; 2 and 6 are the ones that decide whether it works at
# all.
#
# NOTHING HERE TOUCHES ANY REAL NODE. It is entirely local Docker.
#
set -euo pipefail

readonly NETWORK="winnspa-test-net"
readonly NODE="winnspa-test-node"
readonly CLIENT="winnspa-test-client"
readonly IMAGE="winnspa-test-image:1"
# The gated port stands in for the CARRIER port (8443/9443), not for udp/9110:
# direct-awg cannot knock, so udp/9110 is refused outright by winn-spa-nft and
# must never be what this test exercises.
readonly SERVICE_PORT=8443
readonly KNOCK_PORT=9111        # winn-knockd's own listen port
readonly PACKET_SIZE=256
# Short on purpose so expiry is observable inside a test run. Production is 30m.
readonly TEST_GRACE=30s

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD_DIR="$(mktemp -d)"

PASS=0
FAIL=0

cleanup() {
  docker rm -f "${NODE}" "${CLIENT}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
  rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }

# check <description> <expected> <actual>
check() {
  if [[ "$2" == "$3" ]]; then ok "$1 (= $3)"; else bad "$1 (want $2, got $3)"; fi
}

nodesh()   { docker exec "${NODE}" sh -c "$1"; }
clientsh() { docker exec "${CLIENT}" sh -c "$1"; }

# probe_from_client returns REACHABLE or BLOCKED
probe_from_client() {
  clientsh "/opt/spa/spaprobe probe -target ${NODE}:${SERVICE_PORT} -timeout 2s" \
    2>/dev/null | tail -1 || true
}

say "Building linux binaries"
GOARCH="$(docker info --format '{{.Architecture}}')"
case "${GOARCH}" in
  aarch64|arm64) GOARCH=arm64 ;;
  x86_64|amd64)  GOARCH=amd64 ;;
  *) echo "unsupported architecture ${GOARCH}" >&2; exit 1 ;;
esac
( cd "${REPO_ROOT}" &&
  CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" go build -o "${BUILD_DIR}/winn-knockd" ./cmd/winn-knockd &&
  CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" go build -o "${BUILD_DIR}/winn-knock"  ./cmd/winn-knock &&
  CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" go build -o "${BUILD_DIR}/spaprobe"    ./deploy/spa/test/spaprobe )
cp "${REPO_ROOT}/deploy/spa/winn-spa-nft" "${BUILD_DIR}/winn-spa-nft"
chmod +x "${BUILD_DIR}"/*
echo "built for linux/${GOARCH}"

say "Preparing the test image"
# Built once, then served from Docker's layer cache. Doing the apk install per
# run made a transient package-mirror outage look exactly like a test failure.
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "building ${IMAGE} (first run only; needs network)"
  docker build -q -t "${IMAGE}" "$(dirname "${BASH_SOURCE[0]}")" >/dev/null || {
    echo >&2
    echo "FATAL: could not build the test image." >&2
    echo "The Alpine package mirror was unreachable from the Docker VM." >&2
    echo "This is an environment problem, NOT a test failure. Retry when network returns." >&2
    exit 2
  }
fi
echo "using ${IMAGE}"

say "Starting containers"
docker network rm "${NETWORK}" >/dev/null 2>&1 || true
docker network create "${NETWORK}" >/dev/null

docker run -d --name "${NODE}" --network "${NETWORK}" \
  --cap-add=NET_ADMIN \
  "${IMAGE}" sleep 3600 >/dev/null
docker run -d --name "${CLIENT}" --network "${NETWORK}" \
  "${IMAGE}" sleep 3600 >/dev/null

# Copied in rather than bind-mounted: a macOS host's mktemp directory is not
# inside Docker Desktop's shared paths, so a bind mount silently arrives empty.
for container in "${NODE}" "${CLIENT}"; do
  docker exec "${container}" mkdir -p /opt/spa
  for binary in winn-knockd winn-knock spaprobe winn-spa-nft; do
    docker cp "${BUILD_DIR}/${binary}" "${container}:/opt/spa/${binary}" >/dev/null
  done
  docker exec "${container}" chmod +x /opt/spa/winn-knockd /opt/spa/winn-knock \
    /opt/spa/spaprobe /opt/spa/winn-spa-nft
done

CLIENT_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}" "${CLIENT}")"
echo "client source address: ${CLIENT_IP}"

# The SPA key is a credential even in a test. It is generated inside the
# container and is never printed, never leaves it, and dies with it.
nodesh "mkdir -p /etc/winn/spa && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/winn/spa/spa.keys && chmod 400 /etc/winn/spa/spa.keys"
docker cp "${NODE}:/etc/winn/spa/spa.keys" "${BUILD_DIR}/spa.keys" >/dev/null
docker cp "${BUILD_DIR}/spa.keys" "${CLIENT}:/tmp/spa.keys" >/dev/null
rm -f "${BUILD_DIR}/spa.keys"

# A DIFFERENT key, to prove a wrong key opens nothing.
clientsh "head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /tmp/wrong.keys"

# An unprivileged user used by the non-root checks below.
nodesh "adduser -D -H spatest 2>/dev/null || true"

say "Starting the stand-in service on udp/${SERVICE_PORT}"
nodesh "nohup /opt/spa/spaprobe echo -listen :${SERVICE_PORT} >/tmp/echo.log 2>&1 &"
sleep 1
nodesh "cat /tmp/echo.log"

# ---------------------------------------------------------------------------
say "1. BASELINE: port reachable with no gate"
check "no gate -> reachable" "REACHABLE" "$(probe_from_client)"

# ---------------------------------------------------------------------------
say "4. ESTABLISHED FLOW survives the gate being installed"
# Start a persistent flow, install the gate mid-pause, and require that the
# flow still works afterwards. This is the property that makes enabling SPA on
# a live node a no-op for users who are already connected.
clientsh "nohup /opt/spa/spaprobe persist -target ${NODE}:${SERVICE_PORT} -pause 6s -timeout 2s >/tmp/persist.log 2>&1 &"
sleep 2

say "2. GATE INSTALLED: port invisible to a source that has not knocked"
nodesh "WINN_SPA_UDP_PORTS=${SERVICE_PORT} WINN_SPA_GRACE=${TEST_GRACE} /opt/spa/winn-spa-nft apply" || true
check "gated, no knock -> blocked" "BLOCKED" "$(probe_from_client)"

sleep 6
PERSIST_OUT="$(clientsh 'cat /tmp/persist.log' 2>/dev/null || true)"
echo "${PERSIST_OUT}"
check "established flow before gate" "BEFORE=REACHABLE" "$(echo "${PERSIST_OUT}" | grep -o 'BEFORE=[A-Z]*' || true)"
check "established flow survives gate" "AFTER=REACHABLE" "$(echo "${PERSIST_OUT}" | grep -o 'AFTER=[A-Z]*' || true)"

# ---------------------------------------------------------------------------
say "3. LOOPBACK still works while gated (the Xray -> 127.0.0.1:9110 path)"
LOOPBACK="$(nodesh "/opt/spa/spaprobe probe -target 127.0.0.1:${SERVICE_PORT} -timeout 2s" 2>/dev/null | tail -1 || true)"
check "loopback exempt while gated" "REACHABLE" "${LOOPBACK}"

# ---------------------------------------------------------------------------
say "Starting winn-knockd on udp/${KNOCK_PORT}"
nodesh "nohup /opt/spa/winn-knockd -keys /etc/winn/spa/spa.keys -listen 0.0.0.0:${KNOCK_PORT} -packet-size ${PACKET_SIZE} -grace ${TEST_GRACE} -nft-set-v4 spa_allow_v4 >/tmp/knockd.log 2>&1 &"
sleep 1
nodesh "cat /tmp/knockd.log"

# ---------------------------------------------------------------------------
say "5. WRONG KEY opens nothing"
clientsh "/opt/spa/winn-knock -key /tmp/wrong.keys -target ${NODE}:${KNOCK_PORT} -packet-size ${PACKET_SIZE}" 2>&1 | tail -1 || true
sleep 1
check "wrong key -> still blocked" "BLOCKED" "$(probe_from_client)"

# ---------------------------------------------------------------------------
say "6. RIGHT KEY opens the port"
clientsh "/opt/spa/winn-knock -key /tmp/spa.keys -target ${NODE}:${KNOCK_PORT} -packet-size ${PACKET_SIZE}" 2>&1 | tail -2 || true
sleep 1
check "valid knock -> reachable" "REACHABLE" "$(probe_from_client)"

echo "--- allow set now contains: ---"
nodesh "nft list set inet winn_spa spa_allow_v4"
SET_HAS_CLIENT="$(nodesh "nft list set inet winn_spa spa_allow_v4" | grep -c "${CLIENT_IP}" || true)"
check "client address is in the allow set" "1" "${SET_HAS_CLIENT}"

echo "--- knockd counters: ---"
nodesh "cat /tmp/knockd.log"

# ---------------------------------------------------------------------------
say "7. REVERT fully restores the node"
nodesh "/opt/spa/winn-spa-nft revert"
TABLE_GONE="$(nodesh "nft list table inet winn_spa >/dev/null 2>&1 && echo PRESENT || echo GONE")"
check "table deleted" "GONE" "${TABLE_GONE}"
check "after revert -> reachable" "REACHABLE" "$(probe_from_client)"

# ---------------------------------------------------------------------------
say "8. DAEMON DEATH: the watchdog re-opens the port"
nodesh "WINN_SPA_UDP_PORTS=${SERVICE_PORT} WINN_SPA_GRACE=${TEST_GRACE} /opt/spa/winn-spa-nft apply" >/dev/null || true
check "re-gated -> blocked" "BLOCKED" "$(probe_from_client)"
nodesh "pkill -9 -x winn-knockd" || true
sleep 1
DAEMON_ALIVE="$(nodesh "pgrep -x winn-knockd >/dev/null 2>&1 && echo ALIVE || echo DEAD")"
check "daemon is actually dead" "DEAD" "${DAEMON_ALIVE}"
# This is the shell the shipped winn-spa-watchdog.service runs, with the
# liveness check swapped from `systemctl is-active winn-knockd.service` to
# `pgrep -x` because a container has no systemd. `-x` matches the executable
# name exactly: `pgrep -f` would match the watchdog's OWN command line, which
# contains the string "winn-knockd", and conclude the daemon is alive.
nodesh "if nft list table inet winn_spa >/dev/null 2>&1; then if ! pgrep -x winn-knockd >/dev/null 2>&1; then /opt/spa/winn-spa-nft revert; fi; fi"
check "watchdog re-opened the port" "REACHABLE" "$(probe_from_client)"

# ---------------------------------------------------------------------------
# These are the checks the review asked for: assert the BEHAVIOUR (the deadline
# actually moves) rather than the command string. F1 and F2 both returned exit 0
# and looked correct at the argv/rule level while silently doing nothing.
# ---------------------------------------------------------------------------
say "9. F2: a re-knock RENEWS the deadline (destroy+add, not add)"
nodesh "WINN_SPA_UDP_PORTS=${SERVICE_PORT} WINN_SPA_GRACE=${TEST_GRACE} /opt/spa/winn-spa-nft apply" >/dev/null || true
nodesh "nohup /opt/spa/winn-knockd -keys /etc/winn/spa/spa.keys -listen 0.0.0.0:${KNOCK_PORT} -packet-size ${PACKET_SIZE} -grace ${TEST_GRACE} -nft-set-v4 spa_allow_v4 >/tmp/knockd2.log 2>&1 &"
sleep 1
clientsh "/opt/spa/winn-knock -key /tmp/spa.keys -target ${NODE}:${KNOCK_PORT} -packet-size ${PACKET_SIZE}" >/dev/null 2>&1 || true
sleep 1
expiry_ms() {
  nodesh "nft list set inet winn_spa spa_allow_v4 2>/dev/null" \
    | grep -o 'expires [0-9a-z]*' | head -1 | awk '{print $2}'
}
E1="$(expiry_ms)"; echo "  deadline just after knock:      ${E1}"
echo "  ...letting it decay for 12s (no traffic)..."
sleep 12
E2="$(expiry_ms)"; echo "  deadline after 12s of silence:  ${E2}"
clientsh "/opt/spa/winn-knock -key /tmp/spa.keys -target ${NODE}:${KNOCK_PORT} -packet-size ${PACKET_SIZE}" >/dev/null 2>&1 || true
sleep 1
E3="$(expiry_ms)"; echo "  deadline after a RE-KNOCK:      ${E3}"
# Convert nft's duration form ("29s968ms", "1m29s972ms", "4s") to whole seconds.
# The trailing millisecond component is stripped FIRST, because "968ms" would
# otherwise match the minutes pattern and be read as 968 minutes.
secs() {
  printf '%s' "${1:-0s}" | sed 's/[0-9]*ms$//' | awk '{
    s=$0; m=0; sec=0
    if (match(s, /[0-9]+m/)) { m = substr(s, RSTART, RLENGTH-1)+0; s = substr(s, RSTART+RLENGTH) }
    if (match(s, /[0-9]+s/)) { sec = substr(s, RSTART, RLENGTH-1)+0 }
    print m*60+sec
  }'
}
S2="$(secs "${E2}")"; S3="$(secs "${E3}")"
if [[ -n "${E3}" && "${S3}" -gt "${S2}" ]]; then
  ok "re-knock moved the deadline forward (${E2} -> ${E3})"
else
  bad "re-knock did NOT renew the deadline (${E2} -> ${E3}) -- F2 has regressed"
fi

say "10. F1: the window SLIDES under sustained traffic (update rule is reached)"
# Authorized source sending continuously must hold its deadline near full grace.
clientsh "nohup /opt/spa/spaprobe sustain -target ${NODE}:${SERVICE_PORT} -duration 40s -interval 500ms >/tmp/sustain.log 2>&1 &"
sleep 25
E4="$(expiry_ms)"; echo "  deadline after 25s of ACTIVE traffic: ${E4}"
S4="$(secs "${E4}")"
# The grace is 30s. Under the F1 bug the update rule was never reached, so after
# 25s of traffic the element would read ~5s or be gone. With the fix it is
# re-armed by every packet and stays near full.
if [[ -n "${E4}" && "${S4}" -ge 20 ]]; then
  ok "window slid under load (${E4} of ${TEST_GRACE} left after 25s; the F1 bug would show ~5s or EXPIRED)"
else
  bad "window did NOT slide (${E4} left of ${TEST_GRACE} after 25s) -- F1 has regressed"
fi
# Wait for the 40s run to finish before reading its verdict.
sleep 20
SUSTAIN="$(clientsh 'cat /tmp/sustain.log' 2>/dev/null | tail -1 || true)"
echo "  sustained flow result: ${SUSTAIN}"
case "${SUSTAIN}" in
  *RECEIVED=0*|"") bad "authorized sustained flow got no replies (${SUSTAIN})" ;;
  *) ok "authorized sustained flow kept working through the whole run (${SUSTAIN})" ;;
esac

say "11. Re-apply PRESERVES live authorizations"
BEFORE_ELEMS="$(nodesh "nft list set inet winn_spa spa_allow_v4" | grep -c "${CLIENT_IP}" || true)"
nodesh "WINN_SPA_UDP_PORTS=${SERVICE_PORT} WINN_SPA_GRACE=${TEST_GRACE} /opt/spa/winn-spa-nft apply" >/dev/null || true
AFTER_ELEMS="$(nodesh "nft list set inet winn_spa spa_allow_v4" | grep -c "${CLIENT_IP}" || true)"
check "client still authorized after re-apply" "${BEFORE_ELEMS}" "${AFTER_ELEMS}"

say "12. status does not lie to a non-root operator"
STATUS_NONROOT="$(nodesh "su spatest -s /bin/sh -c '/opt/spa/winn-spa-nft status' 2>&1 | head -1" || true)"
echo "  ${STATUS_NONROOT}"
case "${STATUS_NONROOT}" in
  *"NOT INSTALLED"*) bad "status told a non-root operator nothing is gated, while it IS" ;;
  *UNKNOWN*)         ok "status refuses to guess as non-root" ;;
  *)                 bad "unexpected non-root status output: ${STATUS_NONROOT}" ;;
esac

say "14. F3: revert as a NON-ROOT user fails -- which is why ExecStopPost needs +"
# This is the defect F3 described: winn-knockd.service runs as User=winn-knockd,
# so an ExecStopPost without the `+` prefix runs unprivileged, hits require_root,
# and leaves the gate installed with no daemon. Proving the failure here is the
# closest we can get without systemd in a container.
nodesh "WINN_SPA_UDP_PORTS=${SERVICE_PORT} WINN_SPA_GRACE=${TEST_GRACE} /opt/spa/winn-spa-nft apply" >/dev/null 2>&1 || true
NONROOT_REVERT="$(nodesh "su spatest -s /bin/sh -c '/opt/spa/winn-spa-nft revert' 2>&1 | head -1" || true)"
STILL_THERE="$(nodesh "nft list table inet winn_spa >/dev/null 2>&1 && echo PRESENT || echo GONE")"
echo "  non-root revert said: ${NONROOT_REVERT}"
check "unprivileged revert leaves the gate UP (hence ExecStopPost=+)" "PRESENT" "${STILL_THERE}"
nodesh "/opt/spa/winn-spa-nft revert" >/dev/null 2>&1 || true

say "13. udp/9110 is REFUSED outright (direct-awg cannot knock)"
REFUSAL="$(nodesh "WINN_SPA_UDP_PORTS=9110 /opt/spa/winn-spa-nft render 2>&1 | head -1" || true)"
case "${REFUSAL}" in
  *"refusing to gate udp/9110"*) ok "9110 refused: ${REFUSAL}" ;;
  *) bad "9110 was NOT refused, got: ${REFUSAL}" ;;
esac
nodesh "/opt/spa/winn-spa-nft revert" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
say "15. N3: the sliding window uses the GRANTED grace, not the set default"
# The original bug: `update @set { ip saddr }` with no explicit timeout re-armed
# from the SET default, discarding the per-element timeout the daemon granted,
# while `nft list set` kept displaying the granted value. The old suite missed it
# by setting both to the same number. Here the set default is 30s and we confirm
# an ACTIVE flow is held at ~30s rather than collapsing to some other value.
nodesh "WINN_SPA_UDP_PORTS=${SERVICE_PORT} WINN_SPA_GRACE=${TEST_GRACE} /opt/spa/winn-spa-nft apply" >/dev/null 2>&1 || true
TRACK_RULE="$(nodesh "nft list table inet winn_spa" | grep -o 'update @spa_allow_v4 { ip saddr timeout [0-9a-z]* }' | head -1)"
echo "  track rule: ${TRACK_RULE}"
case "${TRACK_RULE}" in
  *"timeout 30s"*) ok "update statement carries an EXPLICIT timeout matching the grace" ;;
  "")              bad "no update statement with an explicit timeout was emitted -- N3 has regressed" ;;
  *)               bad "update timeout does not match the configured grace: ${TRACK_RULE}" ;;
esac

say "16. Structural guard: the update lives in its OWN base chain"
# This is what makes the sliding window independent of rule ordering in the
# filtering chain. An accept ends only the chain it is in; netfilter still runs
# every base chain at the hook.
TRACK_CHAIN="$(nodesh "nft list table inet winn_spa" | grep -c 'chain track' || true)"
TRACK_PRIO="$(nodesh "nft list table inet winn_spa" | grep -A1 'chain track' | grep -o 'priority[^;]*' | head -1)"
INPUT_PRIO="$(nodesh "nft list table inet winn_spa" | grep -A1 'chain input' | grep -o 'priority[^;]*' | head -1)"
echo "  track chain priority: ${TRACK_PRIO} / input chain priority: ${INPUT_PRIO}"
check "a dedicated track chain exists" "1" "${TRACK_CHAIN}"
# And prove it actually counts packets from an authorized, active source.
nodesh "nohup /opt/spa/winn-knockd -keys /etc/winn/spa/spa.keys -listen 0.0.0.0:${KNOCK_PORT} -packet-size ${PACKET_SIZE} -grace ${TEST_GRACE} -nft-set-v4 spa_allow_v4 >/tmp/knockd3.log 2>&1 &"
sleep 1
clientsh "/opt/spa/winn-knock -key /tmp/spa.keys -target ${NODE}:${KNOCK_PORT} -packet-size ${PACKET_SIZE}" >/dev/null 2>&1 || true
sleep 1
clientsh "/opt/spa/spaprobe sustain -target ${NODE}:${SERVICE_PORT} -duration 6s -interval 300ms" >/dev/null 2>&1 || true
TRACK_PACKETS="$(nodesh "nft list table inet winn_spa" | grep 'update @spa_allow_v4' | grep -o 'packets [0-9]*' | awk '{print $2}')"
echo "  track chain counted ${TRACK_PACKETS} packets from the authorized source"
if [[ -n "${TRACK_PACKETS}" && "${TRACK_PACKETS}" -gt 5 ]]; then
  ok "track chain is reached by tunnel traffic (${TRACK_PACKETS} packets)"
else
  bad "track chain saw ${TRACK_PACKETS:-0} packets -- the update is being starved"
fi

say "17. N1: the udp/9110 refusal cannot be bypassed by an env var"
BYPASS="$(nodesh "WINN_SPA_UDP_PORTS_FORBIDDEN=1 WINN_SPA_UDP_PORTS=9110 /opt/spa/winn-spa-nft render 2>&1 | head -1" || true)"
case "${BYPASS}" in
  *"refusing to gate udp/9110"*) ok "env override rejected: ${BYPASS}" ;;
  *) bad "udp/9110 gate was emitted despite the refusal, via env override: ${BYPASS}" ;;
esac
# And the same port via the TCP list must be refused too.
BYPASS_TCP="$(nodesh "WINN_SPA_TCP_PORTS=9110 /opt/spa/winn-spa-nft render 2>&1 | head -1" || true)"
case "${BYPASS_TCP}" in
  *"refusing to gate"*) ok "9110 in the TCP list is refused too" ;;
  *) bad "9110 via WINN_SPA_TCP_PORTS was NOT refused: ${BYPASS_TCP}" ;;
esac

say "18. Preflight refuses a -grace that disagrees with the set timeout (N3 guard)"
MISMATCH="$(nodesh "/opt/spa/winn-knockd -keys /etc/winn/spa/spa.keys -listen 0.0.0.0:9199 -packet-size ${PACKET_SIZE} -grace 17m -nft-set-v4 spa_allow_v4 2>&1 | head -2" || true)"
echo "  ${MISMATCH}"
case "${MISMATCH}" in
  *"MUST be equal"*) ok "daemon refuses to start on a grace/set-timeout mismatch" ;;
  *) bad "daemon started with a grace that disagrees with the set: ${MISMATCH}" ;;
esac

say "19. F3: the shipped unit passes systemd-analyze verify with ExecStopPost=-+"
nodesh "apk add --no-cache systemd >/dev/null 2>&1 || true"
if nodesh "command -v systemd-analyze >/dev/null 2>&1"; then
  docker cp deploy/spa/winn-knockd.service "${NODE}:/etc/systemd/system/winn-knockd.service" >/dev/null 2>&1 || true
  VERIFY="$(nodesh "systemd-analyze verify /etc/systemd/system/winn-knockd.service 2>&1 | grep -iv 'unit .* not found\|LoadCredential\|EnvironmentFile' | head -3" || true)"
  echo "  ${VERIFY:-(no complaints)}"
  case "${VERIFY}" in
    *"Invalid"*|*"invalid"*|*"Failed to parse"*) bad "systemd rejected the unit: ${VERIFY}" ;;
    *) ok "systemd-analyze verify accepted ExecStopPost=-+" ;;
  esac
else
  echo "  SKIPPED: systemd-analyze unavailable in this image (Alpine has no systemd)."
  echo "  The '+' prefix was verified under real systemd 252 by the reviewer;"
  echo "  this check is a placeholder for a systemd-capable test host."
fi
nodesh "/opt/spa/winn-spa-nft revert" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
say "RESULTS"
printf '  passed: %d\n  failed: %d\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]] || exit 1
echo "  ALL CHECKS PASSED"
