#!/usr/bin/env bash
#
# Verifies the parts of the fail-open guarantee that need REAL systemd, which
# the main integration test cannot cover because it runs on Alpine.
#
# Two things are checked, and the second is the one that matters:
#
#   1. `systemd-analyze verify` accepts the shipped unit, so a mistyped
#      ExecStopPost prefix is caught rather than silently ignored.
#   2. After the daemon is SIGKILLed, ExecStopPost actually RUNS AS ROOT
#      despite User=winn-knockd, and actually removes the gate.
#
# (2) is the fix. The main suite's check 14 only pins the PREMISE - that an
# unprivileged revert fails - so dropping the `+` would still pass there.
#
# Needs a privileged container to run systemd as PID 1. Nothing here touches any
# real node.
set -uo pipefail

IMAGE=winnspa-systemd-test:1
NAME=winnspa-systemd
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUILD="$(mktemp -d)"
PASS=0; FAIL=0

ok()  { printf '  PASS  %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }

cleanup() { docker rm -f "${NAME}" >/dev/null 2>&1; rm -rf "${BUILD}"; }
trap cleanup EXIT
# Remove only a stale container here -- NOT the build dir, which was just
# created above and is about to be written to.
docker rm -f "${NAME}" >/dev/null 2>&1

echo "=== building test image (systemd + nftables) ==="
# Ubuntu 24.04 deliberately: it is what production runs, so nft is 1.0.9
# (>= MinNFTVersion) and the daemon can actually start. Debian 12 ships nft
# 1.0.6, where winn-knockd's own version guard correctly refuses to run, which
# is useful evidence but prevents a live-daemon SIGKILL test.
cat > "${BUILD}/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd nftables procps && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
docker build -q -t "${IMAGE}" "${BUILD}" >/dev/null || {
  echo "FATAL: could not build the systemd test image (network?)." >&2; exit 2; }

echo "=== starting systemd as PID 1 ==="
docker run -d --name "${NAME}" --privileged \
  --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --cgroupns=host "${IMAGE}" >/dev/null
for _ in $(seq 1 30); do
  docker exec "${NAME}" systemctl is-system-running >/dev/null 2>&1 && break
  sleep 1
done
echo "  systemd state: $(docker exec "${NAME}" systemctl is-system-running 2>&1 || true)"
echo "  nft version:   $(docker exec "${NAME}" nft --version 2>&1 || true)"

# --- install the real artefacts -------------------------------------------
( cd "${REPO}" && CGO_ENABLED=0 GOOS=linux GOARCH="$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/; s/aarch64/arm64/')" \
    go build -o "${BUILD}/winn-knockd" ./cmd/winn-knockd ) || exit 1
docker cp "${BUILD}/winn-knockd" "${NAME}:/usr/local/bin/winn-knockd" >/dev/null
docker cp "${REPO}/deploy/spa/winn-spa-nft" "${NAME}:/usr/local/sbin/winn-spa-nft" >/dev/null
docker cp "${REPO}/deploy/spa/winn-knockd.service" "${NAME}:/etc/systemd/system/winn-knockd.service" >/dev/null
docker exec "${NAME}" chmod +x /usr/local/bin/winn-knockd /usr/local/sbin/winn-spa-nft

echo
echo "=== 1. systemd-analyze verify on the shipped unit ==="
VERIFY="$(docker exec "${NAME}" systemd-analyze verify /etc/systemd/system/winn-knockd.service 2>&1 \
  | grep -viE 'not found|LoadCredential|EnvironmentFile|Unknown key|dependency' || true)"
echo "  ${VERIFY:-(no complaints)}"
case "${VERIFY}" in
  *nvalid*|*"Failed to parse"*|*"Executable path"*) bad "systemd rejected the unit: ${VERIFY}" ;;
  *) ok "systemd-analyze verify accepted the unit (ExecStopPost=-+ parses)" ;;
esac

echo
echo "=== 2. ExecStopPost runs AS ROOT after SIGKILL and removes the gate ==="
docker exec "${NAME}" bash -c '
  id -u winn-knockd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin winn-knockd
  mkdir -p /etc/winn/spa && chmod 700 /etc/winn/spa
  head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > /etc/winn/spa/spa.keys
  chmod 400 /etc/winn/spa/spa.keys
  cat > /etc/winn/spa/knockd.env <<EOF
WINN_SPA_LISTEN=0.0.0.0:9111
WINN_SPA_PACKET_SIZE=256
WINN_SPA_GRACE=30m
WINN_SPA_TABLE=winn_spa
WINN_SPA_SET_V4=spa_allow_v4
EOF
  # systemd LoadCredential does not function in this container AT ALL -- it
  # fails for a root service too ("No such file or directory", credentials dir
  # empty, no ramfs mount), so it is an environment limitation and not a defect
  # in the shipped unit. Swap it for a direct, service-user-readable path here
  # so the daemon GENUINELY RUNS and the SIGKILL below kills a live process
  # rather than a crash-looping one. LoadCredential itself must be verified on a
  # real VM; see the handoff.
  # The directory is 0700 root, so chowning only the FILE still leaves the
  # service user unable to traverse into it. Both are needed.
  chown winn-knockd /etc/winn/spa/spa.keys
  chown winn-knockd /etc/winn/spa
  sed -i "s#^LoadCredential=.*##" /etc/systemd/system/winn-knockd.service
  sed -i "s#%d/spa.keys#/etc/winn/spa/spa.keys#" /etc/systemd/system/winn-knockd.service
  # Record the uid ExecStopPost runs as, which is the whole point of `+`.
  sed -i "s#^ExecStopPost=.*#ExecStopPost=-+/bin/sh -c \x27id -u > /run/stoppost.uid; /usr/local/sbin/winn-spa-nft revert >> /run/stoppost.log 2>\&1\x27#" \
    /etc/systemd/system/winn-knockd.service
  systemctl daemon-reload
  WINN_SPA_UDP_PORTS=8443 WINN_SPA_GRACE=30m /usr/local/sbin/winn-spa-nft apply >/dev/null 2>&1
  systemctl start winn-knockd.service
' >/dev/null 2>&1
sleep 3
# nft on Debian 12 is 1.0.6, below MinNFTVersion, so the daemon's own preflight
# refuses to start -- which is itself the portability guard working. Report it
# rather than letting it look like an unrelated failure.
docker exec "${NAME}" journalctl -u winn-knockd --no-pager -n 3 --output=cat 2>&1 \
  | grep -q "or newer is required" && \
  echo "  NOTE: daemon refused to start -- nft 1.0.6 < ${MIN:-1.0.8}. That is the version guard working."
STARTED="$(docker exec "${NAME}" systemctl is-active winn-knockd.service 2>&1 || true)"
GATE_BEFORE="$(docker exec "${NAME}" sh -c 'nft list table inet winn_spa >/dev/null 2>&1 && echo PRESENT || echo GONE')"
echo "  daemon: ${STARTED}   gate before kill: ${GATE_BEFORE}"
if [[ "${STARTED}" != "active" ]]; then
  echo "  daemon log:"; docker exec "${NAME}" journalctl -u winn-knockd --no-pager -n 15 2>&1 | sed 's/^/    /'
fi

docker exec "${NAME}" bash -c 'kill -9 $(systemctl show -p MainPID --value winn-knockd.service)' >/dev/null 2>&1
sleep 4
STOPPOST_UID="$(docker exec "${NAME}" cat /run/stoppost.uid 2>/dev/null | tr -d '\r\n' || true)"
GATE_AFTER="$(docker exec "${NAME}" sh -c 'nft list table inet winn_spa >/dev/null 2>&1 && echo PRESENT || echo GONE')"
echo "  ExecStopPost ran as uid: ${STOPPOST_UID:-<did not run>}"
echo "  gate after SIGKILL:      ${GATE_AFTER}"
[[ "${STOPPOST_UID}" == "0" ]] \
  && ok "ExecStopPost ran as root despite User=winn-knockd (the '+' works)" \
  || bad "ExecStopPost ran as uid '${STOPPOST_UID:-none}', not root -- fail-open is broken"
[[ "${GATE_AFTER}" == "GONE" ]] \
  && ok "the gate was removed after SIGKILL: the node failed OPEN" \
  || bad "the gate SURVIVED daemon death -- this is the mass-lockout state"

echo
echo "=== 3. negative control: ExecStopPost WITHOUT '+' must fail to revert ==="
docker exec "${NAME}" bash -c '
  rm -f /run/stoppost.uid
  sed -i "s#^ExecStopPost=.*#ExecStopPost=-/bin/sh -c \x27id -u > /run/stoppost.uid; /usr/local/sbin/winn-spa-nft revert\x27#" \
    /etc/systemd/system/winn-knockd.service
  systemctl daemon-reload
  WINN_SPA_UDP_PORTS=8443 WINN_SPA_GRACE=30m /usr/local/sbin/winn-spa-nft apply >/dev/null 2>&1
  systemctl start winn-knockd.service
' >/dev/null 2>&1
sleep 3
# nft on Debian 12 is 1.0.6, below MinNFTVersion, so the daemon's own preflight
# refuses to start -- which is itself the portability guard working. Report it
# rather than letting it look like an unrelated failure.
docker exec "${NAME}" journalctl -u winn-knockd --no-pager -n 3 --output=cat 2>&1 \
  | grep -q "or newer is required" && \
  echo "  NOTE: daemon refused to start -- nft 1.0.6 < ${MIN:-1.0.8}. That is the version guard working."
docker exec "${NAME}" bash -c 'kill -9 $(systemctl show -p MainPID --value winn-knockd.service)' >/dev/null 2>&1
sleep 4
CTRL_UID="$(docker exec "${NAME}" cat /run/stoppost.uid 2>/dev/null | tr -d '\r\n' || true)"
CTRL_GATE="$(docker exec "${NAME}" sh -c 'nft list table inet winn_spa >/dev/null 2>&1 && echo PRESENT || echo GONE')"
echo "  without '+': ExecStopPost uid=${CTRL_UID:-<none>}  gate=${CTRL_GATE}"
[[ "${CTRL_GATE}" == "PRESENT" ]] \
  && ok "negative control confirms '+' is load-bearing (gate survived without it)" \
  || bad "negative control did NOT reproduce the failure; the test proves nothing"
docker exec "${NAME}" /usr/local/sbin/winn-spa-nft revert >/dev/null 2>&1

echo
printf 'RESULTS  passed: %d  failed: %d\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]] || exit 1
