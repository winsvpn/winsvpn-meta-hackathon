#!/usr/bin/env bash
# Cross-language conformance for the Windows Winn Protocol v3 supervisor.
#
# WHAT THIS PROVES, and why it is the strongest check available off Windows.
#
# There is no Windows host on the machine this project is developed on, so the
# supervisor's processes, pipes, route pin and netsh calls cannot be executed
# here. What CAN be executed is the part where the two languages meet, and that
# is where the failures this lane exists to prevent actually live: a profile the
# Go decoder rejects, a status document the C++ parser misreads, or an inner MTU
# that disagrees between the two. This script runs BOTH directions against a
# REAL cmd/winn-datapath binary built from this tree:
#
#   1. the C++ supervisor emits a -winn3-profile document from a [winn3]
#      section, and the REAL engine decodes it with DisallowUnknownFields;
#   2. the REAL engine publishes its sizing document, and the C++ supervisor
#      parses it, checks the inner MTU, renders the relay's start command, and
#      renders the netsh argument vectors it would execute.
#
# A parser tested only against literals a human typed is a parser tested against
# what that human believed the other side emits. This reads what it emits.
#
# WHAT IT DOES NOT PROVE: nothing here creates a Wintun adapter, starts the
# relay, pins a route, runs netsh or contacts a gateway. `-winn3-print-sizing`
# computes the plan floor from the profile and exits -- no socket, no key file
# read, no network. That is exactly why it can run here.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

say() { printf '[WINN3-SUPERVISOR] %s\n' "$*"; }

if ! command -v go >/dev/null 2>&1; then
  say "SKIPPED: a Go toolchain is required to build the real engine."
  exit 0
fi

cxx="${CXX:-c++}"
if ! command -v "${cxx}" >/dev/null 2>&1; then
  say "SKIPPED: no C++ compiler found (set CXX to override)."
  exit 0
fi

say "Building the supervisor's decidable half and running its own tests"
"${cxx}" -std=c++17 -Wall -Wextra -Werror \
  -o "${work}/winn3_supervisor_test" \
  "${repo_root}/windows/runner/winn3_supervisor_test.cc"
"${work}/winn3_supervisor_test" | sed 's/^/  /'

say "Building the REAL cmd/winn-datapath for this host"
(
  cd "${repo_root}/winn_protocol_experimental"
  GOTOOLCHAIN=local go build -o "${work}/winn-datapath" ./cmd/winn-datapath
)

# A [winn3] section in the shape a served configuration would carry. The key
# paths point at real files this script creates below: since the fleet path
# MTU default moved to 1450 (2026-08-10), -winn3-print-sizing opens the key
# files while loading the profile, so "they need not exist" is no longer true.
# D-01 (2026-08-28 audit): this heredoc used to carry a LIVE fleet static
# X25519 private key, byte-identical to ~/.xprize/winn3-fleet-v4/static.key.
# It is now an unmistakably synthetic repeated-byte value; a real key must
# NEVER appear here. Sizing never transmits the contents, so synthetic bytes
# exercise the same code path. The static-check gate
# (tools/audit_git_history_for_secrets.py) rejects any non-uniform 64-hex
# value in this file's key heredocs.
cat > "${work}/static.key" <<'KEY'
1111111111111111111111111111111111111111111111111111111111111111
KEY
cat > "${work}/gateway.pub" <<'KEY'
c2de5e4ab8fd7bc59958b45e7d4b4719c2917986f5f3e4d62d1785e6d3e79c16
KEY
cat > "${work}/admission.key" <<'KEY'
<REDACTED_ADMISSION_KEY>
KEY
chmod 0600 "${work}/static.key" "${work}/gateway.pub" "${work}/admission.key"

cat > "${work}/winn3.conf" <<CONFIG
[winn3]
enabled = true
endpoint = 198.51.100.7:443
class = udp
plan = udp, tcp, tls
path_mtu = 1450
gateway_id = kansas-1
node = lab-alpha
selected_node = lab-alpha
inner_v4 = 10.9.0.2
router_v4 = 10.9.0.1
static_key_path = ${work}/static.key
gateway_static_key_path = ${work}/gateway.pub
admission_path = ${work}/admission.key
routes = 0.0.0.0/0
dns = 10.9.0.53
dns_are_inner = true
CONFIG

say "Direction 1: the C++ supervisor's profile -> the real Go decoder"
"${work}/winn3_supervisor_test" -emit-profile 49152 \
  < "${work}/winn3.conf" > "${work}/profile.json"
sed 's/^/  /' "${work}/profile.json"

# device.kind is the field that decides whether the tunnel encrypts. Asserted
# on the bytes that actually reach the engine, not on the code that wrote them.
if ! grep -q '"kind":"loopback-udp"' "${work}/profile.json"; then
  say "FAIL: the profile does not name device.kind loopback-udp."
  exit 1
fi
if grep -qi 'awg\|ip-packet' "${work}/profile.json"; then
  say "FAIL: the profile names a winn/1 payload class."
  exit 1
fi

if ! "${work}/winn-datapath" -winn3-profile "${work}/profile.json" \
  -winn3-print-sizing > "${work}/sizing.json" 2> "${work}/engine.stderr"; then
  say "FAIL: the real engine rejected the emitted profile:"
  sed 's/^/  /' "${work}/engine.stderr" >&2
  exit 1
fi
say "The real engine ACCEPTED it and published:"
sed 's/^/  /' "${work}/sizing.json"

# THE ARITHMETIC, read off the engine rather than restated.
#   carrier.Floor(1450, udp, tcp, tls) = 1338
#   tun.Overhead()                     =   29
#   1338 - 29                          = 1309
# 1393 is the DIALLED UDP/IPv4 value and is the trap: an adapter that size
# black holes 1310..1393 the moment the carrier migrates.
if ! grep -q '"inner_mtu":1309' "${work}/sizing.json"; then
  say "FAIL: the engine did not publish the expected shipping-floor inner MTU."
  exit 1
fi
if ! grep -q '"message_size":1338' "${work}/sizing.json"; then
  say "FAIL: the engine did not publish the expected plan floor."
  exit 1
fi
if grep -q '"inner_mtu":1393' "${work}/sizing.json"; then
  say "FAIL: the engine published the DIALLED UDP/IPv4 MTU."
  exit 1
fi
# 1309 >= 1280, so inner IPv6 is arithmetically possible at this floor --
# the property that moved the fleet default from 1280 to 1450 in the first
# place. The host still installs no inner IPv6; THE ENGINE may now say true.
if ! grep -q '"inner_ipv6":true' "${work}/sizing.json"; then
  say "FAIL: the engine denies inner IPv6 at a floor that can carry it."
  exit 1
fi

say "Direction 2: the real engine's document -> the C++ supervisor"
"${work}/winn3_supervisor_test" -parse < "${work}/sizing.json" \
  > "${work}/parsed.txt"
sed 's/^/  /' "${work}/parsed.txt"

# The number that reaches the relay must be the engine's, not a constant.
if ! grep -q 'start mtu=1309 ' "${work}/parsed.txt"; then
  say "FAIL: the start command does not carry the engine's inner MTU."
  exit 1
fi
# A closed gate must HOLD the narrow posture. There is no parse outcome that
# widens a tunnel.
if ! grep -q 'verdict: HOLD' "${work}/parsed.txt"; then
  say "FAIL: a closed gate did not hold the bootstrap posture."
  exit 1
fi
if ! grep -q 'default=no ipv6=no dns=0' "${work}/parsed.txt"; then
  say "FAIL: the bootstrap posture was not narrow."
  exit 1
fi
if ! grep -q 'mtu=1309 store=active' "${work}/parsed.txt"; then
  say "FAIL: the rendered netsh commands do not set the engine's MTU."
  exit 1
fi
if grep -q '0.0.0.0/1' "${work}/parsed.txt"; then
  say "FAIL: a bootstrap posture rendered a default route."
  exit 1
fi

say "PASS: the C++ supervisor and the real Go engine agree in both directions."
say "NOT EXECUTED: no Wintun adapter, no relay, no route pin, no netsh, no"
say "gateway. -winn3-print-sizing opens no socket and reads the key files only,"
say "which is exactly why this check can run on a machine that is not Windows."
