#!/usr/bin/env bash
# Pins winn-spa-nft's port-token validation: the port 22 and
# PORTS_FORBIDDEN (9110) refusals compare exact strings, so a range
# ("20-30") or service name ("ssh") token must be refused before those
# checks, or nft would gate exactly the protected ports. Needs no
# root, no nft and no docker: `render` runs the same assertions.
set -uo pipefail

SPA_NFT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/winn-spa-nft"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }

refused() { # description, env assignment...
  local desc="$1"; shift
  if env "$@" bash "${SPA_NFT}" render >/dev/null 2>&1; then
    bad "${desc}: render succeeded, want refusal"
  else
    ok "${desc}: refused"
  fi
}

refused "tcp range covering ssh"   WINN_SPA_TCP_PORTS=20-30
refused "tcp service name ssh"     WINN_SPA_TCP_PORTS=ssh
refused "udp range covering 9110"  WINN_SPA_UDP_PORTS=9000-9200
refused "tcp port 22"              WINN_SPA_TCP_PORTS=22
refused "udp port 9110"            WINN_SPA_UDP_PORTS=9110
refused "port zero"                WINN_SPA_UDP_PORTS=0
refused "port above 65535"         WINN_SPA_UDP_PORTS=70000
refused "nft metacharacter token"  WINN_SPA_TCP_PORTS='8443}'

rendered="$(WINN_SPA_UDP_PORTS=8443 WINN_SPA_TCP_PORTS=8443 \
  bash "${SPA_NFT}" render 2>/dev/null)"
if [[ "${rendered}" == *'udp dport 8443'* ]]; then
  ok "plain numeric carrier port renders"
else
  bad "plain numeric carrier port renders"
fi

printf '%s passed, %s failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
