#!/bin/bash
# Re-applies the two firewall subsets that make this node a working VPN.
#
# WHY THIS EXISTS: iptables rules here are runtime-only (no iptables-persistent,
# no /etc/iptables/rules.v4), and the mechanism that would normally restore them
# -- wins-edge-hardening.timer -- is DELIBERATELY DISABLED because the full
# artifact closes tcp/80 and tcp/22 (no admission file, Suricata absent). So a
# reboot would silently drop client egress and the Cloudflare-only stealth
# restriction, and the node would look healthy while carrying nobody.
#
# Both halves are idempotent. Runs after docker so --noflush cannot race Docker's
# own chain creation.
set -u
log() { logger -t wins-vpn-firewall "$*"; echo "wins-vpn-firewall: $*"; }

# 1. Client egress: FORWARD accept + MASQUERADE for the VPN subnet.
if [[ -f /root/wins-forward-nat.transaction ]]; then
  if iptables-restore --wait 10 --noflush < /root/wins-forward-nat.transaction; then
    log "egress subset applied"
  else
    log "ERROR: egress subset FAILED to apply"
  fi
else
  log "ERROR: /root/wins-forward-nat.transaction missing; client egress NOT restored"
fi

# 2. Stealth ports reachable only via Cloudflare (hides the origin from raw-IP probes).
CF="$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null | tr '\n' ' ')"
if [[ "$(printf '%s' "$CF" | wc -w)" -lt 5 ]]; then
  log "WARN: could not fetch Cloudflare ranges; leaving stealth ports OPEN rather than locking them out"
  exit 0
fi
iptables -N WINVPN-STEALTH-CF 2>/dev/null || iptables -F WINVPN-STEALTH-CF
iptables -A WINVPN-STEALTH-CF -i lo -j RETURN
iptables -A WINVPN-STEALTH-CF -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
for r in $CF; do iptables -A WINVPN-STEALTH-CF -s "$r" -j RETURN; done
iptables -A WINVPN-STEALTH-CF -j DROP
iptables -C INPUT -p tcp -m multiport --dports 80,443 -j WINVPN-STEALTH-CF 2>/dev/null \
  || iptables -I INPUT 1 -p tcp -m multiport --dports 80,443 -j WINVPN-STEALTH-CF
log "cloudflare-only stealth applied ($(printf '%s' "$CF" | wc -w) ranges)"
