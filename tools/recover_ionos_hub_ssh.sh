#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_RECOVERY_SSH_PUBLIC_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEeoxHg0lm8boSsdp2b385tbFYei19LcyfYj1GWVT8ZU winsvpn-codex-admin'
RECOVERY_SSH_PUBLIC_KEY="${RECOVERY_SSH_PUBLIC_KEY:-${DEFAULT_RECOVERY_SSH_PUBLIC_KEY}}"
RECOVERY_ADMIN_CIDRS="${RECOVERY_ADMIN_CIDRS:-}"
RECOVERY_ENABLE_PASSWORD_AUTH="${RECOVERY_ENABLE_PASSWORD_AUTH:-0}"

die() { printf '[ERR] %s\n' "$*" >&2; exit 1; }

normalize_cidr() {
  local value="$1" address prefix octet
  address="${value%/*}"
  prefix="${value#*/}"
  [[ "${value}" == */* ]] || prefix=32
  [[ "${address}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a octets <<< "${address}"
  for octet in "${octets[@]}"; do
    (( 10#${octet} >= 0 && 10#${octet} <= 255 )) || return 1
  done
  [[ "${prefix}" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 32 )) || return 1
  printf '%s/%s\n' "${address}" "${prefix}"
}

if [[ -z "${RECOVERY_ADMIN_CIDRS}" && -n "${SSH_CONNECTION:-}" ]]; then
  RECOVERY_ADMIN_CIDRS="${SSH_CONNECTION%% *}/32"
fi
read -r -a requested_cidrs <<< "${RECOVERY_ADMIN_CIDRS}"
(( ${#requested_cidrs[@]} > 0 )) || \
  die "Set RECOVERY_ADMIN_CIDRS to one or more trusted IPv4 CIDRs when running from the IONOS console."
ADMIN_CIDRS=()
for requested_cidr in "${requested_cidrs[@]}"; do
  ADMIN_CIDRS+=("$(normalize_cidr "${requested_cidr}")") || \
    die "Invalid trusted recovery CIDR: ${requested_cidr}"
done
[[ "${RECOVERY_SSH_PUBLIC_KEY}" =~ ^(ssh-ed25519|ssh-rsa)[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]] || \
  die "RECOVERY_SSH_PUBLIC_KEY is invalid."

password_auth=no
if [[ "${RECOVERY_ENABLE_PASSWORD_AUTH}" == "1" ]]; then
  password_auth=yes
fi

mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
grep -qxF "${RECOVERY_SSH_PUBLIC_KEY}" /root/.ssh/authorized_keys || printf '%s\n' "${RECOVERY_SSH_PUBLIC_KEY}" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

cat > /etc/ssh/sshd_config.d/10-winsvpn-recovery.conf <<EOF
Port 22
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
PermitRootLogin prohibit-password
MaxAuthTries 5
LoginGraceTime 30
PermitEmptyPasswords no
UsePAM yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding remote
AllowUsers root
EOF

sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

for cidr in "${ADMIN_CIDRS[@]}"; do
  fail2ban-client set sshd unbanip "${cidr%/*}" 2>/dev/null || true
  iptables -C INPUT -s "${cidr}" -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -s "${cidr}" -p tcp --dport 22 -j ACCEPT
  if iptables -nL WINVPN-HUB-INPUT >/dev/null 2>&1; then
    iptables -C WINVPN-HUB-INPUT -s "${cidr}" -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
      iptables -I WINVPN-HUB-INPUT 1 -s "${cidr}" -p tcp --dport 22 -j ACCEPT
  fi
done

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save || true
else
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
fi

ss -ltnp | grep -E '(:22)\b' || true
iptables -S INPUT | head -30
iptables -S WINVPN-HUB-INPUT 2>/dev/null | head -30 || true
fail2ban-client status sshd 2>/dev/null || true
echo "winsvpn-ssh-recovery-ok"
