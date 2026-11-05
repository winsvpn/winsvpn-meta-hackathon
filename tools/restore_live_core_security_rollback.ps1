[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$rollbackDirectory = '/root/winsvpn-live-remediation-core-20260721T010026Z'
$archiveSha256 = '1a2bc6d11f4366f53cc44492c380b54812e8303765acaf92d9b7ff7e2fb90e5b'
$manifestSha256 = 'a90e08d641c638166728d9ab28d2b85ce9e5c4a2ebcfc48224866ad783fd8e8d'
$keyStore = Join-Path $env:LOCALAPPDATA 'WinsVPN\InfrastructureRollbacks\core-20260721T010026Z.key.dpapi'
$sudoStore = Join-Path $env:LOCALAPPDATA 'WinsVPN\B661Observers\core-sudo.dpapi'
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$identity = Join-Path $env:USERPROFILE '.ssh\id_ed25519_wins_ionos'
$knownHosts = Join-Path $env:USERPROFILE '.ssh\known_hosts'

$rollbackSecret = $sudoPassword = ''
$sudoCipher = $sudoPlain = $null
$bstr = [IntPtr]::Zero
try {
    $secure = Get-Content -LiteralPath $keyStore -Raw | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $rollbackSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($rollbackSecret)) { throw 'Rollback key is invalid.' }

    $sudoEntropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.B661CoreObserver.v1')
    $sudoCipher = [IO.File]::ReadAllBytes($sudoStore)
    $sudoPlain = [Security.Cryptography.ProtectedData]::Unprotect(
        $sudoCipher, $sudoEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $sudoPassword = [Text.Encoding]::UTF8.GetString($sudoPlain)
    if ([string]::IsNullOrWhiteSpace($sudoPassword)) { throw 'Core sudo credential is invalid.' }

    $remote = @'
set -Eeuo pipefail
umask 077
PHASE=begin
trap 'printf "ROLLBACK_STAGE=%s\n" "$PHASE" >&2' ERR
TXN='__TXN__'
EXPECTED_ARCHIVE='__ARCHIVE__'
EXPECTED_MANIFEST='__MANIFEST__'
RESTORE_ROOT="$(mktemp -d /root/winsvpn-core-security-restore.XXXXXX)"
FAILED="$TXN/failed-security-state.$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
cleanup() { rm -rf -- "$RESTORE_ROOT"; unset ROLLBACK_SECRET; }
trap cleanup EXIT

PHASE=verify_receipt
[[ "$(sha256sum "$TXN/state.tar.gz.enc" | awk '{print $1}')" == "$EXPECTED_ARCHIVE" ]]
[[ "$(sha256sum "$TXN/files.before.sha256" | awk '{print $1}')" == "$EXPECTED_MANIFEST" ]]
( cd "$TXN" && sha256sum -c receipt.sha256 >/dev/null )
PHASE=decrypt_extract
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -in "$TXN/state.tar.gz.enc" -pass env:ROLLBACK_SECRET | tar --acls --xattrs --numeric-owner -xzf - -C "$RESTORE_ROOT"
( cd "$RESTORE_ROOT" && sha256sum -c "$TXN/files.before.sha256" >/dev/null )

PHASE=capture_failed_state
tar --acls --xattrs --numeric-owner -C / -czf "$FAILED" \
  etc/nginx usr/local/etc/xray etc/systemd/system/xray.service \
  etc/systemd/system/nginx.service.d etc/systemd/system/suricata.service.d \
  etc/systemd/system/wins-core-management-tunnel.service \
  etc/systemd/system/wins-core-sync.service etc/systemd/system/wins-core-sync.timer \
  etc/systemd/system/wins-core-performance-mode.service \
  etc/systemd/system/wins-suricata-update.service etc/systemd/system/wins-suricata-update.timer \
  etc/suricata etc/iptables etc/fail2ban etc/ssh/sshd_config etc/ssh/sshd_config.d \
  etc/docker etc/wins-core etc/amnezia root/wins_core.env root/winsvpn-defaults.env \
  root/winsvpn-secrets.env usr/local/bin 2>/dev/null || true
chmod 0600 "$FAILED" 2>/dev/null || true

PHASE=restore_full_filesystem
systemctl stop suricata.service 2>/dev/null || true
paths=(
  etc/nginx usr/local/etc/xray etc/systemd/system/xray.service
  etc/systemd/system/nginx.service.d etc/systemd/system/suricata.service.d
  etc/systemd/system/wins-core-management-tunnel.service
  etc/systemd/system/wins-core-sync.service etc/systemd/system/wins-core-sync.timer
  etc/systemd/system/wins-core-performance-mode.service
  etc/systemd/system/wins-suricata-update.service etc/systemd/system/wins-suricata-update.timer
  etc/suricata etc/iptables etc/fail2ban etc/ssh/sshd_config etc/ssh/sshd_config.d
  etc/docker etc/wins-core etc/amnezia root/wins_core.env root/winsvpn-defaults.env
  root/winsvpn-secrets.env usr/local/bin
)
for relative in "${paths[@]}"; do
  rm -rf -- "/$relative"
  if [[ -e "$RESTORE_ROOT/$relative" || -L "$RESTORE_ROOT/$relative" ]]; then
    install -d -m 0755 "$(dirname "/$relative")"
    cp -a -- "$RESTORE_ROOT/$relative" "/$relative"
  fi
done

PHASE=recover_missing_suricata_package_config
if [[ ! -s /etc/suricata/suricata.yaml ]]; then
  export DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical NEEDRESTART_MODE=a UCF_FORCE_CONFFOLD=1
  apt-get -o Dpkg::Lock::Timeout=300 -o Acquire::Retries=3 \
    -o Dpkg::Options::=--force-confmiss install --reinstall -y suricata >/dev/null
fi
[[ -s /etc/suricata/suricata.yaml ]]
PHASE=regenerate_reviewed_suricata_policy
# The encrypted preimage did not contain package-owned Suricata configuration.
# Regenerate only that reviewed security component; do not resume main().
source /root/wins_core_server_setup_ONETOUCH.sh
load_existing_core_env_for_preflight
install_core_ids_ips >/dev/null

PHASE=install_suricata_override
if ! grep -Eq -- 'ExecStart=/usr/bin/suricata .* -q 0([[:space:]]|$)' \
    /etc/systemd/system/suricata.service.d/*.conf 2>/dev/null; then
  install -d -m 0755 /etc/systemd/system/suricata.service.d
  mem_total_mb="$(( $(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo) / 1024 ))"
  suricata_max_mb=$((mem_total_mb * 50 / 100))
  ((suricata_max_mb < 768)) && suricata_max_mb=768
  ((suricata_max_mb > 1536)) && suricata_max_mb=1536
  suricata_high_mb=$((suricata_max_mb * 80 / 100))
  cat > /etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf <<EOF
[Service]
ExecStartPre=/bin/rm -f /var/run/suricata/suricata-command.socket
ExecStart=
ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0 -c /etc/suricata/suricata.yaml
MemoryHigh=${suricata_high_mb}M
MemoryMax=${suricata_max_mb}M
TasksMax=384
OOMScoreAdjust=-200
EOF
  chmod 0644 /etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf
fi
systemctl daemon-reload
PHASE=validate_suricata_nfq
suricata --build-info 2>/dev/null | grep -Ei 'NFQ' >/dev/null
PHASE=validate_suricata_config
suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1
PHASE=start_suricata
systemctl reset-failed suricata.service
systemctl start suricata.service
for _ in $(seq 1 30); do
  systemctl is-active --quiet suricata.service && suricatasc -c uptime >/dev/null 2>&1 && break
  sleep 1
done
systemctl is-active --quiet suricata.service
PHASE=verify_suricata_exec
systemctl show suricata.service -p ExecStart --value | grep -E -- '(^|[[:space:]])-q[[:space:]]+0([[:space:]]|$)' >/dev/null
suricatasc -c uptime >/dev/null 2>&1
PHASE=verify_suricata_queue
awk '$1 == 0 {found=1} END {exit(found ? 0 : 1)}' /proc/net/netfilter/nfnetlink_queue
PHASE=restore_firewall
iptables-restore --wait 10 --test < /etc/iptables/rules.v4
iptables-restore --wait 10 < /etc/iptables/rules.v4
if [[ -s /etc/iptables/rules.v6 ]]; then
  ip6tables-restore --wait 10 < /etc/iptables/rules.v6 2>/dev/null || true
fi
systemctl restart xray.service nginx.service
docker restart wins-core-ingress >/dev/null
while IFS= read -r container; do
  [[ -n "$container" ]] || continue
  docker restart "$container" >/dev/null
done < <(docker ps -a --format '{{.Names}}' | grep '^wins-core-exit-' || true)
systemctl enable --now wins-core-sync.timer >/dev/null

PHASE=verify_runtime
nfqueue_count="$(iptables-save | grep -c -- '--queue-num 0' || true)"
queue_bypass=false
iptables-save | grep -q -- '--queue-bypass' && queue_bypass=true
ipv6_disabled="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || true)"
management_active="$(systemctl is-active wins-core-management-tunnel.service 2>/dev/null || true)"
[[ "${nfqueue_count}" == 5 ]] || {
  echo "Rollback restored an unexpected NFQUEUE rule count: ${nfqueue_count}" >&2
  exit 1
}
[[ "${queue_bypass}" == false ]] || {
  echo 'Rollback restored a fail-open --queue-bypass rule.' >&2
  exit 1
}
python3 - "$nfqueue_count" "$queue_bypass" "$ipv6_disabled" "$management_active" <<'PY'
import json,sys
count=int(sys.argv[1]); bypass=sys.argv[2]=="true"
ok=count==5 and not bypass and sys.argv[3]=="1" and sys.argv[4]=="active"
print(json.dumps({
 "contract":"winsvpn-core-full-rollback-v1","ok":ok,
 "suricata_active":True,"suricata_queue0":True,"suricata_control":True,
 "nfqueue_rule_count":count,"queue_bypass":bypass,
 "ipv6_disabled":sys.argv[3]=="1","management_active":sys.argv[4]=="active"
},sort_keys=True,separators=(",",":")))
raise SystemExit(0 if ok else 1)
PY
'@
    $remote = $remote.Replace('__TXN__', $rollbackDirectory).Replace('__ARCHIVE__', $archiveSha256).Replace('__MANIFEST__', $manifestSha256)
    $payload = "$sudoPassword`n$rollbackSecret`n$remote"
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
    try {
        $payloadB64 = [Convert]::ToBase64String($payloadBytes)
        $wrapper = @"
import base64,json,os,pathlib,re,sqlite3,subprocess
raw=base64.b64decode('$payloadB64')
password,remote_input=raw.split(b'\n',1)
db=sqlite3.connect('file:/root/vpn_auth/vpn_users.db?mode=ro',uri=True,timeout=5);db.row_factory=sqlite3.Row
rows=db.execute("SELECT management_host host,COALESCE(NULLIF(management_user,''),'ubuntu') user FROM core_servers WHERE status='online' AND management_status='ok' ORDER BY core_id").fetchall();db.close()
if len(rows)!=1: raise SystemExit('managed_core_not_unique')
host=str(rows[0]['host']).strip().lower();user=str(rows[0]['user']).strip().lower();kh=pathlib.Path('/root/vpn_auth/managed_known_hosts')
env=os.environ.copy();ep=pathlib.Path('/root/vpn_auth/.env')
if ep.is_file():
 for line in ep.read_text().splitlines():
  if '=' in line and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',line.split('=',1)[0]):env[line.split('=',1)[0]]=line.split('=',1)[1]
cmd=['ssh','-i','/root/.ssh/id_rsa','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={kh}','-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no','-o','ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h',f'{user}@{host}',"sudo -S -p '' -- sh -c 'IFS= read -r ROLLBACK_SECRET; export ROLLBACK_SECRET; bash -s'"]
p=subprocess.run(cmd,input=password+b'\n'+remote_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=300)
if p.returncode!=0:
 text=p.stderr.decode('utf-8','replace');m=re.findall(r'ROLLBACK_STAGE=([a-z_]+)',text)
 print(json.dumps({'contract':'winsvpn-core-security-rollback-v1','ok':False,'error_type':'remote_restore_failed','stage':m[-1] if m else 'unknown','returncode':p.returncode},sort_keys=True,separators=(',',':')));raise SystemExit(1)
print(p.stdout.decode('utf-8','strict').strip())
"@
        $wrapper | & $ssh -i $identity -o BatchMode=yes -o StrictHostKeyChecking=yes `
            -o "UserKnownHostsFile=$knownHosts" -o GlobalKnownHostsFile=NUL -o UpdateHostKeys=no `
            -o ConnectTimeout=12 root@<KANSAS_IP> 'python3 -'
        if ($LASTEXITCODE -ne 0) { throw 'Core security rollback relay failed.' }
    }
    finally {
        [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
    }
}
finally {
    $rollbackSecret = $sudoPassword = ''
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($null -ne $sudoPlain) { [Array]::Clear($sudoPlain, 0, $sudoPlain.Length) }
    if ($null -ne $sudoCipher) { [Array]::Clear($sudoCipher, 0, $sudoCipher.Length) }
}
