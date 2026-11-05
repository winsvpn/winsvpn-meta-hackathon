[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('data', 'core')]
    [string]$Role
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$keyRoot = Join-Path $env:LOCALAPPDATA 'WinsVPN\InfrastructureRollbacks'
New-Item -ItemType Directory -Force -Path $keyRoot | Out-Null
$keyPath = Join-Path $keyRoot "$Role-$stamp.key.dpapi"
$keyBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($keyBytes) }
finally { $random.Dispose() }
$passphrase = [Convert]::ToBase64String($keyBytes)
$securePassphrase = ConvertTo-SecureString $passphrase -AsPlainText -Force
[IO.File]::WriteAllText(
    $keyPath,
    (ConvertFrom-SecureString $securePassphrase),
    [Text.UTF8Encoding]::new($false)
)

$remote = @'
set -Eeuo pipefail
umask 077
STAGE=initial
trap 'printf "ROLLBACK_STAGE=%s\n" "$STAGE" >&2' ERR
ROLE='__ROLE__'
STAMP='__STAMP__'
TXN="/root/winsvpn-live-remediation-${ROLE}-${STAMP}"
install -d -m 0700 "$TXN"
if [[ "$ROLE" == data ]]; then
  paths=(
    /etc/nginx /usr/local/etc/xray /etc/systemd/system/xray.service
    /etc/systemd/system/nginx.service.d /etc/systemd/system/suricata.service.d
    /etc/systemd/system/wins-node-management-tunnel.service
    /etc/systemd/system/wins-node-register.service /etc/systemd/system/wins-node-register.timer
    /etc/systemd/system/wins-node-canary.service /etc/systemd/system/wins-node-canary.timer
    /etc/systemd/system/wins-node-backup.service /etc/systemd/system/wins-node-backup.timer
    /etc/systemd/system/wins-edge-hardening.service
    /etc/systemd/system/wins-suricata-update.service /etc/systemd/system/wins-suricata-update.timer
    /etc/suricata /etc/iptables /etc/fail2ban /etc/ssh/sshd_config /etc/ssh/sshd_config.d
    /etc/docker /etc/winsvpn /etc/amnezia /root/node.env /root/winsvpn-defaults.env
    /root/winsvpn-secrets.env /usr/local/bin /opt/AdGuardHome/AdGuardHome.yaml
  )
else
  paths=(
    /etc/nginx /usr/local/etc/xray /etc/systemd/system/xray.service
    /etc/systemd/system/nginx.service.d /etc/systemd/system/suricata.service.d
    /etc/systemd/system/wins-core-management-tunnel.service
    /etc/systemd/system/wins-core-sync.service /etc/systemd/system/wins-core-sync.timer
    /etc/systemd/system/wins-core-performance-mode.service
    /etc/systemd/system/wins-suricata-update.service /etc/systemd/system/wins-suricata-update.timer
    /etc/suricata /etc/iptables /etc/fail2ban /etc/ssh/sshd_config /etc/ssh/sshd_config.d
    /etc/docker /etc/wins-core /etc/amnezia /root/wins_core.env /root/winsvpn-defaults.env
    /root/winsvpn-secrets.env /usr/local/bin
  )
fi
core_expected_nfqueue_rules() {
  # Mirrors capture_core_package_security_preimage in the Core installer: one
  # queue0 rule per configured stealth transport while Core IDS/IPS is on, and
  # none when it is off. Read the values the installer persisted to its env
  # file without sourcing it; that file is written with printf %q, which
  # escapes the commas in the transport list.
  local env_file="$1" ids transports route count=0
  local allowed='^[0-9A-Za-z:,\]+$'
  [[ -f "$env_file" && ! -L "$env_file" && "$(stat -c '%u' "$env_file")" == 0 ]] || return 1
  [[ -z "$(find "$env_file" -prune -perm /022 -print -quit)" ]] || return 1
  ids="$(sed -n 's/^INSTALL_CORE_IDS_IPS=//p' "$env_file" | tail -n 1)"
  transports="$(sed -n 's/^CORE_STEALTH_TRANSPORTS=//p' "$env_file" | tail -n 1)"
  [[ "$ids" == 0 || "$ids" == 1 ]] || return 1
  [[ "$transports" =~ $allowed ]] || return 1
  transports="${transports//\\/}"
  if [[ "$ids" == 1 ]]; then
    while IFS= read -r route; do
      [[ -n "$route" ]] || continue
      count=$((count + 1))
    done < <(tr ',' '\n' <<<"$transports")
  fi
  printf '%s\n' "$count"
}
existing=()
for path in "${paths[@]}"; do
  [[ -e "$path" || -L "$path" ]] && existing+=("${path#/}")
done
if [[ "$ROLE" == core ]]; then
  STAGE=core_security_preimage
  security="$TXN/core-package-security-preimage"
  config=/etc/suricata/suricata.yaml
  override=/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf
  vendor=/lib/systemd/system/suricata.service
  [[ -e "$vendor" ]] || vendor=/usr/lib/systemd/system/suricata.service
  for required in "$config" "$override" "$vendor"; do
    [[ -f "$required" && ! -L "$required" && "$(stat -c '%u' "$required")" == 0 ]] || {
      echo "Core rollback capture requires a safe package-security file: $required" >&2
      exit 1
    }
    [[ -z "$(find "$required" -prune -perm /022 -print -quit)" ]] || {
      echo "Core rollback capture refused writable package-security file: $required" >&2
      exit 1
    }
  done
  grep -Eq -- '^ExecStart=/usr/bin/suricata .* -q 0([[:space:]]|$)' "$override" || {
    echo 'Core rollback capture requires the root-owned Suricata -q 0 override.' >&2
    exit 1
  }
  expected_nfqueue_rules="$(core_expected_nfqueue_rules /root/wins_core.env)" || {
    echo 'Core rollback capture cannot derive the NFQUEUE policy from /root/wins_core.env (INSTALL_CORE_IDS_IPS, CORE_STEALTH_TRANSPORTS).' >&2
    exit 1
  }
  [[ "$expected_nfqueue_rules" =~ ^[1-9][0-9]*$ ]] || {
    echo 'Core rollback capture requires Core IDS/IPS with at least one queued stealth transport.' >&2
    exit 1
  }
  install -d -m 0700 "$security"
  install -m 0600 "$config" "$security/suricata.yaml"
  install -m 0600 "$override" "$security/30-wins-inline-ips.conf"
  install -m 0600 "$vendor" "$security/suricata.vendor.service"
  iptables-save > "$security/live.rules.v4"
  chmod 0600 "$security/live.rules.v4"
  nfqueue_count="$(grep -c -- '--queue-num 0' "$security/live.rules.v4" || true)"
  [[ "$nfqueue_count" == "$expected_nfqueue_rules" ]] || {
    echo "Core rollback capture requires exactly $expected_nfqueue_rules live NFQUEUE queue0 rules; found $nfqueue_count." >&2
    exit 1
  }
  ! grep -q -- '--queue-bypass' "$security/live.rules.v4" || {
    echo 'Core rollback capture refused a fail-open --queue-bypass rule.' >&2
    exit 1
  }
  ip6tables-save > "$security/live.rules.v6" 2>/dev/null || true
  chmod 0600 "$security/live.rules.v6" 2>/dev/null || true
  # Same contract the installer writes, so restore_core_package_security_preimage
  # can validate this snapshot against the count it was captured under.
  {
    printf 'contract=winsvpn-core-package-security-preimage-v1\n'
    printf 'state=protected\n'
    printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'expected_nfqueue_rules=%s\n' "$expected_nfqueue_rules"
    printf 'queue_bypass_allowed=0\n'
    printf 'config_path=%s\n' "$config"
    printf 'override_path=%s\n' "$override"
    printf 'vendor_path=%s\n' "$vendor"
  } > "$security/contract.env"
  chmod 0600 "$security/contract.env"
  (cd "$security" && sha256sum ./* > files.sha256)
  chmod 0600 "$security/files.sha256"
  existing+=("${security#/}")
fi
STAGE=hash_manifest
( cd /; find "${existing[@]}" -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum ) >"$TXN/files.before.sha256"
STAGE=state_manifest
{
  printf 'contract=winsvpn-live-remediation-rollback-v1\n'
  printf 'role=%s\n' "$ROLE"
  printf 'created_utc=%s\n' "$STAMP"
  printf 'xray_unit=%s\n' "$(systemctl is-active xray.service 2>/dev/null || true)"
  printf 'nginx_unit=%s\n' "$(systemctl is-active nginx.service 2>/dev/null || true)"
  printf 'suricata_unit=%s\n' "$(systemctl is-active suricata.service 2>/dev/null || true)"
  printf 'xray_version=%s\n' "$(xray version 2>/dev/null | awk 'NR==1{print $2}')"
  if [[ "$ROLE" == data ]]; then
    printf 'awg_container=%s\n' "$(docker inspect -f '{{.State.Running}}' amnezia-awg2 2>/dev/null || true)"
    printf 'awg_iface=%s\n' "$(docker exec amnezia-awg2 awg show interfaces 2>/dev/null || true)"
    printf 'udp_listener=%s\n' "$(ss -H -lun | awk '$4 ~ /:9110$/ || $5 ~ /:9110$/ {found=1} END{print found ? "true":"false"}')"
  else
    printf 'awg_container=%s\n' "$(docker inspect -f '{{.State.Running}}' wins-core-ingress 2>/dev/null || true)"
    printf 'awg_iface=%s\n' "$(docker exec wins-core-ingress awg show interfaces 2>/dev/null || true)"
    printf 'udp_listener=%s\n' "$(ss -H -lun | awk '$4 ~ /:9210$/ || $5 ~ /:9210$/ {found=1} END{print found ? "true":"false"}')"
  fi
} >"$TXN/state.before"
STAGE=tar
tar --acls --xattrs --numeric-owner -C / -czf "$TXN/state.tar.gz" "${existing[@]}"
STAGE=encrypt
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 \
  -in "$TXN/state.tar.gz" -out "$TXN/state.tar.gz.enc" -pass env:ROLLBACK_SECRET
STAGE=decrypt_verify
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -in "$TXN/state.tar.gz.enc" -pass env:ROLLBACK_SECRET | tar -tzf - >/dev/null
if command -v shred >/dev/null 2>&1; then
  shred -u "$TXN/state.tar.gz"
else
  rm -f "$TXN/state.tar.gz"
fi
STAGE=receipt
sha256sum "$TXN/state.tar.gz.enc" "$TXN/files.before.sha256" "$TXN/state.before" >"$TXN/receipt.sha256"
chmod 0700 "$TXN"
chmod 0600 "$TXN"/*
archive_sha="$(sha256sum "$TXN/state.tar.gz.enc" | awk '{print $1}')"
manifest_sha="$(sha256sum "$TXN/files.before.sha256" | awk '{print $1}')"
python3 - "$ROLE" "$TXN" "$archive_sha" "$manifest_sha" <<'PY'
import json, sys
print(json.dumps({
    "contract": "winsvpn-live-remediation-rollback-v1",
    "ok": True,
    "role": sys.argv[1],
    "transaction_dir": sys.argv[2],
    "archive_sha256": sys.argv[3],
    "manifest_sha256": sys.argv[4],
    "encrypted": True,
    "root_only": True,
}, separators=(",", ":"), sort_keys=True))
PY
unset ROLLBACK_SECRET
'@
$remote = $remote.Replace('__ROLE__', $Role).Replace('__STAMP__', $stamp)

try {
    if ($Role -eq 'core') {
        $sudoStore = Join-Path $env:LOCALAPPDATA 'WinsVPN\B661Observers\core-sudo.dpapi'
        $entropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.B661CoreObserver.v1')
        $sudoBytes = $null
        $sudoPassword = ''
        try {
            $protected = [IO.File]::ReadAllBytes($sudoStore)
            $sudoBytes = [Security.Cryptography.ProtectedData]::Unprotect(
                $protected,
                $entropy,
                [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            $sudoPassword = [Text.Encoding]::UTF8.GetString($sudoBytes)
            $payload = "$sudoPassword`n$passphrase`n$remote"
            $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
            $wrapper = @"
import base64,json,os,pathlib,re,sqlite3,subprocess
raw=base64.b64decode('$payloadB64')
password,remote_input=raw.split(b'\n',1)
db=sqlite3.connect('file:/root/vpn_auth/vpn_users.db?mode=ro',uri=True,timeout=5)
db.row_factory=sqlite3.Row
rows=db.execute("SELECT management_host AS host,COALESCE(NULLIF(management_user,''),'ubuntu') AS user FROM core_servers WHERE status='online' AND management_status='ok' ORDER BY core_id").fetchall()
db.close()
if len(rows)!=1: raise SystemExit('managed_core_not_unique')
host=str(rows[0]['host']).strip().lower(); user=str(rows[0]['user']).strip().lower()
kh=pathlib.Path('/root/vpn_auth/managed_known_hosts')
env=os.environ.copy()
p=pathlib.Path('/root/vpn_auth/.env')
if p.is_file():
  for line in p.read_text().splitlines():
    if '=' in line and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',line.split('=',1)[0]):
      env[line.split('=',1)[0]]=line.split('=',1)[1]
cmd=['ssh','-i','/root/.ssh/id_rsa','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={kh}','-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no','-o','ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h',f'{user}@{host}',"sudo -S -p '' -- sh -c 'IFS= read -r ROLLBACK_SECRET; export ROLLBACK_SECRET; bash -s'"]
completed=subprocess.run(cmd,input=password+b'\n'+remote_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=300)
if completed.returncode!=0:
  err=completed.stderr.decode('utf-8','replace').lower()
  kind='sudo_authentication_failed' if ('sorry, try again' in err or 'incorrect password' in err) else 'rollback_capture_failed'
  stage='unknown'; m=re.findall(r'rollback_stage=([a-z_]+)',err)
  if m: stage=m[-1]
  print(json.dumps({'ok':False,'role':'core','error_type':kind,'stage':stage,'returncode':completed.returncode},separators=(',',':')))
  raise SystemExit(1)
print(completed.stdout.decode().strip())
"@
            $output = $wrapper | ssh -i "$env:USERPROFILE\.ssh\id_ed25519_wins_ionos" `
                -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 `
                root@<KANSAS_IP> 'python3 -'
            if ($LASTEXITCODE -ne 0) {
                Write-Output $output
                throw 'Core rollback relay failed.'
            }
            Write-Output $output
        }
        finally {
            if ($null -ne $sudoBytes) { [Array]::Clear($sudoBytes, 0, $sudoBytes.Length) }
            $sudoPassword = ''
        }
    }
    else {
        $payload = "$passphrase`n$remote"
        $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
        $wrapper = @"
import base64,json,os,pathlib,re,sqlite3,subprocess
db=sqlite3.connect('file:/root/vpn_auth/vpn_users.db?mode=ro',uri=True,timeout=5)
db.row_factory=sqlite3.Row
row=db.execute("SELECT ssh_host AS host FROM nodes WHERE status='online' AND management_status='ok' ORDER BY slug LIMIT 1").fetchone()
db.close()
if not row: raise SystemExit('managed_target_unavailable')
host=str(row['host']).strip().lower()
kh=pathlib.Path('/root/vpn_auth/managed_known_hosts')
env=os.environ.copy()
for p in (pathlib.Path('/root/vpn_auth/.env'),):
  if p.is_file():
    for line in p.read_text().splitlines():
      if '=' in line and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',line.split('=',1)[0]):
        env[line.split('=',1)[0]]=line.split('=',1)[1]
cmd=['ssh','-i','/root/.ssh/id_rsa','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={kh}','-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no']
if not re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',host):
  cmd+=['-o','ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h']
cmd+=['root@'+host,"sh -c 'IFS= read -r ROLLBACK_SECRET; export ROLLBACK_SECRET; bash -s'"]
p=subprocess.run(cmd,input=base64.b64decode('$payloadB64'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=300)
if p.returncode!=0:
  err=p.stderr.decode('utf-8','replace').lower()
  detail='unknown'
  for name,needle in (('tar_changed','file changed as we read'),('tar_missing','cannot stat'),('permission','permission denied'),('disk_full','no space left'),('openssl_bad_decrypt','bad decrypt'),('openssl_unknown_option','unknown option'),('openssl_help','use -help for summary'),('openssl_password','error reading password'),('missing_file','no such file or directory'),('broken_pipe','broken pipe')):
    if needle in err: detail=name; break
  stage='unknown'
  m=re.findall(r'rollback_stage=([a-z_]+)',err)
  if m: stage=m[-1]
  print(json.dumps({'ok':False,'role':'data','error_type':'rollback_capture_failed','diagnostic':detail,'stage':stage,'returncode':p.returncode},separators=(',',':')))
  raise SystemExit(1)
print(p.stdout.decode().strip())
"@
        $output = $wrapper | ssh -i "$env:USERPROFILE\.ssh\id_ed25519_wins_ionos" `
            -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 `
            root@<KANSAS_IP> 'python3 -'
        if ($LASTEXITCODE -ne 0) {
            Write-Output $output
            throw 'Data rollback relay failed.'
        }
        Write-Output $output
    }
    Write-Output "local_dpapi_key=$keyPath"
}
finally {
    [Array]::Clear($keyBytes, 0, $keyBytes.Length)
    $passphrase = ''
}
