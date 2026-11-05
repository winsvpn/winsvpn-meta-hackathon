[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('data', 'core')]
    [string]$Role
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

function ConvertTo-BashAssignment {
    param([string]$Name, [AllowEmptyString()][string]$Value)
    if ($Name -notmatch '^[A-Z][A-Z0-9_]*$' -or $Value -match "[\r\n]") {
        throw "Unsafe environment assignment for $Name."
    }
    $quoted = $Value.Replace("'", "'`"'`"'")
    return "$Name='$quoted'"
}

$preseedPath = Join-Path $env:LOCALAPPDATA 'WinsVPN\Deployment\preseed.dpapi'
$entropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.DeploymentPreseed.v1')
$cipher = $plain = $secretBytes = $null
$json = ''
try {
    $cipher = [IO.File]::ReadAllBytes($preseedPath)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $cipher, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $json = [Text.Encoding]::UTF8.GetString($plain)
    $payload = $json | ConvertFrom-Json
    if ([int]$payload.schema -ne 1) { throw 'Unsupported deployment preseed schema.' }
    $values = $payload.values
    # L41: no ADMIN_TOKEN and no Cloudflare credential is ever pushed to a data
    # plane or Core. A Core role file is therefore empty, and a refresh drops
    # any fleet credential an older deployment left in the secrets file.
    $selected = if ($Role -eq 'data') {
        [ordered]@{
            RCLONE_CONFIG_B64 = [string]$values.RCLONE_CONFIG_B64
            REQUIRE_REMOTE_BACKUP = [string]$values.REQUIRE_REMOTE_BACKUP
            DNS4EU_COMMERCIAL_DOH_URL = if ($null -ne $values.PSObject.Properties['DNS4EU_COMMERCIAL_DOH_URL']) {
                [string]$values.DNS4EU_COMMERCIAL_DOH_URL
            }
            else { '' }
        }
    }
    else {
        [ordered]@{}
    }
    $lines = foreach ($entry in $selected.GetEnumerator()) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            ConvertTo-BashAssignment -Name ([string]$entry.Key) -Value ([string]$entry.Value)
        }
    }
    $secretBytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    $encoded = [Convert]::ToBase64String($secretBytes)

    $sudoPassword = ''
    $sudoPlain = $sudoCipher = $null
    try {
        if ($Role -eq 'core') {
            $sudoEntropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.B661CoreObserver.v1')
            $sudoCipher = [IO.File]::ReadAllBytes(
                (Join-Path $env:LOCALAPPDATA 'WinsVPN\B661Observers\core-sudo.dpapi'))
            $sudoPlain = [Security.Cryptography.ProtectedData]::Unprotect(
                $sudoCipher, $sudoEntropy,
                [Security.Cryptography.DataProtectionScope]::CurrentUser)
            $sudoPassword = [Text.Encoding]::UTF8.GetString($sudoPlain)
        }

        $sudoEncoded = if ($Role -eq 'core') {
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sudoPassword))
        }
        else { '' }
        $wrapper = @'
import base64,json,os,pathlib,re,sqlite3,subprocess
role='__ROLE__'; content=base64.b64decode('__CONTENT__'); sudo_password=base64.b64decode('__SUDO__')
db=sqlite3.connect('file:/root/vpn_auth/vpn_users.db?mode=ro',uri=True,timeout=5);db.row_factory=sqlite3.Row
if role=='data':
 row=db.execute("SELECT ssh_host host,'root' user FROM nodes WHERE management_status='ok' AND (lower(name) LIKE '%spain%' OR lower(slug) LIKE '%spain%') LIMIT 1").fetchone()
else:
 row=db.execute("SELECT management_host host,COALESCE(NULLIF(management_user,''),'ubuntu') user FROM core_servers WHERE status='online' AND management_status='ok' LIMIT 1").fetchone()
db.close()
if not row: raise SystemExit('managed_target_missing')
host=str(row['host']).strip().lower(); user=str(row['user']).strip().lower(); kh=pathlib.Path('/root/vpn_auth/managed_known_hosts'); env=os.environ.copy(); ep=pathlib.Path('/root/vpn_auth/.env')
if ep.is_file():
 for line in ep.read_text().splitlines():
  if '=' in line and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',line.split('=',1)[0]): env[line.split('=',1)[0]]=line.split('=',1)[1]
cmd=['ssh','-i','/root/.ssh/id_rsa','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={kh}','-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no']
if not re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',host): cmd+=['-o','ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h']
remote=r'''import json,os,pathlib,re,shlex,sys,tempfile
role=os.environ.get('WINS_REFRESH_ROLE','')
content=sys.stdin.buffer.read()
persisted=pathlib.Path('/root/node.env' if role=='data' else '/root/wins_core.env')
st=persisted.stat()
if st.st_uid!=0 or st.st_mode&0o077:
 raise SystemExit('unsafe_persisted_role_environment')
if re.search(rb'(?m)^(export[ \t]+)?(ADMIN_TOKEN|CLOUDFLARE_[A-Z_]*|CF_API_TOKEN)=',content):
 raise SystemExit('fleet_credential_in_role_content')
if not content.endswith(b'\n'):content+=b'\n'
names=[]
for line in content.decode('utf-8','strict').splitlines():
 m=re.match(r'^([A-Z][A-Z0-9_]*)=',line)
 if m:names.append(m.group(1))
fd,tmp=tempfile.mkstemp(prefix='.winsvpn-secrets.',dir='/root')
try:
 os.fchmod(fd,0o600);os.write(fd,content);os.fsync(fd);os.close(fd);fd=-1
 os.replace(tmp,'/root/winsvpn-secrets.env')
finally:
 if fd>=0:os.close(fd)
 pathlib.Path(tmp).unlink(missing_ok=True)
st=pathlib.Path('/root/winsvpn-secrets.env').stat()
print(json.dumps({'contract':'winsvpn-live-role-secret-refresh-v1','ok':st.st_uid==0 and st.st_mode&0o077==0,'owner_only':st.st_uid==0 and st.st_mode&0o077==0,'name_count':len(names)},separators=(',',':'),sort_keys=True))'''
if role=='core':
 cmd += [f'{user}@{host}',"sudo -S -p '' -- env WINS_REFRESH_ROLE=core python3 -c "+__import__('shlex').quote(remote)]
 input_bytes=sudo_password+b'\n'+content
else:
 cmd += [f'{user}@{host}',"env WINS_REFRESH_ROLE=data python3 -c "+__import__('shlex').quote(remote)]
 input_bytes=content
p=subprocess.run(cmd,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=90)
if p.returncode!=0:
 err=p.stderr.decode('utf-8','replace').lower();kind='sudo_authentication_failed' if 'incorrect password' in err or 'sorry, try again' in err else 'remote_refresh_failed'
 print(json.dumps({'contract':'winsvpn-live-role-secret-refresh-v1','ok':False,'role':role,'error_type':kind},separators=(',',':'),sort_keys=True));raise SystemExit(1)
result=json.loads(p.stdout.decode('utf-8','strict'));result['role']=role;print(json.dumps(result,separators=(',',':'),sort_keys=True))
'@
        $wrapper = $wrapper.Replace('__ROLE__', $Role).Replace('__CONTENT__', $encoded).Replace('__SUDO__', $sudoEncoded)
        $wrapper | ssh -i "$env:USERPROFILE\.ssh\id_ed25519_wins_ionos" `
            -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 `
            root@<KANSAS_IP> 'python3 -'
        if ($LASTEXITCODE -ne 0) { throw "$Role secret refresh failed." }
    }
    finally {
        $sudoPassword = ''
        if ($null -ne $sudoPlain) { [Array]::Clear($sudoPlain, 0, $sudoPlain.Length) }
        if ($null -ne $sudoCipher) { [Array]::Clear($sudoCipher, 0, $sudoCipher.Length) }
    }
}
finally {
    $json = ''
    if ($null -ne $secretBytes) { [Array]::Clear($secretBytes, 0, $secretBytes.Length) }
    if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($null -ne $cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
}
