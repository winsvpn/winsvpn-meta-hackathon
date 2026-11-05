[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('data', 'core')]
    [string]$Role,
    [Parameter(Mandatory)][string]$TransactionDir,
    [Parameter(Mandatory)][string]$DpapiKeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$encrypted = Get-Content -Raw -LiteralPath $DpapiKeyPath
$secure = ConvertTo-SecureString $encrypted
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$passphrase = ''
try {
    $passphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $probe = @'
import json, os, pathlib, shlex, subprocess, tempfile
role=os.environ['WINS_RECOVER_ROLE']
txn=pathlib.Path(os.environ['WINS_RECOVER_TXN'])
archive=txn/'state.tar.gz.enc'
member='root/node.env' if role=='data' else 'root/wins_core.env'
openssl=subprocess.Popen(['openssl','enc','-d','-aes-256-cbc','-pbkdf2','-iter','600000','-in',str(archive),'-pass','env:ROLLBACK_SECRET'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
tar=subprocess.run(['tar','-xOzf','-',member],stdin=openssl.stdout,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
if openssl.stdout: openssl.stdout.close()
openssl_rc=openssl.wait(timeout=30)
if openssl_rc or tar.returncode: raise SystemExit('rollback_extract_failed')
admin=''
for line in tar.stdout.decode('utf-8','strict').splitlines():
 fields=shlex.split(line,comments=False,posix=True)
 if len(fields)==1 and fields[0].startswith('ADMIN_TOKEN='): admin=fields[0].split('=',1)[1]
if len(admin)<32 or any(ch.isspace() for ch in admin): raise SystemExit('rollback_admin_missing')
assignment="ADMIN_TOKEN='"+admin.replace("'","'\"'\"'")+"'"
targets=[pathlib.Path('/root/node.env' if role=='data' else '/root/wins_core.env'),pathlib.Path('/root/winsvpn-secrets.env')]
for target in targets:
 st=target.stat()
 if st.st_uid!=0 or st.st_mode&0o077: raise SystemExit('unsafe_target')
 lines=target.read_text(encoding='utf-8',errors='strict').splitlines()
 replaced=False; output=[]
 for line in lines:
  if line.startswith('ADMIN_TOKEN='):
   output.append(assignment);replaced=True
  else: output.append(line)
 if not replaced: output.append(assignment)
 fd,tmp=tempfile.mkstemp(prefix='.'+target.name+'.admin.',dir=target.parent)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'w',encoding='utf-8') as handle:
   handle.write(chr(10).join(output)+chr(10));handle.flush();os.fsync(handle.fileno())
  os.replace(tmp,target)
 finally:
  pathlib.Path(tmp).unlink(missing_ok=True)
print(json.dumps({'contract':'winsvpn-live-admin-rollback-recovery-v1','ok':True,'role':role,'targets_updated':2,'token_exposed':False},separators=(',',':'),sort_keys=True))
'@
    $probeB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
    $inputB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($passphrase + "`n"))
    $wrapper = @'
import base64,json,os,pathlib,re,sqlite3,subprocess
role='__ROLE__'; txn='__TXN__'; raw=base64.b64decode('__INPUT__')
db=sqlite3.connect('file:/root/vpn_auth/vpn_users.db?mode=ro',uri=True,timeout=5);db.row_factory=sqlite3.Row
if role=='data': row=db.execute("SELECT ssh_host host,'root' user FROM nodes WHERE management_status='ok' AND (lower(name) LIKE '%spain%' OR lower(slug) LIKE '%spain%') LIMIT 1").fetchone()
else: row=db.execute("SELECT management_host host,COALESCE(NULLIF(management_user,''),'ubuntu') user FROM core_servers WHERE status='online' AND management_status='ok' LIMIT 1").fetchone()
db.close();host=str(row['host']).strip();user=str(row['user']).strip();kh=pathlib.Path('/root/vpn_auth/managed_known_hosts');env=os.environ.copy();ep=pathlib.Path('/root/vpn_auth/.env')
if ep.is_file():
 for line in ep.read_text().splitlines():
  if '=' in line and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',line.split('=',1)[0]):env[line.split('=',1)[0]]=line.split('=',1)[1]
cmd=['ssh','-i','/root/.ssh/id_rsa','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={kh}','-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no','-o','ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h']
remote="sh -c 'IFS= read -r ROLLBACK_SECRET; export ROLLBACK_SECRET; env WINS_RECOVER_ROLE="+role+" WINS_RECOVER_TXN="+txn+" python3 -c \"import base64;exec(base64.b64decode(\\\"__PROBE__\\\"))\"'"
cmd += [f'{user}@{host}',remote]
p=subprocess.run(cmd,input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=120)
if p.returncode:
 print(json.dumps({'contract':'winsvpn-live-admin-rollback-recovery-v1','ok':False,'role':role,'error_type':'remote_recovery_failed'},separators=(',',':')));raise SystemExit(1)
print(p.stdout.decode().strip())
'@
    $wrapper = $wrapper.Replace('__ROLE__', $Role).Replace('__TXN__', $TransactionDir).Replace('__INPUT__', $inputB64).Replace('__PROBE__', $probeB64)
    $wrapper | ssh -i "$env:USERPROFILE\.ssh\id_ed25519_wins_ionos" `
        -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 `
        root@<KANSAS_IP> 'python3 -'
    if ($LASTEXITCODE -ne 0) { throw "$Role live admin recovery failed." }
}
finally {
    $passphrase = ''
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
