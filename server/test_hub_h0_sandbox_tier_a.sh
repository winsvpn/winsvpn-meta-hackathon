#!/usr/bin/env bash
# H0 Tier A (design v17 sections 3.2 and 5.2): D1 to D4 from a process
# sandboxed exactly as wins-hub.service is.
#
# The context is a transient unit started with every [Service] sandbox property
# of the hub unit the installer renders (same user, capability set, runtime
# allow-list, read-only and writable paths). From inside it:
#   D1  starting a transient unit fails, so the stand-in key cannot be read
#       through one; the manager's private socket and the system bus are gone.
#   D2  connect() to every socket under the host's /run fails, except the
#       allow-listed ones.
#   D3  root's authorized_keys and its login hooks cannot be written; the
#       app's own SSH working directory can. The hub sshd policy, when it is
#       installed here, forbids the hooks.
#   D4  the capability sets are empty, an iptables write fails, and the
#       stand-in key file (another user's 0400 file) fails with EACCES.
# The unit-text and app-level checks for D1 to D8 are in
# server/test_hub_h0_hardening.py, which runs anywhere.
#
# Needs Linux, systemd as PID 1, root, python3 and iptables. Anywhere else it
# prints SKIP and exits 77. Never run it on a production hub: it creates and
# removes a scratch directory under /var/lib and probes the local firewall.
#
# usage: server/test_hub_h0_sandbox_tier_a.sh [repo_root]
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HUB="${ROOT}/server/wins_control_plane_setup_ONETOUCH.sh"
failures=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failures=$((failures + 1)); }
skip() { printf 'SKIP %s\n' "$*"; exit 77; }

[[ "$(uname -s)" == "Linux" ]] || skip "not Linux"
[[ "$(id -u)" == "0" ]] || skip "not root"
[[ "$(cat /proc/1/comm 2>/dev/null)" == "systemd" ]] || skip "systemd is not PID 1"
command -v systemd-run >/dev/null 2>&1 || skip "no systemd-run"
command -v python3 >/dev/null 2>&1 || skip "no python3"
command -v iptables >/dev/null 2>&1 || skip "no iptables"
[[ -r "${HUB}" ]] || { fail "cannot read ${HUB}"; exit 1; }

WORK="$(mktemp -d /var/lib/wins-h0-tier-a.XXXXXX)"
created=()
created_files=()
resolver_pid=""
cleanup() {
  local dir
  [[ -z "${resolver_pid}" ]] || kill "${resolver_pid}" 2>/dev/null || true
  iptables -w 5 -X WINS-H0-TIER-A >/dev/null 2>&1 || true
  for dir in "${created_files[@]}"; do rm -f -- "${dir}"; done
  rm -rf -- "${WORK}"
  for dir in "${created[@]}"; do rmdir -- "${dir}" 2>/dev/null || true; done
}
trap cleanup EXIT

# The hub unit's [Service] properties, rendered as the installer renders them,
# one KEY=VALUE per line. Process and start settings are left out; every
# sandbox property is kept.
python3 -I - "${HUB}" > "${WORK}/properties" <<'PY' || { fail "cannot render the hub unit"; exit 1; }
import re, sys
source = open(sys.argv[1], encoding="utf-8").read()
header = 'cat > "${SERVICE_FILE}" <<EOF\n'
body = source[source.index(header) + len(header):]
body = body[:body.index("\nEOF\n") + 1]
app = re.search(r'^APP_DIR="([^"]*)"$', source, re.M).group(1)
values = {"APP_DIR": app, "VENV_DIR": app + "/venv", "ENV_FILE": "/root/vpn_auth.env",
          "LEGACY_ENV_FILE": app + "/.env", "bind_host": "127.0.0.1"}
body = re.sub(r"\$\{([A-Za-z_]+)\}", lambda m: values.get(m.group(1), m.group(0)), body)
skip = {"ExecStart", "Restart", "RestartSec", "WorkingDirectory", "EnvironmentFile", "User"}
section = ""
for line in body.splitlines():
    line = line.strip()
    if line.startswith("["):
        section = line
        continue
    if section != "[Service]" or not line or line.startswith("#") or "=" not in line:
        continue
    key = line.split("=", 1)[0]
    if key not in skip:
        print(line)
PY
grep -qx 'CapabilityBoundingSet=' "${WORK}/properties" || fail "rendered hub unit is not the H0 unit (CapabilityBoundingSet)"

# Every writable exception and every allow-listed directory must exist before
# the context starts, as the installer arranges for the real unit.
while IFS= read -r path; do
  path="${path#-}"
  [[ -n "${path}" && ! -e "${path}" ]] || continue
  mkdir -p -- "${path}" && created+=("${path}")
done < <(sed -n 's/^\(ReadWritePaths\|BindReadOnlyPaths\|ReadOnlyPaths\)=//p' "${WORK}/properties" | tr ' ' '\n' | grep -v '\.conf$')

# Stand-in for the signer's key file: another user's 0400 file (design 3.4).
install -d -m 0755 "${WORK}/signer"
printf 'h0-tier-a-stand-in-key\n' > "${WORK}/signer/g2.ed25519.pem"
chown nobody "${WORK}/signer/g2.ed25519.pem" && chmod 0400 "${WORK}/signer/g2.ed25519.pem"

find /run -type s 2>/dev/null | sort > "${WORK}/sockets" || { fail "socket inventory failed"; exit 1; }
python3 -I - > "${WORK}/abstract-sockets" <<'PY'
from pathlib import Path
for row in Path('/proc/net/unix').read_text().splitlines()[1:]:
    fields = row.split(None, 7)
    if len(fields) == 8 and fields[7].startswith('@'):
        print(fields[4], fields[7])
PY
args=()
while IFS= read -r property; do args+=(-p "${property}"); done < "${WORK}/properties"

cat > "${WORK}/probe.py" <<'PY'
import errno, os, socket, subprocess, sys
key, sockets = sys.argv[1], sys.argv[2]
allowed = ("/run/litestream/", "/run/wins-hub-spa-window/")
def report(ok, text):
    print(("PASS " if ok else "FAIL ") + text, flush=True)
def can_connect(path):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        s = socket.socket(socket.AF_UNIX, kind)
        s.settimeout(2)
        try:
            s.connect(path)
            return True
        except OSError:
            pass
        finally:
            s.close()
    return False
def can_write(path):
    try:
        with open(path, "a"):
            pass
        return True
    except OSError:
        return False

# D1
try:
    run = subprocess.run(["systemd-run", "--wait", "--pipe", "--quiet", "cat", key],
                         capture_output=True, text=True, timeout=30)
    report(run.returncode != 0 and "stand-in" not in run.stdout,
           f"D1 a transient unit cannot be started from the hub context (rc={run.returncode})")
except FileNotFoundError:
    report(True, "D1 systemd-run is not reachable from the hub context")
for path in ("/run/systemd/private", "/run/dbus/system_bus_socket"):
    report(not can_connect(path), f"D1 {path} is unreachable")

# D2
listed = [line.strip() for line in open(sockets, encoding="utf-8") if line.strip()]
for path in listed:
    if path.startswith(allowed):
        report(can_connect(path), f"D2 allow-listed {path} stays reachable")
    else:
        report(not can_connect(path), f"D2 broker socket {path} is unreachable")
report(bool(listed), f"D2 enumerated {len(listed)} host sockets under /run")
for line in open(os.path.join(os.path.dirname(sockets), 'abstract-sockets'), encoding='utf-8'):
    kind, name = line.rstrip('\n').split(' ', 1)
    endpoint = '\0' + name[1:]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM if int(kind, 16) == 2 else socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(endpoint)
        report(False, f'D2 abstract broker {name} is reachable')
    except OSError:
        report(True, f'D2 abstract broker {name} is unreachable')
    finally:
        s.close()

# D3
for path in ("/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2", "/root/.ssh/rc",
             "/root/.ssh/environment", "/root/.bashrc", "/root/.profile", "/etc/ssh/sshrc"):
    report(not can_write(path), f"D3 {path} is not writable")
os.makedirs("/var/lib/wins-hub-ssh/cm", mode=0o700, exist_ok=True)
probe = "/var/lib/wins-hub-ssh/cm/.h0-tier-a"
report(can_write(probe), "D3 the app's own SSH working directory is writable")
try:
    os.unlink(probe)
except OSError:
    pass

# D3: test the hub's actual identity, without an agent or fallback identity.
if os.path.exists('/root/.ssh/id_rsa'):
    login = subprocess.run(['ssh', '-vv', '-o', 'BatchMode=yes', '-o', 'IdentityAgent=none',
                            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=no',
                            '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5',
                            '-i', '/root/.ssh/id_rsa', 'root@127.0.0.1', 'true'],
                           capture_output=True, text=True, timeout=30)
    report(login.returncode != 0 and 'Authenticated to ' not in login.stderr,
           f'D3 direct root authentication with the hub key fails (rc={login.returncode})')
else:
    report(False, 'D3 direct authentication is unverified because the hub identity is absent')
report(not can_write('/root/vpn_auth/venv/bin/.h0-tier-a'), 'D7 the installer venv is not writable')

# D4
status = dict(line.split(":", 1) for line in open("/proc/self/status", encoding="ascii") if ":" in line)
for field in ("CapBnd", "CapEff", "CapPrm", "CapAmb"):
    report(int(status[field].strip(), 16) == 0, f"D4 {field} is empty ({status[field].strip()})")
firewall = subprocess.run(["iptables", "-w", "5", "-N", "WINS-H0-TIER-A"], capture_output=True, text=True, timeout=30)
report(firewall.returncode != 0, f"D4 an iptables write fails from the hub context (rc={firewall.returncode})")
try:
    open(key, "rb").close()
    report(False, "D4 the stand-in key file opened")
except PermissionError as exc:
    report(exc.errno == errno.EACCES, "D4 opening the stand-in key file fails with EACCES")
PY

out="$(systemd-run --wait --pipe --collect --quiet --unit="wins-h0-tier-a-$$" "${args[@]}" \
  /usr/bin/python3 -I - "${WORK}/signer/g2.ed25519.pem" "${WORK}/sockets" < "${WORK}/probe.py" 2>&1)"
rc=$?
printf '%s\n' "${out}"
(( rc == 0 )) || fail "the sandboxed context exited ${rc}"
grep -q '^PASS D4 opening the stand-in key file fails with EACCES$' <<<"${out}" \
  || fail "the context did not reach its last check"
failures=$((failures + $(grep -c '^FAIL ' <<<"${out}")))
if iptables -w 5 -n -L WINS-H0-TIER-A >/dev/null 2>&1; then
  fail "D4 the chain the context tried to create exists"
else
  pass "D4 the firewall is unchanged"
fi

# D3: the installed hub sshd policy forbids the deferred-login hooks.
if [[ -e /etc/ssh/sshd_config.d/20-winsvpn-hub.conf ]]; then
  effective="$(sshd -T -C 'user=root,host=localhost,addr=127.0.0.1' 2>/dev/null || true)"
  grep -qx 'permituserrc no' <<<"${effective}" && pass "D3 sshd: permituserrc no" || fail "D3 sshd: permituserrc is not no"
  grep -qx 'permituserenvironment no' <<<"${effective}" && pass "D3 sshd: permituserenvironment no" \
    || fail "D3 sshd: permituserenvironment is not no"
else
  printf 'NOTE hub sshd policy not installed here; its text is checked by test_hub_h0_hardening.py\n'
fi

# D8: an actual writable connection in the canary's actual profile must fail
# every database mutation. This fixture is inside its former writable grant.
canary_db="$(mktemp /root/vpn_auth/.h0-tier-a-canary.XXXXXX)" || exit 1
created_files+=("${canary_db}" "${canary_db}-journal" "${canary_db}-wal" "${canary_db}-shm")
python3 -I - "${canary_db}" <<'PY' || exit 1
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as conn:
    conn.execute('CREATE TABLE nodes (slug TEXT)')
    conn.execute("INSERT INTO nodes VALUES ('fixture')")
PY
python3 -I - "${HUB}" > "${WORK}/canary-properties" <<'PY' || exit 1
import sys
source = open(sys.argv[1], encoding='utf-8').read()
header = "cat > /etc/systemd/system/wins-gateway-canary.service <<'EOF'\n"
body = source[source.index(header) + len(header):].split('\nEOF\n', 1)[0]
section = ''
for line in body.splitlines():
    if line.startswith('['): section = line
    elif section == '[Service]' and '=' in line and not line.startswith('#'):
        if line.split('=', 1)[0] not in {'Type', 'ExecStart'}: print(line)
PY
canary_args=()
while IFS= read -r property; do canary_args+=(-p "${property}"); done < "${WORK}/canary-properties"
canary_out="$(systemd-run --wait --pipe --collect --quiet --unit="wins-h0-canary-write-$$" "${canary_args[@]}" \
  /usr/bin/python3 -I - "${canary_db}" <<'PY'
import sqlite3, sys
statements = ['UPDATE nodes SET slug=slug', "INSERT INTO nodes VALUES ('bad')", 'DELETE FROM nodes',
              'ALTER TABLE nodes ADD COLUMN bad TEXT', 'CREATE TABLE bad(n)', 'DROP TABLE nodes',
              'PRAGMA user_version=1']
failed = 0
for statement in statements:
    try:
        with sqlite3.connect(sys.argv[1]) as conn: conn.execute(statement)
        print('FAIL D8 canary database mutation succeeded:', statement)
        failed += 1
    except sqlite3.OperationalError as exc:
        if 'readonly' not in str(exc).lower() and 'read-only' not in str(exc).lower():
            print('FAIL D8 unexpected database error:', exc)
            failed += 1
        else:
            print('PASS D8 canary database mutation denied:', statement)
raise SystemExit(bool(failed))
PY
)"
canary_rc=$?
printf '%s\n' "${canary_out}"
(( canary_rc == 0 )) || fail "D8 actual canary sandbox write test failed"
[[ "$(grep -c '^PASS D8' <<<"${canary_out}")" == 7 ]] || fail "D8 did not deny all seven mutations"

# Resolver replacement: a running file bind retains its inode; a new unit
# must bind the replacement inode. Both source files belong to this test.
printf 'first\n' > "${WORK}/resolver.conf"
cat > "${WORK}/resolver-probe.py" <<'PY'
from pathlib import Path
import sys, time
root = Path(sys.argv[1])
target = Path('/run/systemd/resolve/stub-resolv.conf')
print('before=' + target.read_text().strip(), flush=True)
deadline = time.monotonic() + 20
while not (root / 'resolver-renamed').exists() and time.monotonic() < deadline:
    time.sleep(0.1)
print('after=' + target.read_text().strip(), flush=True)
PY
systemd-run --wait --pipe --collect --quiet --unit="wins-h0-resolver-first-$$" "${args[@]}" \
  -p "BindReadOnlyPaths=${WORK}/resolver.conf:/run/systemd/resolve/stub-resolv.conf" \
  /usr/bin/python3 -I - "${WORK}" < "${WORK}/resolver-probe.py" > "${WORK}/resolver-first.log" 2>&1 &
resolver_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  grep -q '^before=first$' "${WORK}/resolver-first.log" && break
  sleep 0.1
done
grep -q '^before=first$' "${WORK}/resolver-first.log" || fail "resolver initial bind failed"
printf 'second\n' > "${WORK}/resolver-new.conf"
mv "${WORK}/resolver-new.conf" "${WORK}/resolver.conf"
touch "${WORK}/resolver-renamed"
wait "${resolver_pid}" || fail "resolver running bind test failed"
resolver_pid=""
grep -q '^after=first$' "${WORK}/resolver-first.log" || fail "resolver replacement did not retain the old inode until restart"
rebound="$(systemd-run --wait --pipe --collect --quiet --unit="wins-h0-resolver-rebound-$$" "${args[@]}" \
  -p "BindReadOnlyPaths=${WORK}/resolver.conf:/run/systemd/resolve/stub-resolv.conf" \
  /usr/bin/cat /run/systemd/resolve/stub-resolv.conf)" || fail "resolver rebind failed"
if [[ "${rebound}" == second ]]; then
  pass "resolver replacement is visible after restart and rebind"
else
  fail "resolver replacement remained stale after restart"
fi

if (( failures > 0 )); then
  printf '%d check(s) failed\n' "${failures}"
  exit 1
fi
printf 'all Tier A H0 checks passed\n'
