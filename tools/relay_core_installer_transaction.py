#!/usr/bin/env python3
"""Relay a reviewed full Core installer through the pinned Control Hub path.

The helper is run ephemerally on the hub.  It accepts the Core sudo password
as its first stdin line and emits only a sanitized transaction result.  The
reviewed installer must already be staged root-only at
``/tmp/wins_core_server_setup_ONETOUCH.current`` on the hub.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys


CONTRACT = "winsvpn-core-installer-relay-v1"
STAGE = pathlib.Path("/tmp/wins_core_server_setup_ONETOUCH.current")
UNIT = "winsvpn-core-live-remediation.service"
# The one managed Core. A Core the installer has withdrawn for a rerun stays
# in status 'maintenance' with its withdrawal id until the new agent registers
# again, so it must remain reachable here: otherwise a rerun that pauses for a
# package reboot, or fails before the new sync agent runs, leaves the relay
# with no Core to status, reboot, restart or recover (Turn 2, OI-COREB-5).
#
# Turn 3 (OI-COREB-T2-3): recover-firewall is refused for a withdrawn Core. It
# would source the installer with CORE_INSTALLER_RERUN_ACTIVE=0 and call
# write_firewall with admission 1, which deletes the rerun serving hold and
# re-admits public ingress without a successful postflight. status, reboot,
# start and stage-validate stay available.
CORE_SELECTION_SQL = """SELECT management_host AS host,
                      COALESCE(NULLIF(management_user,''),'ubuntu') AS user,
                      COALESCE(deployment_withdrawal_id,'') AS withdrawal_id
                 FROM core_servers
                WHERE management_status='ok'
                  AND (status='online'
                       OR (status='maintenance'
                           AND COALESCE(deployment_withdrawal_id,'') != ''))
                ORDER BY core_id"""

# IA-CORE-03: the exact text main() logs after a successful --preflight.
PREFLIGHT_PASSED_MARKER = "installation preflight and disk-encryption posture checks passed"

# IA-CORE-03: rebuild the serving firewall exactly as main() does: inline IPS
# plus explicit public admission (argument 2 = 1). Without it write_firewall
# defaults admission to closed and drops the public TCP stealth transports.
# The expected NFQUEUE rule count is one per configured stealth transport,
# which is what write_firewall emits, not a fixed number. write_firewall itself
# persists rules.v4 and rules.v6 and fails on either; a second unchecked save
# here could only truncate what it had just persisted (Turn 2, Sol N-3).
#
# Turn 3: on the Core itself, recovery also refuses while an installer
# transaction unit is running (exit 73) or while any fail-closed hold is in
# place (exit 74); both holds are released only by a successful postflight.
# Turn 4 (Sol N-9): those checks and the firewall commit all run under the
# installer's deployment lock (fd 7, held until this script exits), taken
# without waiting (exit 72 when a deployment holds it). A hold can therefore
# not appear between the checks and write_firewall. The lock path is the
# same literal as in the installer's acquire_core_deployment_lock (neither side
# takes an override).
# Follow-up N-7(c): the hold probe lists both base chains and fails closed. An
# iptables listing that fails (xtables lock, missing binary, any error) stops
# recovery before write_firewall; only a successful listing without the hold
# jump counts as "no hold".
FIREWALL_RECOVERY_SCRIPT = r'''set -Eeuo pipefail
exec 7>>/run/lock/wins-core-deployment.lock
flock -n 7 || exit 72
case "$(systemctl is-active winsvpn-core-live-remediation.service 2>/dev/null || true)" in
  active|activating|reloading|deactivating) exit 73 ;;
esac
input_rules="$(iptables -w 10 -S INPUT)" || exit 1
forward_rules="$(iptables -w 10 -S FORWARD)" || exit 1
if grep -Fxq -- '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' <<<"${input_rules}" \
    || grep -Fxq -- '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD' <<<"${forward_rules}"; then
  exit 74
fi
source /root/wins_core_server_setup_ONETOUCH.sh
load_existing_core_env_for_preflight
systemctl is-active --quiet suricata.service
systemctl show suricata.service -p ExecStart --value | grep -E -- '(^|[[:space:]])-q[[:space:]]+0([[:space:]]|$)' >/dev/null
suricatasc -c uptime >/dev/null 2>&1
awk '$1 == 0 {found=1} END {exit(found ? 0 : 1)}' /proc/net/netfilter/nfnetlink_queue
CORE_STEALTH_TRANSPORTS="$(normalize_core_stealth_transports "${CORE_STEALTH_TRANSPORTS}" "${CORE_STEALTH_ORIGIN_PORT}" "${CORE_XRAY_SECURITY}")"
expected="$(tr ',' '\n' <<<"${CORE_STEALTH_TRANSPORTS}" | grep -c . || true)"
write_firewall "${INSTALL_CORE_IDS_IPS:-${INSTALL_CORE_IDS_IPS_DEFAULT}}" 1 >/dev/null
count="$(iptables-save | grep -c -- '--queue-num 0' || true)"
bypass=false; iptables-save | grep -q -- '--queue-bypass' && bypass=true
input_drop="$(iptables -S INPUT | head -n1 | grep -c -- '-P INPUT DROP' || true)"
forward_drop="$(iptables -S FORWARD | head -n1 | grep -c -- '-P FORWARD DROP' || true)"
python3 - "$count" "$bypass" "$input_drop" "$forward_drop" "$expected" <<'PY'
import json,sys
count=int(sys.argv[1]); bypass=sys.argv[2]=='true'; expected=int(sys.argv[5])
ok=count==expected and expected>0 and not bypass and sys.argv[3]=='1' and sys.argv[4]=='1'
print(json.dumps({'role':'core','ok':ok,'nfqueue_rule_count':count,'nfqueue_rules_expected':expected,'queue_bypass':bypass,'input_drop':sys.argv[3]=='1','forward_drop':sys.argv[4]=='1','suricata_active':True,'queue0_bound':True},sort_keys=True,separators=(',',':')))
raise SystemExit(0 if ok else 1)
PY'''


def result(ok: bool, **values: object) -> int:
    payload = {"contract": CONTRACT, "ok": ok, **values}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if ok else 1


def main() -> int:
    action = os.environ.get("WINS_CORE_INSTALL_ACTION", "")
    if action not in {"stage-validate", "start", "status", "reboot", "recover-firewall"}:
        return result(False, error_type="invalid_action")
    password = sys.stdin.readline(512).rstrip("\r\n")
    if not password or len(password) > 256 or "\x00" in password:
        return result(False, error_type="invalid_sudo_credential")
    if os.geteuid() != 0:
        return result(False, error_type="hub_root_required")

    database = pathlib.Path("/root/vpn_auth/vpn_users.db")
    known_hosts = pathlib.Path("/root/vpn_auth/managed_known_hosts")
    identity = pathlib.Path("/root/.ssh/id_rsa")
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(CORE_SELECTION_SQL).fetchall()
        connection.close()
    except Exception:
        return result(False, error_type="database_query_failed")
    if len(rows) != 1:
        return result(False, error_type="managed_core_not_unique")
    host = str(rows[0]["host"] or "").strip().lower()
    user = str(rows[0]["user"] or "").strip().lower()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        return result(False, error_type="invalid_management_user")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        return result(False, error_type="invalid_management_host")
    if action == "recover-firewall" and str(rows[0]["withdrawal_id"] or "").strip():
        return result(False, action=action, error_type="core_withdrawn_for_deployment")
    if (
        not known_hosts.is_file()
        or known_hosts.is_symlink()
        or known_hosts.stat().st_mode & 0o077
        or not identity.is_file()
    ):
        return result(False, error_type="unsafe_management_prerequisite")
    if not any(
        line.split(None, 1)[0] == host
        for line in known_hosts.read_text(encoding="utf-8", errors="strict").splitlines()
        if line.strip()
    ):
        return result(False, error_type="pinned_host_key_missing")

    environment = os.environ.copy()
    env_path = pathlib.Path("/root/vpn_auth/.env")
    if env_path.is_file() and not env_path.is_symlink() and not env_path.stat().st_mode & 0o077:
        for line in env_path.read_text(encoding="utf-8", errors="strict").splitlines():
            if "=" in line and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", line.split("=", 1)[0]):
                environment[line.split("=", 1)[0]] = line.split("=", 1)[1]
    base = [
        "ssh", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no", "-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h",
        f"{user}@{host}",
    ]

    def remote(command: str, extra: bytes = b"", timeout: int = 90) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            base + [command], input=password.encode() + b"\n" + extra,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            timeout=timeout, check=False,
        )

    if action == "stage-validate":
        try:
            info = STAGE.lstat()
            data = STAGE.read_bytes()
        except Exception:
            return result(False, error_type="hub_stage_missing")
        if STAGE.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022 or not data.startswith(b"#!/usr/bin/env bash\n"):
            return result(False, error_type="unsafe_hub_stage")
        digest = hashlib.sha256(data).hexdigest()
        installed = remote(
            "sudo -S -p '' -- install -o root -g root -m 0700 /dev/stdin "
            "/root/wins_core_server_setup_ONETOUCH.sh",
            data,
            120,
        )
        if installed.returncode != 0:
            return result(False, error_type="remote_stage_failed")
        preflight = remote(
            "sudo -S -p '' -- bash /root/wins_core_server_setup_ONETOUCH.sh --preflight",
            timeout=180,
        )
        text = (preflight.stdout + b"\n" + preflight.stderr).decode("utf-8", errors="replace")
        return result(
            preflight.returncode == 0,
            action=action,
            source_sha256=digest,
            preflight_passed=preflight.returncode == 0 and PREFLIGHT_PASSED_MARKER in text,
            error_marker_count=text.count("[ERR]"),
            returncode=preflight.returncode,
        )

    if action == "start":
        cleared = remote(
            "sudo -S -p '' -- bash -c '"
            "state=$(systemctl is-active winsvpn-core-live-remediation.service 2>/dev/null || true); "
            "case $state in active|activating|reloading|deactivating) exit 9;; esac; "
            "systemctl reset-failed winsvpn-core-live-remediation.service 2>/dev/null || true'",
            timeout=30,
        )
        if cleared.returncode != 0:
            return result(False, action=action, error_type="existing_transaction_active")
        command = (
            "sudo -S -p '' -- systemd-run --unit=winsvpn-core-live-remediation "
            "--property=Type=exec --property=TimeoutStartSec=infinity "
            "--property=StandardOutput=journal --property=StandardError=journal "
            "/bin/bash /root/wins_core_server_setup_ONETOUCH.sh --deploy"
        )
        started = remote(command, timeout=45)
        return result(started.returncode == 0, action=action, start_returncode=started.returncode)

    if action == "reboot":
        rebooted = remote("sudo -S -p '' -- systemctl reboot", timeout=30)
        # SSH normally exits nonzero while systemd tears the connection down.
        return result(rebooted.returncode in {0, 255}, action=action, dispatch_returncode=rebooted.returncode)

    if action == "recover-firewall":
        import base64
        recovery = FIREWALL_RECOVERY_SCRIPT
        encoded = base64.b64encode(recovery.encode()).decode()
        command = (
            "sudo -S -p '' -- env WINS_CORE_RECOVERY_B64=" + encoded + " bash -c "
            "'base64 -d <<<\"$WINS_CORE_RECOVERY_B64\" | bash'"
        )
        recovered = remote(command, timeout=180)
        if recovered.returncode == 72:
            return result(False, action=action, error_type="deployment_in_progress")
        if recovered.returncode == 73:
            return result(False, action=action, error_type="installer_transaction_active")
        if recovered.returncode == 74:
            return result(False, action=action, error_type="deployment_hold_active")
        if recovered.returncode != 0:
            return result(False, action=action, error_type="firewall_recovery_failed")
        try:
            payload = json.loads(recovered.stdout.decode("utf-8", errors="strict"))
        except Exception:
            return result(False, action=action, error_type="firewall_recovery_invalid")
        payload_ok = payload.pop("ok", False) is True
        return result(payload_ok, action=action, **payload)

    probe = r'''import hashlib,json,pathlib,re,subprocess
def run(args,timeout=20):
 r=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
 return r.returncode,r.stdout.strip()
props={}
for name in ("ActiveState","SubState","Result","ExecMainStatus","InvocationID","ExecMainStartTimestamp","ExecMainStartTimestampMonotonic"):
 rc,value=run(["systemctl","show","winsvpn-core-live-remediation.service","-p",name,"--value"])
 props[name.lower()]=value if rc==0 else "unknown"
invocation_id=props["invocationid"]
journal=["journalctl","--no-pager","-o","cat"]
if len(invocation_id)==32 and all(c in "0123456789abcdef" for c in invocation_id.lower()):
 journal.insert(1,"_SYSTEMD_INVOCATION_ID="+invocation_id)
else:
 journal[1:1]=["-u","winsvpn-core-live-remediation.service"]
rc,log=run(journal,30)
source=pathlib.Path("/root/wins_core_server_setup_ONETOUCH.sh")
markers=[("preflight","Preflight passed:"),("luks","[CORE] Disk-encryption posture:"),("packages","Installing core-hop packages"),("reboot-resume","Verified the required package reboot"),("swap","Applying zram swap and swappiness"),("performance","persistent dm-crypt multi-core"),("sysctl","forwarding, buffer, and IPv6"),("management-key","Fetching the control hub's SSH key"),("management","Hub verified outbound Core management"),("awg-ingress","Installing AmneziaWG core ingress"),("xray","Installing pinned Xray"),("nginx","Configuring dynamic Nginx"),("suricata","Configuring Core inline Suricata"),("firewall","Applying core firewall"),("sshd","Hardening SSH"),("sync","sync complete assignments="),("postflight","Running core-hop post-deployment validation"),("complete","Core server setup complete")]
last_stage="unknown";last_position=-1
for name,needle in markers:
 position=log.rfind(needle)
 if position>last_position:last_stage=name;last_position=position
diagnostic="none"
lower=log.lower()
if "could not get lock" in lower or "dpkg was interrupted" in lower or "e: " in lower: diagnostic="package_manager"
elif "failed to fetch" in lower or "temporary failure resolving" in lower: diagnostic="package_network"
elif "job for" in lower and "failed" in lower: diagnostic="service_start"
elif "permission denied" in lower: diagnostic="permission"
known_failures={"suricata_queue_unhealthy":"inline Suricata queue 0 is not healthy" in log,"firewall_validation":"firewall transaction validation failed" in log,"firewall_commit":"firewall transaction failed" in log,"firewall_rollback":"firewall rollback failed" in log,"suricata_config":"suricata: Configuration provided was invalid" in log,"suricata_action_policy":"Suricata action policy violation" in log}
diagnostic_tail=[]
journal_tail=[]
for line in log.splitlines():
 lower_line=line.lower()
 clean_all=re.sub(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}","[ip]",line)
 clean_all=re.sub(r"[A-Za-z0-9+/=_-]{40,}","[redacted]",clean_all)
 if not any(secret in clean_all.lower() for secret in ("password=","token=","secret=","privatekey=")):
  journal_tail.append(clean_all[-240:])
 if any(word in lower_line for word in ("firewall","iptables","suricata","rollback","preimage","failed","error","restor")):
  diagnostic_tail.append(clean_all[-240:])
print(json.dumps({"role":"core","source_sha256":hashlib.sha256(source.read_bytes()).hexdigest() if source.is_file() else "","invocation_id":invocation_id,"exec_main_start_timestamp":props["execmainstarttimestamp"],"exec_main_start_monotonic":props["execmainstarttimestampmonotonic"],"active_state":props["activestate"],"sub_state":props["substate"],"result":props["result"],"exec_main_status":props["execmainstatus"],"error_marker_count":log.count("[ERR]"),"warning_marker_count":log.count("[WARN]"),"last_stage":last_stage,"diagnostic":diagnostic,"diagnostic_tail":diagnostic_tail[-24:],"journal_tail":journal_tail[-48:],"known_failures":known_failures,"postflight_passed":"Core-hop post-deployment validation passed" in log,"complete_marker":"Core server setup complete" in log,"reboot_boundary":("requires a reboot" in log or props["execmainstatus"]=="75")},sort_keys=True,separators=(",",":")))'''
    import base64
    encoded = base64.b64encode(probe.encode()).decode()
    command = (
        "sudo -S -p '' -- env WINS_CORE_STATUS_B64=" + encoded + " python3 -c "
        "'import base64,os;exec(base64.b64decode(os.environ[\"WINS_CORE_STATUS_B64\"]))'"
    )
    observed = remote(command, timeout=60)
    if observed.returncode != 0:
        return result(False, action=action, error_type="remote_status_failed")
    try:
        payload = json.loads(observed.stdout.decode("utf-8", errors="strict"))
    except Exception:
        return result(False, action=action, error_type="remote_status_invalid")
    return result(True, action=action, **payload)


if __name__ == "__main__":
    raise SystemExit(main())
