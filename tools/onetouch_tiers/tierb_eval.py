"""Tier B evaluators that are not 5.7 read-backs (design v17 5.1 step 12, 5.3 checked starts in flight, the staging).

Each evaluator is a pure function from the raw text a catalogue step captured to a verdict {"pass": bool, "reason":
str, ...}. tier_b.py's `evaluate` step looks a name up in readbacks first, then here. tests/test_winn3_onetouch_s7.py
feeds each one a right reading and wrong readings, and applies text mutants to this file to show the tests notice.
"""
import datetime
import json
import math
import re


def kv(*texts):
    """key=value lines of one or more captures; a later capture's value wins. A key is what the drivers emit: letters,
    digits and underscores, and the hyphens and dots of unit and container names (s7_tb09.sh prints after_winn3-gateway,
    container_amnezia-awg2 and docker_stops_amnezia-awg2)."""
    out = {}
    for text in texts:
        for line in (text or "").splitlines():
            key, sep, value = line.partition("=")
            if sep and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", key):
                out[key] = value
    return out


def _num(text):
    """A finite number, else None."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


# --- TB-03: rerun without restart (5.1 step 12, P-14) ---------------------------------------------------------------
# The session counts are in the gateway's serve status, which it prints to stdout (the journal) once a second
# (cmd/winn3-gateway/main.go serveStatus: "sessions", "carrying", "ready"). /run/winn3-gateway/status.json is the
# proof status and carries none of them. Read the way the data plane's own heartbeat reads it (DP 15453 to 15455),
# bound to the current invocation.
SERVE_STATUS = (
    "inv=$(systemctl show winn3-gateway.service -p InvocationID --value); "
    "journalctl --no-pager -o cat \"_SYSTEMD_INVOCATION_ID=${inv}\" --since '-30 s' -n 40 2>/dev/null "
    "| grep -E '^\\{\"event\":\"[a-z_]+\"' | tail -n 1 "
    "| python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); "
    "print(\"sessions=%s\" % d[\"sessions\"]); print(\"carrying=%s\" % d[\"carrying\"]); print(\"ready=%s\" % d[\"ready\"])' "
    "2>/dev/null || echo status=unreadable")
SNAPSHOT_RERUN = (
    "echo \"main=$(systemctl show winn3-gateway.service -p MainPID --value)\"; "
    "echo \"active=$(systemctl is-active winn3-gateway.service)\"; "
    "for f in /etc/winn/credentials/*.seed /etc/winn/credentials/*.key; do "
    "[ -f \"$f\" ] && echo \"key $(sha256sum \"$f\" | cut -d' ' -f1) $f\"; done; " + SERVE_STATUS)


def _snapshot(text):
    facts = kv(text)
    keys = sorted(tuple(line.split(None, 2)[1:]) for line in (text or "").splitlines() if line.startswith("key "))
    return facts, keys


def evaluate_rerun_unchanged(before, after):
    """P-14: the rerun kept the gateway MainPID, every credential digest and the carrying-session count. A zero count
    on both sides passes but is reported as `carrying_vacuous`, so a reader cannot take it for a preserved session."""
    b, bkeys = _snapshot(before)
    a, akeys = _snapshot(after)
    problems = []
    if not re.fullmatch(r"[1-9]\d*", b.get("main", "")):
        problems.append("no gateway MainPID before the rerun: %r" % b.get("main"))
    if b.get("main") != a.get("main"):
        problems.append("the gateway MainPID changed from %s to %s" % (b.get("main"), a.get("main")))
    if b.get("active") != "active" or a.get("active") != "active":
        problems.append("the gateway was %s before and %s after" % (b.get("active"), a.get("active")))
    if not bkeys or any(len(k) != 2 or not re.fullmatch(r"[0-9a-f]{64}", k[0]) for k in bkeys):
        problems.append("no readable credential digest before the rerun")
    if bkeys != akeys:
        problems.append("credential digests changed")
    for side, facts in (("before", b), ("after", a)):
        if not re.fullmatch(r"\d+", facts.get("carrying", "")):
            problems.append("the carrying-session count is unreadable %s the rerun" % side)
    if b.get("carrying") != a.get("carrying"):
        problems.append("carrying sessions went from %s to %s" % (b.get("carrying"), a.get("carrying")))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "main": b.get("main"),
            "carrying_before": b.get("carrying"), "carrying_after": a.get("carrying"),
            "sessions_before": b.get("sessions"), "sessions_after": a.get("sessions"),
            "carrying_vacuous": b.get("carrying") == "0" and a.get("carrying") == "0", "keys": len(bkeys)}


# --- the staging the `installer-staged` requirement claims ----------------------------------------------------------
COVER_KEYS = ("WINN3_COVER_CERT_B64", "WINN3_COVER_KEY_B64", "WINN3_COVER_ECH_KEYS_B64",
              "WINN3_COVER_WINN_CERT_B64", "WINN3_COVER_WINN_KEY_B64")


def evaluate_staging(text, installer_sha256, binary_pin):
    """The staging check's capture (STAGING_CHECK in the catalogue): the installer bytes are the plan's, the gateway
    binary and its .sha256 record both name the installer's pin and `sha256sum -c` accepts the record, the siblings
    exist, and the secrets file is root 0600 with all five cover keys. No value is ever read into the capture: key
    names and counts only. A plan digest or pin that is not 64 hex digits fails: an empty capture would equal it."""
    facts = kv(text)
    problems = []
    for name, value in (("installer_sha256", installer_sha256), ("binary_pin", binary_pin)):
        if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
            problems.append("the plan's %s is not a sha256: %r" % (name, value))
    if facts.get("installer_sha256") != installer_sha256:
        problems.append("staged installer %s is not the plan's %s" % (facts.get("installer_sha256"), installer_sha256))
    if facts.get("binary_sha256") != binary_pin:
        problems.append("staged gateway binary %s is not the pin %s" % (facts.get("binary_sha256"), binary_pin))
    if facts.get("binary_record") != binary_pin:
        problems.append("the .sha256 record names %s, not the pin" % facts.get("binary_record"))
    if facts.get("binary_record_check") != "ok":
        problems.append("sha256sum -c on the record: %s" % facts.get("binary_record_check"))
    for name in ("amneziawg_builder", "cloudflare_gpg"):
        if facts.get(name) != "present":
            problems.append("%s is %s" % (name, facts.get(name)))
    if facts.get("secrets_mode") != "root 600":
        problems.append("secrets file mode is %s" % facts.get("secrets_mode"))
    missing = [k for k in COVER_KEYS if facts.get("cover_" + k) != "1"]
    if missing:
        problems.append("cover material missing from the secrets file: %s" % ",".join(missing))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok"}


# --- TB-09: checked starts in flight (5.3, variants 1 to 4, 6, 8, 9) ----------------------------------------------------
def docker_time(text):
    """dockerd's RFC 3339 time with up to nanoseconds (2026-10-08T17:52:15.123456789Z) as an epoch, or None."""
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)", text or "")
    if not match:
        return None
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    try:
        base = datetime.datetime.fromisoformat(match.group(1) + zone).timestamp()
    except ValueError:
        return None
    return base + (float("0" + match.group(2)) if match.group(2) else 0.0)


def _record(facts):
    try:
        record = json.loads(facts.get("record") or "")
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def _record_epoch(record):
    try:
        return datetime.datetime.fromisoformat(record.get("time", "")).timestamp()
    except (TypeError, ValueError):
        return None


def _starts_after(facts):
    """Serving-unit starts (journal epochs) at or after the handler's last stop. None when the last stop or the starts
    were not read or do not parse: an empty serving_starts reads no start, a missing one reads nothing."""
    last = _num(facts.get("last_handler_stop"))
    text = facts.get("serving_starts")
    if last is None or text is None:
        return None
    starts = [_num(x) for x in text.split()]
    if None in starts:
        return None
    return [s for s in starts if s >= last]


# What `systemctl is-active` prints for a unit that is not serving, and the AWG container names s7_tb09.sh inspects.
STOPPED = ("inactive", "failed")
AWG_CONTAINERS = ("amnezia-awg2", "awg", "amnezia-awg")


def _container_state(value):
    """`docker inspect -f '{{.State.Running}} {{.State.StartedAt}}'` as (running, started epoch), else None."""
    fields = (value or "").split()
    if len(fields) != 2 or fields[0] not in ("true", "false"):
        return None
    started = docker_time(fields[1])
    return None if started is None else (fields[0] == "true", started)


def _common_dark(facts, record, problems):
    # Darkness is read, never assumed: a unit state or container state that is missing or does not parse fails.
    for unit in ("nginx", "xray", "winn3-gateway"):
        state = facts.get("after_" + unit)
        if state not in STOPPED:
            problems.append("%s is %s 30 s after the exit path ended" % (unit, state or "not read"))
    containers = {key[len("container_"):]: value for key, value in facts.items() if key.startswith("container_")}
    if not any(name in containers for name in AWG_CONTAINERS):
        problems.append("no AWG container state was read 30 s after the exit path ended")
    for name, value in sorted(containers.items()):
        state = _container_state(value)
        if state is None:
            problems.append("the %s container state does not parse: %r" % (name, value))
        elif state[0]:
            problems.append("%s is running 30 s after the exit path ended" % name)
    after = _starts_after(facts)
    if after is None:
        problems.append("the handler's last stop or the serving-unit starts were not read from the traces")
    elif after:
        problems.append("a serving unit started after the handler's last stop: %s" % after)
    if not re.fullmatch(r"[1-9]\d*", facts.get("installer_failed") or ""):
        problems.append("the forced late failure did not fire (installer_failed %r)" % facts.get("installer_failed"))
    if facts.get("ip_wait_timeout") != "0":
        problems.append("the held failure point timed out or its count was not read (ip_wait_timeout %r)" % facts.get("ip_wait_timeout"))
    if record is None:
        problems.append("no late-failure record")
    elif record.get("activation_fence") != "done":
        problems.append("activation_fence is %s" % record.get("activation_fence"))


def _docker_stops(facts, name):
    return [s for s in (_num(x) for x in (facts.get("docker_stops_" + name) or "").split()) if s is not None]


def _proxy_epoch(log, word):
    """The epoch of the first `word` line of the proxy log (lines joined by |), else None."""
    match = re.search(r"(?:^|\|)%s \S+(?: \S+)? ([0-9]+\.[0-9]+)(?:\||$)" % re.escape(word), log or "")
    return float(match.group(1)) if match else None


def _stopped_after(facts, name, completed, problems, what):
    """A restart dockerd completed at `completed` must be followed by a `docker stop` of that container."""
    if completed is None:
        return
    if not any(stop >= completed for stop in _docker_stops(facts, name)):
        problems.append("%s completed at %.3f, and no docker stop of %s came after it" % (what, completed, name))


def evaluate_tb09(*texts):
    """One TB-09 run, from the four phase captures of s7_tb09.sh (start, caller, interfere, finish)."""
    facts = kv(*texts)
    variant = facts.get("variant")
    record = _record(facts)
    problems = []
    if facts.get("error"):
        problems.append("the driver stopped: %s" % facts["error"])
    rec = record or {}
    window = str(rec.get("settle_window_seconds", ""))
    lock = rec.get("activation_lock")
    first_flock = _num(facts.get("first_flock"))
    ended = _record_epoch(rec) if record else None
    d150 = variant == "9" and facts.get("d") == "150"
    if not d150:
        _common_dark(facts, record, problems)
    elif record is None:
        problems.append("no late-failure record")
    if variant == "1":
        if lock != "held":
            problems.append("variant 1 must end with the lock held; activation_lock is %s" % lock)
        if rec.get("first_lock") != "contended":
            problems.append("first_lock is %s; the continued child held fd 6 when the handler first asked" % rec.get("first_lock"))
        if "caller_rc=0" not in (facts.get("caller_log") or ""):
            problems.append("the continued child's start did not complete")
    elif variant == "2":
        if facts.get("child_at_106") not in ("gone", "Z"):
            problems.append("the child still exists 106 s after spawn (state %s)" % facts.get("child_at_106"))
        if lock != "held":
            problems.append("variant 2 must end with the lock held; activation_lock is %s" % lock)
    elif variant == "3":
        if facts.get("scope_procs_at_106") != "empty":
            problems.append("the scope's cgroup is not empty 106 s after it started: %s" % facts.get("scope_procs_at_106"))
        if facts.get("child_at_106") not in ("gone", "Z"):
            problems.append("the child is alive 106 s after the scope started (state %s)" % facts.get("child_at_106"))
        if "Failed with result 'timeout'" not in (facts.get("scope_journal") or ""):
            problems.append("the scope journal does not show result timeout from RuntimeMaxSec")
        if facts.get("timeout_state_at_106") != "T":
            problems.append("timeout was not held stopped (state %s)" % facts.get("timeout_state_at_106"))
        if lock != "unavailable":
            problems.append("variant 3 must take the unavailable path; activation_lock is %s" % lock)
        if first_flock is None or ended is None or ended < first_flock + 120:
            problems.append("the handler finished before t_p + 120 s (t_p %s, record time %s)" % (first_flock, ended))
        for key in ("timeout_pgid", "parent_pgid"):
            if not re.fullmatch(r"\d+", facts.get(key, "")):
                problems.append("%s not recorded" % key)
    elif variant == "4":
        if lock != "unavailable":
            problems.append("variant 4 must take the unavailable path; activation_lock is %s" % lock)
        if "late-failure hold" not in (facts.get("caller_log") or ""):
            problems.append("after SIGCONT the child did not see the record and the parent did not log the skip")
    elif variant == "6":
        if lock != "unavailable":
            problems.append("variant 6 must take the unavailable path; activation_lock is %s" % lock)
    elif variant == "8":
        if facts.get("after_nginx") != "inactive":
            problems.append("the delayed nginx start job did not end inactive (%s)" % facts.get("after_nginx"))
        if window != "120":
            problems.append("the settle window is %s, not 120" % window)
        name = facts.get("container", "")
        started = (facts.get("container_" + name) or "").split()
        done = docker_time(started[1]) if len(started) == 2 else None
        requested = _num(facts.get("restart_requested_at"))
        if done is None or requested is None:
            problems.append("the in-flight restart's completion time was not read")
        elif done > requested:
            # dockerd completed the restart after the request: some installer `docker stop` must follow it. The settle
            # check's first pass stops any running container, so settle_stops alone would prove nothing here.
            _stopped_after(facts, name, done, problems, "the in-flight docker restart")
    elif variant == "9":
        trigger = "first_lock contended" if facts.get("client") == "keep" else "fence killed"
        if window != "120":
            problems.append("the settle window is %s, not 120" % window)
        if facts.get("client") == "keep":
            if rec.get("first_lock") != "contended":
                problems.append("the fd-6 client's first flock -n 6 must fail; first_lock is %s" % rec.get("first_lock"))
            if rec.get("fence_killed") != "no":
                problems.append("the fence must not kill a client the supervisors end; fence_killed is %s" % rec.get("fence_killed"))
            if (facts.get("client_fd6") or "").find("wins-serving-activation.lock") < 0:
                problems.append("the client was not shown to hold fd 6")
        elif facts.get("client") == "closed":
            if rec.get("fence_killed") != "yes":
                problems.append("the fence did not kill the released-lock client")
            if facts.get("caller_unit_after_handoff") not in STOPPED:
                problems.append("the parent may still hold its copies before the failure was forced (caller unit %s)"
                                % facts.get("caller_unit_after_handoff"))
        else:
            problems.append("unknown client %r" % facts.get("client"))
        if facts.get("d") not in ("45", "150"):
            problems.append("unknown or missing D %r" % facts.get("d"))
        completed = _proxy_epoch(facts.get("proxy_log"), "completed")
        if _proxy_epoch(facts.get("proxy_log"), "forwarded") is None:
            problems.append("the proxy never forwarded the restart")
        if facts.get("d") == "45":
            if completed is None:
                problems.append("D=45: dockerd never answered the forwarded restart")
            _stopped_after(facts, facts.get("container", ""), completed, problems, "D=45: the forwarded restart")
        verdict_trigger = trigger
    else:
        problems.append("unknown or missing variant %r" % variant)
    out = {"pass": not problems, "reason": "; ".join(problems) or "ok", "variant": variant,
           "activation_lock": lock, "first_lock": rec.get("first_lock"), "settle_window_seconds": window,
           "settle_stops": rec.get("settle_stops"), "fence_killed": rec.get("fence_killed")}
    if variant == "9":
        out.update({"client": facts.get("client"), "d": facts.get("d"), "trigger": verdict_trigger,
                    "container_after": facts.get("container_" + facts.get("container", ""))})
    if variant == "3":
        out.update({"timeout_pgid": facts.get("timeout_pgid"), "parent_pgid": facts.get("parent_pgid")})
    if variant == "8":
        started = (facts.get("container_" + facts.get("container", "")) or "").split()
        done = docker_time(started[1]) if len(started) == 2 else None
        requested = _num(facts.get("restart_requested_at"))
        out.update({"restart_duration_seconds": None if done is None or requested is None else round(done - requested, 3),
                    "container_after": facts.get("container_" + facts.get("container", ""))})
    return out


# --- hub-lite outputs (TB-02, TB-06, TB-13, TB-14) ---------------------------------------------------------------------
def _json(text):
    """The last JSON object line of a hub-lite or tierb_hub output, or None."""
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


def evaluate_fresh_golive(released, provision, flipped, sweep, served):
    """TB-02 hub side, in the 3.1 order: complete-fresh released the node dark as fresh_install; provisioning signed
    and stored a g2 descriptor and flipped the carrier without opening the node; the go-live sweep reopened it as
    auto_golive_fresh_install at the ticket's tier; the client-facing node list then serves it on every platform."""
    rel, prov, flip, swept, listed = (_json(t) for t in (released, provision, flipped, sweep, served))
    problems = []
    if not rel or not rel.get("ok"):
        problems.append("no hub status after the deploy")
    else:
        if not rel.get("deployment_released_at") or not rel.get("deployment_completed_at"):
            problems.append("complete-fresh did not set deployment_released_at and deployment_completed_at")
        if rel.get("health_closed_reason") != "fresh_install":
            problems.append("released with health_closed_reason %r, not fresh_install" % rel.get("health_closed_reason"))
        if rel.get("operator_enabled") != 0:
            problems.append("the node was open before its proofs")
    result = (prov or {}).get("result") or {}
    if not result.get("ok"):
        problems.append("provisioning did not sign and store: %s" % (result.get("reason") or result.get("error")))
    if not flip or flip.get("protocol_version") != "winn/3" or flip.get("descriptor_seq") is None:
        problems.append("after provisioning the carrier is %s with descriptor seq %s" % ((flip or {}).get("protocol_version"),
                                                                                        (flip or {}).get("descriptor_seq")))
    elif flip.get("operator_enabled") != 0:
        problems.append("the carrier flip opened the node")
    status = (swept or {}).get("status") or {}
    slug = status.get("slug") or (rel or {}).get("slug")
    if not slug:
        problems.append("no slug was read from the hub")
    if not swept or slug not in (swept.get("reopened") or []):
        problems.append("the go-live sweep did not reopen the node; held: %s" % (swept or {}).get("held"))
    if status.get("operator_enabled") != 1 or status.get("latest_promotion_source") != "auto_golive_fresh_install":
        problems.append("after the sweep operator_enabled %s, promotion source %s" % (status.get("operator_enabled"),
                                                                                   status.get("latest_promotion_source")))
    platforms = (listed or {}).get("platforms") or {}
    missing = sorted(p for p in ("default", "android", "linux", "ios") if not (platforms.get(p) or {}).get("listed"))
    if missing:
        problems.append("the client-facing node list does not serve the node on %s" % ",".join(missing))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "slug": slug,
            "descriptor_kid": (flip or {}).get("descriptor_kid"), "tier": status.get("latest_promotion_tier")}


def evaluate_completion_failure(before, withdrawn, sweep, after):
    """TB-06 hub side: the node was live; the rerun's withdrawal closed it and the failed completion left it closed;
    after the recovering rerun the go-live sweep reopened it through the installer-rerun class."""
    b, w, swept, a = (_json(t) for t in (before, withdrawn, sweep, after))
    problems = []
    if not b or b.get("operator_enabled") != 1:
        problems.append("the node was not live before the rerun (operator_enabled %s)" % (b or {}).get("operator_enabled"))
    if not w or w.get("operator_enabled") != 0:
        problems.append("the node is not closed after the failed completion (operator_enabled %s)" % (w or {}).get("operator_enabled"))
    slug = (a or {}).get("slug")
    if not slug:
        problems.append("no slug was read from the hub after recovery")
    if not swept or slug not in (swept.get("reopened") or []):
        problems.append("the sweep after the recovering rerun did not reopen it; held: %s" % (swept or {}).get("held"))
    if not a or a.get("operator_enabled") != 1 or a.get("latest_promotion_source") != "auto_reopen_installer_rerun":
        problems.append("after recovery operator_enabled %s, promotion source %s" % ((a or {}).get("operator_enabled"),
                                                                                  (a or {}).get("latest_promotion_source")))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok"}


# --- TB-13 (STEP-13) and TB-14 (STEP-14) node snapshots -----------------------------------------------------------------
_KEYS = ("for f in /etc/winn/credentials/static.key /etc/winn/credentials/admission.key "
         "/etc/winn/credentials/auth_ed25519.seed /etc/winn/credentials/auth_mldsa65.seed; do "
         "[ -f \"$f\" ] && echo \"key $(sha256sum \"$f\" | cut -d' ' -f1) $f\"; done; ")
_GATEWAY_ID = "echo \"gateway_id=$(sed -n 's/^WINN3_GATEWAY_ID=//p' /etc/winn/winn3-gateway.env 2>/dev/null | tr -d \"'\\\"\" | head -n 1)\"; "
# A standalone-built unit may load its keys from other paths (DP legacy_sources reads the live unit's LoadCredential=
# lines), so adoption names each key by its credential id and hashes the file the loaded unit names.
_UNIT_KEYS = ("systemctl cat winn3-gateway.service 2>/dev/null | awk -F'[=:]' "
              "'/^LoadCredential=(static[.]key|admission[.]key|dual-auth-ed-key|dual-auth-ml-seed):/ "
              "{print $2, substr($0, index($0, \":\") + 1)}' | sort -u | while read -r id path; do "
              "[ -f \"$path\" ] && echo \"key $(sha256sum \"$path\" | cut -d' ' -f1) $id\"; done; ")
SNAPSHOT_ADOPTION = (
    "echo \"role=$(tr -d '[:space:]' < /etc/winsvpn/role 2>/dev/null)\"; " + _GATEWAY_ID + _UNIT_KEYS +
    "echo \"identity_file=$(test -s /etc/winn/public/gateway-identity.json && echo present || echo absent)\"; "
    "echo \"backups=$(ls -d /var/backups/winsvpn/winn3-pre-onetouch-* 2>/dev/null | wc -l)\"; "
    "for d in /var/backups/winsvpn/winn3-pre-onetouch-*; do [ -d \"$d\" ] || continue; "
    "echo \"backup_check=$(cd \"$d\" && sha256sum -c --quiet MANIFEST.sha256 >/dev/null 2>&1 && echo ok || echo failed)\"; "
    "echo \"backup_files=$(ls \"$d\" | tr '\\n' ' ')\"; done; "
    "echo \"gateway_active=$(systemctl is-active winn3-gateway.service)\"")
SNAPSHOT_STEP14 = (
    _GATEWAY_ID + _KEYS +
    "echo \"gateway_active=$(systemctl is-active winn3-gateway.service)\"; "
    "echo \"gateway_enabled=$(systemctl is-enabled winn3-gateway.service 2>/dev/null)\"; "
    "echo \"firewall_enabled=$(systemctl is-enabled winn3-gateway-firewall.service 2>/dev/null)\"; "
    "echo \"env_file=$(test -e /etc/winn/winn3-gateway.env && echo present || echo absent)\"; "
    "echo \"listen_9111=$(ss -Hlun 'sport = :9111' | wc -l) $(ss -Hltn 'sport = :9111' | wc -l)\"")


def _keys(text):
    return sorted(tuple(line.split(None, 2)[1:]) for line in (text or "").splitlines() if line.startswith("key "))


def _good_keys(keys):
    return len(keys) == 4 and all(len(k) == 2 and re.fullmatch(r"[0-9a-f]{64}", k[0]) for k in keys)


def evaluate_adoption_node(standalone, adopted):
    """STEP-13 node half (design 2.6): the standalone tree's four keys and gateway id are kept, the role marker
    data-winn3 is rewritten to data-cover, exactly one pre-adoption backup exists and its manifest verifies, and the
    adopted gateway runs with the identity file in place."""
    before, after = kv(standalone), kv(adopted)
    kb, ka = _keys(standalone), _keys(adopted)
    problems = []
    if before.get("role") != "data-winn3":
        problems.append("the tree before the run is not standalone-built (role %r)" % before.get("role"))
    if not _good_keys(kb):
        problems.append("the standalone tree does not hold the four gateway keys")
    if kb != ka:
        problems.append("the adoption changed a gateway key")
    if not before.get("gateway_id") or before.get("gateway_id") != after.get("gateway_id"):
        problems.append("gateway id %r became %r" % (before.get("gateway_id"), after.get("gateway_id")))
    if after.get("role") != "data-cover":
        problems.append("the role marker is %r after the run, not data-cover" % after.get("role"))
    if before.get("backups") != "0" or after.get("backups") != "1":
        problems.append("pre-adoption backups: %s before, %s after (want 0 and 1)" % (before.get("backups"), after.get("backups")))
    if after.get("backup_check") != "ok":
        problems.append("the backup's MANIFEST.sha256 does not verify")
    if "restore.sh" not in (after.get("backup_files") or "") or "manifest.json" not in (after.get("backup_files") or ""):
        problems.append("the backup lacks restore.sh or manifest.json")
    if after.get("identity_file") != "present" or after.get("gateway_active") != "active":
        problems.append("after adoption the identity file is %s and the gateway is %s" % (after.get("identity_file"),
                                                                                        after.get("gateway_active")))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "gateway_id": after.get("gateway_id")}


def evaluate_adoption_hub(adopt, unsuspend, rekey, status):
    """STEP-13 hub half (3.12, 5.5): the g1 descriptor is stored and the signer's reconcile rebuilds the ledger from it
    (the slug suspended, its floor above the stored sequence); an unsuspend with a t1 ticket resumes it; the hub's real
    request builder then presents the stored sequence on the rekey, which issues above the ledger floor under g2."""
    a, u, r, st = (_json(t) for t in (adopt, unsuspend, rekey, status))
    problems = []
    if not a or not a.get("ok") or a.get("stored_status") != 200:
        problems.append("the g1 descriptor was not stored and reconciled: %s" % (a or {}).get("reconcile_error") or (a or {}).get("detail"))
    else:
        if a.get("ledger_state") != "suspended" or a.get("ledger_live_kid") != "g1":
            problems.append("after reconcile the ledger is %s with live kid %s" % (a.get("ledger_state"), a.get("ledger_live_kid")))
        seq = a.get("ledger_live_seq")
        if not isinstance(seq, int) or not isinstance(a.get("ledger_floor"), int) or a["ledger_floor"] <= seq:
            problems.append("the ledger floor %s is not above the stored sequence %s" % (a.get("ledger_floor"), seq))
    if not u or not u.get("ok") or u.get("state") != "active":
        problems.append("unsuspend: %s" % ((u or {}).get("error") or (u or {}).get("state")))
    request = (r or {}).get("request") or {}
    if not r or not r.get("ok"):
        problems.append("the rekey was refused: %s" % (r or {}).get("error"))
    else:
        if a and request.get("expected_prior_seq") != a.get("ledger_live_seq"):
            problems.append("the rekey presented %s, not the stored %s" % (request.get("expected_prior_seq"), a.get("ledger_live_seq")))
        if a and isinstance(a.get("ledger_floor"), int) and not (isinstance(r.get("seq"), int) and r["seq"] > a["ledger_floor"]):
            problems.append("the rekey issued %s, not above the floor %s" % (r.get("seq"), a.get("ledger_floor")))
    if not st or st.get("descriptor_kid") != "g2":
        problems.append("the stored descriptor is %s after the rekey, not g2" % (st or {}).get("descriptor_kid"))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok"}


def evaluate_step14_node(before, rolled_back, restored):
    """STEP-14 node half: --winn3-rollback stops and disables both gateway units, removes the env file and closes
    9111 with every key kept; a normal rerun brings the gateway back with the same keys and gateway id."""
    b, r, s2 = kv(before), kv(rolled_back), kv(restored)
    kb = _keys(before)
    problems = []
    if not _good_keys(kb) or b.get("gateway_active") != "active":
        problems.append("the node was not a running v3 node before the rollback")
    if r.get("gateway_active") not in STOPPED:
        problems.append("the gateway is %s after the rollback" % (r.get("gateway_active") or "not read"))
    if r.get("gateway_enabled") != "disabled" or r.get("firewall_enabled") != "disabled":
        problems.append("a gateway unit is not disabled after the rollback (%s, %s)" % (r.get("gateway_enabled"), r.get("firewall_enabled")))
    if r.get("env_file") != "absent":
        problems.append("the gateway env file is still present after the rollback")
    if r.get("listen_9111") != "0 0":
        problems.append("9111 is still bound after the rollback (%s)" % r.get("listen_9111"))
    if _keys(rolled_back) != kb:
        problems.append("the rollback changed or removed a key")
    if s2.get("gateway_active") != "active" or _keys(restored) != kb:
        problems.append("the rerun did not restore the gateway with the same keys")
    if not b.get("gateway_id") or s2.get("gateway_id") != b.get("gateway_id"):
        problems.append("gateway id %r became %r" % (b.get("gateway_id"), s2.get("gateway_id")))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok"}


def evaluate_step14_hub(hold, withhold, suspend, unsuspend, unhold, status):
    """STEP-14 hub half: the sticky hold bumps the generation first and moves the carrier back to winn/1; the withhold
    bumps it again and keeps the floor; the signer suspends and unsuspends on t1 tickets; the hold is cleared."""
    h, w, su, un, uh, st = (_json(t) for t in (hold, withhold, suspend, unsuspend, unhold, status))
    problems = []
    if not h or not h.get("ok") or not isinstance(h.get("generation_before"), int) or h.get("deployment_generation") != h["generation_before"] + 1:
        problems.append("the hold did not bump the generation: %s" % h)
    elif h.get("winn3_operator_hold") != 1 or h.get("protocol_version") != "winn/1":
        problems.append("after the hold: hold %s, carrier %s" % (h.get("winn3_operator_hold"), h.get("protocol_version")))
    if not w or not w.get("ok") or w.get("descriptor_stored") is not False:
        problems.append("the withhold did not withhold the descriptor")
    if not su or not su.get("ok") or su.get("state") != "suspended":
        problems.append("suspend: %s" % ((su or {}).get("error") or (su or {}).get("state")))
    if not un or not un.get("ok") or un.get("state") != "active":
        problems.append("unsuspend: %s" % ((un or {}).get("error") or (un or {}).get("state")))
    if not uh or not uh.get("ok") or uh.get("winn3_operator_hold") != 0:
        problems.append("the hold was not cleared")
    if not st or st.get("ok") is not True:
        problems.append("no hub status at the end")
    return {"pass": not problems, "reason": "; ".join(problems) or "ok"}
