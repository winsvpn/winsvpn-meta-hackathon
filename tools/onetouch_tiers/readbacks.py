"""Section 5.7 read-backs and decision rules, as code (design v17 5.7, 10.0, 10.3, 10.6).

Two kinds of function:
  * collect_*: the shell command a harness runs on a node to read a value (printed by `tier_b.py plan`).
  * evaluate_*: a pure function from the raw text of that read, or from a list of measurements, to a verdict
    {"pass": bool, "reason": str, ...}. They are the same functions the Tier A and Tier B runs call, and
    tests/test_winn3_onetouch_s7.py checks them on canned data.

No function here measures throughput, latency or connect time on the emulated Tier B guest; the performance
evaluators only judge numbers handed to them, and `refuse_emulated` rejects numbers whose node class is the
qemu-emulated amd64t guest (design fact 4, 5.7).
"""
import json
import math
import re
import statistics

# --- P-1: merged sysctls --------------------------------------------------------------------------------------
GATEWAY_UDP_BUFFER_TARGETS = {
    "net.core.rmem_max": 134217728,
    "net.core.wmem_max": 134217728,
}
SYSCTL_KEYS = ("net.core.rmem_max", "net.core.wmem_max", "net.core.rmem_default", "net.core.wmem_default",
               "net.ipv4.ip_forward", "net.core.netdev_max_backlog")

COLLECT_SYSCTLS = "sysctl -n " + " ".join(SYSCTL_KEYS) + " 2>&1"
# Every setting line (systemd-sysctl's optional leading - included, comments excluded) as path:key=value, so one value
# per key is judged and not only a file count.
COLLECT_SYSCTL_OWNERS = ("grep -H -E '^[[:space:]]*-?net\\.core\\.(rmem|wmem)_max[[:space:]]*=' /etc/sysctl.conf /etc/sysctl.d/*.conf "
                         "/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 2>/dev/null")
# P-1's single owner is the data-plane installer, with one value per key (tools/test_sysctl_single_owner.py), not one
# file: setup_sysctl writes 99-winsvpn-node.conf and wins-edge-hardening's apply_sysctl mirrors the same values into
# 99-winsvpn-edge.conf so load order cannot change them (server/test_data_plane_sysctl_udp_default.py).
DATA_PLANE_SYSCTL_FILES = ("/etc/sysctl.d/99-winsvpn-node.conf", "/etc/sysctl.d/99-winsvpn-edge.conf")


def _sysctl_owner_values(owners_text):
    """{key: {path: [value, ...]}} from COLLECT_SYSCTL_OWNERS lines; None when a line does not parse."""
    found = {}
    for line in (owners_text or "").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"(/[^:\s]+):\s*-?(net\.core\.[rw]mem_max)\s*=\s*([0-9]+)\s*", line)
        if not match:
            return None
        found.setdefault(match.group(2), {}).setdefault(match.group(1), []).append(int(match.group(3)))
    return found


def evaluate_sysctls(text, owners_text="", former_targets=None):
    """P-1: no key is below the gateway's former 60-winn3-gateway-udp-buffers.conf target; one owner sets them: only
    the data-plane installer's files set rmem_max and wmem_max, each to one value, the live one."""
    values = text.split()
    if len(values) != len(SYSCTL_KEYS) or not all(re.fullmatch(r"-?\d+", v) for v in values):
        return {"pass": False, "reason": "unreadable sysctl output: %r" % text[:120]}
    got = dict(zip(SYSCTL_KEYS, map(int, values)))
    targets = dict(GATEWAY_UDP_BUFFER_TARGETS)
    targets.update(former_targets or {})
    low = {k: (got.get(k), floor) for k, floor in targets.items() if got.get(k, -1) < floor}
    owners = _sysctl_owner_values(owners_text)
    problems = []
    if low:
        problems.append("below the gateway's former target: %s" % low)
    if got.get("net.ipv4.ip_forward") != 1:
        problems.append("ip_forward is not 1")
    if owners is None:
        problems.append("unreadable sysctl owners reading: %r" % (owners_text or "")[:200])
        owners = {}
    for key in ("net.core.rmem_max", "net.core.wmem_max"):
        files = owners.get(key, {})
        if not files:
            problems.append("no file read as setting %s (an empty owners reading is not one owner)" % key)
            continue
        others = sorted(set(files) - set(DATA_PLANE_SYSCTL_FILES))
        if others:
            problems.append("a file the data-plane installer does not write sets %s: %s" % (key, others))
        values = sorted({value for found in files.values() for value in found})
        if values != [got[key]]:
            problems.append("%s is set to %s in %s and is %d live; one owner sets one value" % (key, values, sorted(files), got[key]))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "values": got,
            "owners": {key: sorted(files) for key, files in sorted(owners.items())}}


# --- P-1: granted UDP buffers ---------------------------------------------------------------------------------
# The current incarnation only: an older start's line must not vouch for this one. The gateway prints the line once,
# at start, and then a serve status line every second, so the line is selected, never the journal's tail (a tail of
# 400 lines loses it after about 400 s of uptime).
COLLECT_GATEWAY_JOURNAL = ("inv=$(systemctl show winn3-gateway.service -p InvocationID --value 2>/dev/null); "
                           "if [ -n \"$inv\" ]; then journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID=\"$inv\" 2>&1 "
                           "| grep -E 'requested [0-9]+, granted read=' | tail -n 5; "
                           "else echo 'no InvocationID for winn3-gateway.service'; fi")
GRANTED_RE = re.compile(r"requested (\d+), granted read=(\d+) write=(\d+)")
UDP_FLOOR = 8 * 1024 * 1024   # udp_socket_buffers.go:27 (the 8 MiB floor)


def evaluate_granted_buffers(journal_text):
    """Granted sizes are at least 2 x 16777216 (the kernel doubles the request), and at least the 8 MiB floor."""
    found = GRANTED_RE.findall(journal_text)
    if not found:
        return {"pass": False, "reason": "no 'requested N, granted read=R write=W' line in the gateway journal"}
    bad = [(a, b, c) for a, b, c in found if int(b) < 2 * 16777216 or int(c) < 2 * 16777216 or int(b) < UDP_FLOOR or int(c) < UDP_FLOOR]
    return {"pass": not bad, "reason": ("granted below 2 x 16777216: %s" % bad[:3]) if bad else "ok", "lines": found[-2:]}


# --- P-4, P-5: the fleet constants -----------------------------------------------------------------------------
# The data plane's own read-back (wins-node-perf-readback, the WINS_PERF_READBACK here-document) resolves these;
# tests/test_winn3_onetouch_s7.py reads them out of the installer under test, so a drift fails there, not here.
FLEET = {
    "SMALL_RAM_KB": 5000000,
    "WAN_FQ_LIMIT": 131072,
    "WAN_FQ_LIMIT_SMALL": 16384,
    "VPN_FQ_LIMIT": 20480,
    "VPN_FQ_LIMIT_SMALL": 10240,
    "FQ_FLOW_LIMIT": 256,
    # The WAN root carries the v3 tunnel as one flow: 131072 / 32768 since
    # 2026-10-11 (tunnel-speed round 2, Turn 14), the limits in the supplied Canada
    # measurement records.
    "WAN_FQ_FLOW_LIMIT": 32768,
    "FQ_QUANTUM": 1280,
    "FQ_INITIAL_QUANTUM": 25600,
    "FQ_REFILL_US": 1000,
    "WINN3GW_QLEN": 10000,
}


def sections(text):
    """`== name` headed sections of a collector's output: {name: [lines]}. Lines before the first header go to ''."""
    out, name = {"": []}, ""
    for line in (text or "").splitlines():
        match = re.match(r"^== (\S+)\s*$", line)
        if match:
            name = match.group(1)
            out.setdefault(name, [])
        else:
            out.setdefault(name, []).append(line)
    return out


def key_values(lines):
    out = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[a-z_0-9]+", key.strip()):
            out[key.strip()] = value.strip()
    return out


def _int(text):
    return int(text) if text is not None and re.fullmatch(r"\d+", str(text).strip()) else None


def _time_us(text):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(s|sec|secs|ms|msec|msecs|us|usec|usecs)", text or "")
    if not match:
        return None
    scale = {"s": 1000000, "sec": 1000000, "secs": 1000000, "ms": 1000, "msec": 1000,
             "msecs": 1000, "us": 1, "usec": 1, "usecs": 1}[match.group(2)]
    return int(float(match.group(1)) * scale + 0.5)


def fq_fields(line):
    """Fields of one `tc qdisc show` fq line (limit and flow_limit in packets, quantum sizes in bytes), else None.
    tc prints sizes as 1280b, 25Kb or 1Mb, and older releases as a bare number."""
    if not re.match(r"^qdisc fq ", line or ""):
        return None
    fields = {}
    for key in ("limit", "flow_limit"):
        match = re.search(r"\b%s ([0-9]+)p\b" % key, line)
        fields[key] = int(match.group(1)) if match else None
    for key in ("quantum", "initial_quantum"):
        match = re.search(r"\b%s ([0-9]+)(b|Kb|Mb)?(?=\s|$)" % key, line)
        fields[key] = int(match.group(1)) * {None: 1, "b": 1, "Kb": 1024, "Mb": 1048576}[match.group(2)] if match else None
    match = re.search(r"\brefill_delay ([0-9.]+[a-z]+)", line)
    fields["refill_us"] = _time_us(match.group(1)) if match else None
    return fields


def want_limit(mem_kb, large, small):
    return None if mem_kb is None else (small if mem_kb < FLEET["SMALL_RAM_KB"] else large)


# --- P-4: WAN queue ---------------------------------------------------------------------------------------------
COLLECT_WAN_QDISC = ("dev=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") {print $(i+1); exit}}'); "
                     "echo \"dev=$dev\"; echo \"mem_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)\"; "
                     "echo '== root'; tc qdisc show dev \"$dev\" root 2>&1; "
                     "echo '== edge_queues'; systemctl is-enabled wins-edge-queues.service 2>&1; "
                     "echo '== overrides'; grep -hoE '^(export )?(WAN_FQ_|WAN_QDISC_)[A-Z0-9_]+' /root/node.env 2>/dev/null; true")


def evaluate_wan_queue(text, fleet_flow_limit=None):
    """P-4: the WAN root qdisc is fq with the fleet limit for the node's RAM class, the fleet flow_limit, quantum,
    initial_quantum and refill_delay, pacing on and no finite maxrate, and wins-edge-queues.service is enabled. WAN_FQ_* names found in node.env are reported; the values must still be the
    fleet's (design 5.7: they do not depend on any WAN_FQ_* variable)."""
    flow_want = FLEET["WAN_FQ_FLOW_LIMIT"] if fleet_flow_limit is None else int(fleet_flow_limit)
    parts = sections(text)
    facts = key_values(parts.get("", []))
    mem_kb = _int(facts.get("mem_kb"))
    root_lines = [l for l in parts.get("root", []) if l.startswith("qdisc ")]
    root = root_lines[0] if root_lines else ""
    kind = root.split()[1] if len(root.split()) > 1 else "missing"
    fields = fq_fields(root) or {}
    limit_want = want_limit(mem_kb, FLEET["WAN_FQ_LIMIT"], FLEET["WAN_FQ_LIMIT_SMALL"])
    enabled = [l.strip() for l in parts.get("edge_queues", []) if l.strip()]
    problems = []
    if not facts.get("dev"):
        problems.append("no default-route device")
    if kind != "fq":
        problems.append("the WAN root qdisc is %s, not fq" % kind)
    if fields.get("flow_limit") != flow_want:
        problems.append("flow_limit is %s, fleet value %s" % (fields.get("flow_limit"), flow_want))
    if limit_want is None:
        problems.append("MemTotal unreadable, so the fleet limit is unknown")
    elif fields.get("limit") != limit_want:
        problems.append("limit is %s, fleet value %s for MemTotal %s kB" % (fields.get("limit"), limit_want, mem_kb))
    for key, want in (("quantum", FLEET["FQ_QUANTUM"]),
                      ("initial_quantum", FLEET["FQ_INITIAL_QUANTUM"])):
        if fields.get(key) != want:
            problems.append("%s is %s, fleet value %s" % (key, fields.get(key), want))
    refill = fields.get("refill_us")
    if refill is None or not (refill + 100 >= FLEET["FQ_REFILL_US"]
                              and refill < FLEET["FQ_REFILL_US"] + 10000):
        problems.append("refill_delay is outside the fleet tolerance")
    if "nopacing" in root.split() or "maxrate" in root.split():
        problems.append("WAN fq must have pacing enabled and no finite maxrate")
    if enabled != ["enabled"]:
        problems.append("wins-edge-queues.service is not enabled: %s" % enabled)
    overrides = sorted({l.replace("export ", "").strip() for l in parts.get("overrides", []) if l.strip()})
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "dev": facts.get("dev"), "root": kind,
            "limit": fields.get("limit"), "flow_limit": fields.get("flow_limit"), "node_env_overrides": overrides}


# --- P-5: winn3gw0 ----------------------------------------------------------------------------------------------
QUEUE_STATE_PATH = "/run/winsvpn/winn3gw-queues.state"
COLLECT_WINN3GW0 = ("echo '== qdisc'; tc qdisc show dev winn3gw0 2>&1; "
                    "echo '== facts'; echo \"main_pid=$(systemctl show winn3-gateway.service -p MainPID --value)\"; "
                    "echo \"active=$(systemctl is-active winn3-gateway.service)\"; "
                    "echo \"ifindex=$(cat /sys/class/net/winn3gw0/ifindex 2>/dev/null)\"; "
                    "echo \"qlen=$(cat /sys/class/net/winn3gw0/tx_queue_len 2>/dev/null)\"; "
                    "echo \"tx_queues=$(ls -d /sys/class/net/winn3gw0/queues/tx-* 2>/dev/null | wc -l)\"; "
                    "echo \"mem_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)\"; "
                    "echo '== state'; head -c 8192 " + QUEUE_STATE_PATH + " 2>&1; echo; "
                    "echo '== helper'; systemctl show wins-winn3gw-queues.service -p Result -p ExecMainStatus 2>&1; true")


def _child_matches(fields, limit):
    return bool(fields and fields["limit"] == limit and fields["flow_limit"] == FLEET["FQ_FLOW_LIMIT"]
                and fields["quantum"] == FLEET["FQ_QUANTUM"] and fields["initial_quantum"] == FLEET["FQ_INITIAL_QUANTUM"]
                and fields["refill_us"] is not None
                and fields["refill_us"] + 100 >= FLEET["FQ_REFILL_US"] and fields["refill_us"] < FLEET["FQ_REFILL_US"] + 10000)


def evaluate_winn3gw0(text, fleet_qlen=None):
    """P-5: root mq with one calibrated fq child per TX queue (or root fq on a one-queue device), the device qlen the
    fleet constant, and the helper's state file naming result ok, the CURRENT gateway MainPID and winn3gw0 ifindex."""
    qlen_want = FLEET["WINN3GW_QLEN"] if fleet_qlen is None else int(fleet_qlen)
    parts = sections(text)
    facts = key_values(parts.get("facts", []))
    lines = [l for l in parts.get("qdisc", []) if l.startswith("qdisc ")]
    root = next((l for l in lines if " root" in l), "")
    kind = root.split()[1] if len(root.split()) > 1 else "missing"
    children = [l for l in lines if " parent " in l]
    parents = {m.group(1) for m in (re.search(r" parent (\S+)", l) for l in children) if m}
    queues = _int(facts.get("tx_queues"))
    limit = want_limit(_int(facts.get("mem_kb")), FLEET["VPN_FQ_LIMIT"], FLEET["VPN_FQ_LIMIT_SMALL"])
    problems = []
    if facts.get("active") != "active":
        problems.append("winn3-gateway.service is %s" % facts.get("active"))
    if limit is None:
        problems.append("MemTotal unreadable, so the calibrated fq limit is unknown")
    if kind == "mq":
        if not queues or len(children) != queues or len(parents) != queues:
            problems.append("%s fq children over %s parents for %s TX queues" % (len(children), len(parents), queues))
        bad = [l for l in children if not _child_matches(fq_fields(l), limit)]
        if bad:
            problems.append("a child is not fq with the fleet values: %s" % bad[0][:160])
    elif kind == "fq" and queues == 1:
        if not _child_matches(fq_fields(root), limit):
            problems.append("the single-queue root fq is not calibrated: %s" % root[:160])
    else:
        problems.append("winn3gw0 root is %s with %s TX queues" % (kind, queues))
    if _int(facts.get("qlen")) != qlen_want:
        problems.append("qlen is %s, fleet value %s" % (facts.get("qlen"), qlen_want))
    state_text = "\n".join(parts.get("state", [])).strip()
    try:
        state = json.loads(state_text)
    except ValueError:
        state = None
    if not isinstance(state, dict):
        problems.append("the helper state file is missing or unreadable")
    else:
        if state.get("result") != "ok":
            problems.append("helper result %s: %s" % (state.get("result"), state.get("reason")))
        if state.get("main_pid") is None or state.get("main_pid") != _int(facts.get("main_pid")):
            problems.append("state main_pid %s is not the current MainPID %s" % (state.get("main_pid"), facts.get("main_pid")))
        if state.get("ifindex") is None or state.get("ifindex") != _int(facts.get("ifindex")):
            problems.append("state ifindex %s is not the current winn3gw0 ifindex %s" % (state.get("ifindex"), facts.get("ifindex")))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "root": kind, "children": len(children),
            "main_pid": facts.get("main_pid"), "ifindex": facts.get("ifindex")}


def evaluate_restart_series(rows, required=20, reboots=3):
    """20 of 20 restarts and 3 of 3 reboots must match, and the helper ran once per restart (P-5)."""
    restarts = [r for r in rows if r.get("kind") == "restart"]
    boots = [r for r in rows if r.get("kind") == "reboot"]
    bad = [r for r in restarts + boots if not r.get("matched") or r.get("helper_runs") != 1]
    problems = []
    if len(restarts) < required:
        problems.append("only %d of %d restarts recorded" % (len(restarts), required))
    if len(boots) < reboots:
        problems.append("only %d of %d reboots recorded" % (len(boots), reboots))
    if bad:
        problems.append("%d run(s) did not match with exactly one helper run" % len(bad))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok"}


# One line per restart or reboot, printed by the TB-21 collectors. The helper state is inlined as its JSON text.
SERIES_RE = re.compile(r"^kind=(restart|reboot) run=(\d+) main=(\S*) ifindex=(\S*) helper_runs=(\S*) old_main=(\S*) state=(.*)$")


def parse_restart_series(*texts):
    """Rows for evaluate_restart_series from the raw TB-21 captures. A row matches when the helper's state file says
    result ok and names the gateway MainPID and winn3gw0 ifindex read in the same breath; a restart must also have
    produced a new MainPID. A line that does not parse is kept as an unmatched row, so it can only fail the series."""
    rows = []
    for text in texts:
        for line in (text or "").splitlines():
            if not line.startswith("kind="):
                continue
            match = SERIES_RE.match(line.strip())
            if not match:
                rows.append({"kind": "unparsed", "matched": False, "helper_runs": None, "line": line[:200]})
                continue
            kind, run, main, ifindex, helper, old_main, state_text = match.groups()
            try:
                state = json.loads(state_text)
            except ValueError:
                state = None
            matched = (isinstance(state, dict) and state.get("result") == "ok" and _int(main) is not None
                       and state.get("main_pid") == _int(main) and _int(ifindex) is not None
                       and state.get("ifindex") == _int(ifindex))
            if kind == "restart" and (_int(old_main) is None or _int(old_main) == _int(main)):
                matched = False
            rows.append({"kind": kind, "run": int(run), "matched": bool(matched), "helper_runs": _int(helper),
                         "main": main, "ifindex": ifindex})
    return rows


# TB-21's collectors. Each restart is the automatic one after a SIGKILL (Restart=on-failure, RestartSec=2). The gateway
# unit allows 5 starts in 60 s (StartLimitIntervalSec=60, StartLimitBurst=5, DP 27891), so starts are paced at least
# 15 s apart; faster kills would trip the start limit and fail the unit, which is not what P-5 asks. A row is read once
# the gateway is active under a new MainPID and the helper's state names it (bounded at 60 s); the helper runs are
# counted by distinct invocation ids of wins-winn3gw-queues.service since the kill.
SERIES_HELPER_RUNS = ("python3 -c 'import json,sys; print(len({(d.get(\"_SYSTEMD_INVOCATION_ID\") or d.get(\"INVOCATION_ID\")) "
                      "for d in map(json.loads, filter(str.strip, sys.stdin))} - {None}))'")
COLLECT_RESTART_SERIES = (
    "st=/run/winsvpn/winn3gw-queues.state; "
    "for i in $(seq 1 20); do "
    "old=$(systemctl show winn3-gateway.service -p MainPID --value); t=$(date +%s); "
    "systemctl kill -s KILL winn3-gateway.service; main=; "
    "for w in $(seq 1 120); do sleep 0.5; m=$(systemctl show winn3-gateway.service -p MainPID --value); "
    "if [ \"$(systemctl is-active winn3-gateway.service)\" = active ] && [ \"$m\" != 0 ] && [ \"$m\" != \"$old\" ] "
    "&& grep -q \"\\\"main_pid\\\":$m,\" $st 2>/dev/null; then main=$m; break; fi; done; "
    "sleep 2; "
    "runs=$(journalctl -u wins-winn3gw-queues.service --since \"@$t\" -o json --no-pager 2>/dev/null | " + SERIES_HELPER_RUNS + "); "
    "echo \"kind=restart run=$i main=${main:-$(systemctl show winn3-gateway.service -p MainPID --value)} "
    "ifindex=$(cat /sys/class/net/winn3gw0/ifindex 2>/dev/null) helper_runs=$runs old_main=$old state=$(tr -d '\\n' < $st 2>/dev/null)\"; "
    "while [ $(( $(date +%s) - t )) -lt 15 ]; do sleep 1; done; "
    "done")
COLLECT_REBOOT_LINE = (
    "st=/run/winsvpn/winn3gw-queues.state; main=; "
    "for w in $(seq 1 360); do m=$(systemctl show winn3-gateway.service -p MainPID --value); "
    "if [ \"$(systemctl is-active winn3-gateway.service)\" = active ] && [ \"$m\" != 0 ] "
    "&& grep -q \"\\\"main_pid\\\":$m,\" $st 2>/dev/null; then main=$m; break; fi; sleep 0.5; done; "
    "runs=$(journalctl -b -u wins-winn3gw-queues.service -o json --no-pager 2>/dev/null | " + SERIES_HELPER_RUNS + "); "
    "echo \"kind=reboot run={boot} main=${main:-$(systemctl show winn3-gateway.service -p MainPID --value)} "
    "ifindex=$(cat /sys/class/net/winn3gw0/ifindex 2>/dev/null) helper_runs=$runs old_main=- state=$(tr -d '\\n' < $st 2>/dev/null)\"")


def evaluate_restart_series_capture(*texts):
    """TB-21's evaluate step: the raw captures of the restart loop and of each reboot, judged by evaluate_restart_series.
    Every row must be a distinct run number per kind, so a duplicated line cannot fill the count."""
    rows = parse_restart_series(*texts)
    unparsed = [r for r in rows if r["kind"] == "unparsed"]
    seen, duplicate = set(), False
    for r in rows:
        key = (r["kind"], r.get("run"))
        duplicate = duplicate or key in seen
        seen.add(key)
    verdict = evaluate_restart_series([r for r in rows if r["kind"] != "unparsed"])
    problems = [] if verdict["pass"] else [verdict["reason"]]
    if unparsed:
        problems.append("%d unparsed series line(s)" % len(unparsed))
    if duplicate:
        problems.append("a run number appears twice")
    return {"pass": not problems, "reason": "; ".join(problems) or "ok",
            "restarts": len([r for r in rows if r["kind"] == "restart"]), "reboots": len([r for r in rows if r["kind"] == "reboot"])}


# --- P-9, A-1: forward-async gate ------------------------------------------------------------------------------
# The gateway logs "winn3-gateway: -forward-async-write enabled: 2.00 usable CPUs (affinity 2, ...)"
# (forward_cpugate.go: state "enabled", or "DISABLED (...)", then ": %.2f usable CPUs"); the data plane's read-back uses the same form.
GATE_RE = re.compile(r"-forward-async-write (enabled|ENABLED|DISABLED)\b.*?: ([0-9]+(?:\.[0-9]+)?) usable CPUs")
ASYNC_FLAG_RE = re.compile(r"[ \t]-forward-async-write(=true|=1)?([ \t;]|$)")
COLLECT_FORWARD_ASYNC = ("echo '== execstart'; systemctl show winn3-gateway.service -p ExecStart --value; "
                         "inv=$(systemctl show winn3-gateway.service -p InvocationID --value); "
                         "echo '== gate'; journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID=\"$inv\" 2>/dev/null "
                         "| grep -E -- '-forward-async-write (enabled|ENABLED|DISABLED)' | tail -n 1; "
                         "echo '== cpus'; cg=$(systemctl show winn3-gateway.service -p ControlGroup --value); "
                         "cat \"/sys/fs/cgroup${cg}/cpuset.cpus.effective\" 2>/dev/null || cat /sys/fs/cgroup/cpuset.cpus.effective; true")


def cpu_list_count(text):
    """`0-3,6` -> 5. None when it does not parse."""
    text = (text or "").strip()
    if not text or not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", text):
        return None
    count = 0
    for part in text.split(","):
        low, _, high = part.partition("-")
        count += (int(high) - int(low) + 1) if high else 1
    return count


def evaluate_forward_async(gate_line, usable_cpus, flag_present):
    """With the flag set the gate line reads enabled with N >= 2 usable CPUs; with 1 usable CPU the flag is absent.
    gate_line is the gateway's own line; usable_cpus is the count the harness read (cpuset of the gateway's cgroup)."""
    match = GATE_RE.search(gate_line or "")
    if usable_cpus is not None and usable_cpus < 2:
        return {"pass": not flag_present, "reason": "ok" if not flag_present else "the flag is present on a 1-CPU gateway"}
    if not flag_present:
        enabled = bool(match and match.group(1).lower() == "enabled")
        return {"pass": not enabled, "reason": "ok (flag absent)" if not enabled else "an enabled gate line without the flag"}
    ok = bool(match and match.group(1).lower() == "enabled" and float(match.group(2)) >= 2)
    return {"pass": ok, "reason": "ok" if ok else "flag set but the gate line is %r" % (gate_line or "")[:200]}


def judge_forward_async(text):
    """TB-20's P-9 evaluate step on the raw COLLECT_FORWARD_ASYNC capture."""
    parts = sections(text)
    execstart = " ".join(parts.get("execstart", []))
    gate = next((l for l in reversed(parts.get("gate", [])) if l.strip()), "")
    cpus = cpu_list_count(next((l for l in parts.get("cpus", []) if l.strip()), ""))
    flag = ASYNC_FLAG_RE.search(" " + execstart + " ") is not None
    verdict = evaluate_forward_async(gate, cpus, flag)
    if cpus is None and flag:
        verdict = {"pass": False, "reason": "the gateway cgroup's cpuset is unreadable while the flag is set"}
    verdict.update({"flag_present": flag, "usable_cpus": cpus, "gate_line": gate[:200]})
    if not execstart.strip():
        verdict.update({"pass": False, "reason": "no ExecStart read for winn3-gateway.service"})
    return verdict


# --- go-live latency (5.7) ---------------------------------------------------------------------------------------
def _finite(value):
    """A measurement the performance rules can judge: an int or float that is finite (never a bool)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def percentile(values, p):
    ordered = sorted(values)
    if not ordered:
        raise ValueError("no values")
    rank = max(0, min(len(ordered) - 1, int(-(-p * len(ordered) // 100)) - 1))
    return ordered[rank]


def evaluate_golive(runs, budget=180.0, minimum_runs=10):
    """p95 of completed->operator_enabled over at least 10 fresh installs, and every proof's ok_at after completion."""
    if len(runs) < minimum_runs:
        return {"pass": False, "reason": "only %d runs, %d required" % (len(runs), minimum_runs)}
    unread = [r for r in runs if not (_finite(r.get("completed")) and _finite(r.get("enabled")) and r.get("proof_ok_at")
                                      and all(_finite(t) for t in r["proof_ok_at"].values()))]
    if unread:
        return {"pass": False, "reason": "%d run(s) lack a numeric completed, enabled or proof ok_at reading" % len(unread)}
    stale = [r for r in runs if any(t <= r["completed"] for t in r["proof_ok_at"].values())]
    durations = [r["enabled"] - r["completed"] for r in runs]
    p95 = percentile(durations, 95)
    problems = []
    if stale:
        problems.append("%d run(s) used a proof older than completion" % len(stale))
    if p95 > budget:
        problems.append("p95 %.1f s exceeds %.0f s" % (p95, budget))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "p95": p95}


# --- connect time (5.7) --------------------------------------------------------------------------------------------
def evaluate_connect(samples, limit=4.0, minimum_runs=10):
    """10 runs per network type and node class, p95 at most 4.0 s in each.

    samples: {(network, node_class): [seconds, ...]}.
    """
    results, problems = {}, []
    if not samples:
        problems.append("no connect-time samples")
    for key, values in sorted(samples.items()):
        if len(values) < minimum_runs:
            problems.append("%s: only %d runs" % (key, len(values)))
            continue
        if not all(_finite(v) for v in values):
            problems.append("%s: a sample is not a number" % (key,))
            continue
        p95 = percentile(values, 95)
        results[key] = p95
        if p95 > limit:
            problems.append("%s: p95 %.2f s exceeds %.1f s" % (key, p95, limit))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "p95": results}


def stage_blocks_signoff(stage_now, stage_baseline, noise):
    """A miss blocks S7 sign-off only if the same stage is slower than baseline beyond its own run noise."""
    return stage_now - stage_baseline > noise


# --- uncapped Ryzen acceptance run (5.7) -------------------------------------------------------------------------
def evaluate_ryzen(up_gbit, down_gbit, target=1.8, minimum_runs=10):
    """Median at least 1.8 Gbit/s in each direction over at least 10 runs per direction."""
    problems = []
    medians = {}
    for name, values in (("up", up_gbit), ("down", down_gbit)):
        if len(values) < minimum_runs:
            problems.append("%s: only %d runs" % (name, len(values)))
            continue
        if not all(_finite(v) for v in values):
            problems.append("%s: a run is not a number" % name)
            continue
        medians[name] = statistics.median(values)
        if medians[name] < target:
            problems.append("%s: median %.3f Gbit/s below %.1f" % (name, medians[name], target))
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "median": medians, "blocks_s7": False}


# --- rule R (10.0) ---------------------------------------------------------------------------------------------------
# Item 1: a candidate that is worse than the base beyond the run's own base-against-base noise on any of these is rejected.
# Item 1 names AWG and Xray throughput only; a lower v3 throughput fails item 2 ("throughput not lower beyond noise") and
# item 3's both-improve clause, so it is judged after item 1 with branch 2.
RULE_R_HIGHER_IS_WORSE = ("rise_ms", "p99_rise_ms", "jitter_ms", "loss", "awg_p99_ms", "xray_p99_ms")
RULE_R_LOWER_IS_WORSE = ("awg_throughput_gbit", "xray_throughput_gbit")
# Read on both sides of every trial; the optional keys are compared only where the run recorded them, and then on both
# sides: a key one side lacks is a missing reading, never "not worse".
RULE_R_REQUIRED = ("rise_ms", "throughput_gbit", "loss", "jitter_ms")
RULE_R_OPTIONAL = ("p99_rise_ms", "awg_p99_ms", "xray_p99_ms", "awg_throughput_gbit", "xray_throughput_gbit",
                   "start_failure_rate", "cpu_pct")


def rule_r_adopt(base, candidate, bar_ms=50.0, noise=None, cpu_ceiling_points=None):
    """Rule R (10.0) in its own order: item 1 rejects, item 2 needs the trial's purpose served, item 3 applies the 50 ms bar.

    base/candidate: one netem profile's rise_ms (loaded p50 rise over idle), throughput_gbit, loss (loaded
    probe loss) and jitter_ms; where the run recorded them also p99_rise_ms, awg_/xray_ figures, start_failure_rate,
    new_failure_class and cpu_pct. noise: the run's base-against-base spread per key (0 where absent).
    cpu_ceiling_points: 5 for busy polling (P-3) on a 4-vCPU node. A trial judges both profiles: rule_r_adopt_profiles.
    A reading the rule needs that is missing on either side, or is not a finite number, raises ValueError.
    """
    noise = noise or {}
    needed = set(RULE_R_REQUIRED) | {k for k in RULE_R_OPTIONAL if k in base or k in candidate}
    if cpu_ceiling_points is not None:
        needed.add("cpu_pct")
    missing = sorted(k for k in needed if not (_finite(base.get(k)) and _finite(candidate.get(k))))
    missing += sorted("noise " + k for k, v in noise.items() if not _finite(v))
    if missing:
        raise ValueError("rule R has no numeric reading on both sides for: %s" % ", ".join(missing))

    def beyond(key, worse_sign):
        if key not in base or key not in candidate:
            return False
        return worse_sign * (candidate[key] - base[key]) > noise.get(key, 0)

    for key in RULE_R_HIGHER_IS_WORSE:
        if beyond(key, 1):
            return {"adopt": False, "branch": "1", "reason": "%s worse beyond noise" % key}
    for key in RULE_R_LOWER_IS_WORSE:
        if beyond(key, -1):
            return {"adopt": False, "branch": "1", "reason": "%s lower beyond noise" % key}
    if candidate.get("new_failure_class"):
        return {"adopt": False, "branch": "1", "reason": "a new session-failure class"}
    if ("start_failure_rate" in base and "start_failure_rate" in candidate
            and candidate["start_failure_rate"] > base["start_failure_rate"] + 1.0 / 200):
        return {"adopt": False, "branch": "1", "reason": "start-failure rate above the base rate plus 1 in 200"}
    if cpu_ceiling_points is not None and candidate.get("cpu_pct", 0) - base.get("cpu_pct", 0) > cpu_ceiling_points:
        return {"adopt": False, "branch": "1", "reason": "CPU use above the %s point ceiling" % cpu_ceiling_points}
    if beyond("throughput_gbit", -1):
        return {"adopt": False, "branch": "2", "reason": "throughput_gbit lower beyond noise"}
    if beyond("rise_ms", -1):
        verdict = {"adopt": True, "branch": "3(a)"}
        if candidate["rise_ms"] > bar_ms:
            verdict["owner_bar"] = "owner bar not met: rise %g ms, gap %g ms" % (candidate["rise_ms"], candidate["rise_ms"] - bar_ms)
        return verdict
    if beyond("throughput_gbit", 1):
        if candidate["rise_ms"] <= bar_ms:
            return {"adopt": True, "branch": "3(b)"}
        # 3(b): the base stays; the paired numbers go to the owner as a ruling candidate, nothing is adopted without a ruling
        return {"adopt": False, "branch": "3(b)", "owner_ruling_candidate": True,
                "reason": "throughput gain at a rise of %g ms, above the %g ms bar" % (candidate["rise_ms"], bar_ms)}
    return {"adopt": False, "branch": "2", "reason": "the trial's purpose is not served beyond noise"}


def rule_r_adopt_profiles(base, candidate, bar_ms=50.0, noise=None, cpu_ceiling_points=None):
    """Rule R over the paired netem profiles (10.0: "on both netem profiles"). base, candidate and noise map a profile
    name to what rule_r_adopt takes for that profile. Item 1 rejects on a rise beyond noise in ANY profile, so the worse
    profile alone is not enough; the candidate is adopted only when every profile adopts it."""
    if not base or set(base) != set(candidate):
        raise ValueError("base and candidate must cover the same netem profiles")
    verdicts = {p: rule_r_adopt(base[p], candidate[p], bar_ms, (noise or {}).get(p), cpu_ceiling_points) for p in sorted(base)}
    for profile, verdict in verdicts.items():
        if verdict["branch"] == "1":
            return dict(verdict, profile=profile)
    for profile, verdict in verdicts.items():
        if not verdict["adopt"]:
            return dict(verdict, profile=profile)
    merged = {"adopt": True, "branch": "+".join(sorted({v["branch"] for v in verdicts.values()}))}
    bars = ["%s: %s" % (p, v["owner_bar"]) for p, v in verdicts.items() if "owner_bar" in v]
    if bars:
        merged["owner_bar"] = "; ".join(bars)
    return merged


# --- hub cost (5.7) --------------------------------------------------------------------------------------------------
def evaluate_cache_bounds(entries_after_10000, cap=256):
    return {"pass": entries_after_10000 <= cap, "reason": "ok" if entries_after_10000 <= cap else "cache holds %d entries" % entries_after_10000}


def refuse_emulated(node_class):
    """Performance figures never come from the emulated Tier B guest (fact 4)."""
    if node_class.get("emulated") or node_class.get("virt") == "qemu":
        raise ValueError("a performance figure was offered from the emulated amd64t guest; refused")
    if not node_class.get("virt"):
        raise ValueError("the node class carries no virt reading, so emulation cannot be ruled out; refused")
    return True
