#!/usr/bin/env python3
"""Design v17 10.2 P-5: the winn3gw0 queue owner (wins-winn3gw-queues).

The data-plane installer's edge script (`wins-edge-hardening --winn3gw-queues`,
run by wins-winn3gw-queues.service after every start of winn3-gateway.service)
is extracted from its heredoc and run against a sandbox: a fake
/sys/class/net/winn3gw0 and /proc/meminfo, and stub tc, ip, systemctl and sleep
programs on PATH. The tc stub models the kernel's qdisc state per device (the
default mq root with default fq children that lane L13 read on France, mq
handles, per-queue classes) and prints what iproute2 prints, sizes included
("quantum 1280b initial_quantum 25Kb"). wins-node-perf-readback, extracted from
the same installer, then reads the same sandbox, so every case checks that the
record the queue owner writes is the one P1's postflight and heartbeat accept
or reject. Nothing touches the host.

What it proves:
  - a correctly configured forwarding gateway (2 or 4 TX queues, mq or not, a
    single-queue device, a small node) gets the calibrated queue and an `ok`
    record bound to its MainPID and ifindex, and P1's --check passes;
  - a wrong queue count (missing mq classes, a child missing from the read-back,
    no TX queue), a forced tc failure after an automatic restart, a qlen that
    cannot be set and a 30 s device-wait timeout each leave a `failed` record
    with the MainPID and ifindex, a non-zero exit, and P1's --check failing;
  - two tries within the 30 s wait; a device that appears late or is recreated
    mid-try is still set; a restart makes the record stale and the next run
    renews it; a reflector gets no record; environment queue values are ignored;
  - the unit text (Type=oneshot, no RemainAfterExit, After=, PartOf=, WantedBy=
    the gateway) and phase C's wiring (unit enabled as a Wants= link before the
    gateway restart, the step run after readiness also when nothing restarted,
    a failed step left to the postflight read-back).

usage: python3 -B -m pytest -q -p no:cacheprovider server/test_winn3gw_queues_p5.py
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import _toolchain  # noqa: E402  (V-01 preflight)

INSTALLER = Path(os.environ.get("P5_DATA_PLANE_INSTALLER", HERE / "wins_data_plane_setup_ONETOUCH.sh"))
SOURCE = INSTALLER.read_text(encoding="utf-8")
BASH = _toolchain.bash4()
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PY = sys.executable
INVOCATION = "0123456789abcdef0123456789abcdef"
FORWARDING = ("{ path=/usr/local/libexec/winn/winn3-gateway ; argv[]=/usr/local/libexec/winn/winn3-gateway serve "
              "-plan udp -max-sessions 22 -forward -forward-if winn3gw0 -resolver ; ignore_errors=no }")
REFLECTOR = ("{ path=/usr/local/libexec/winn/winn3-gateway ; argv[]=/usr/local/libexec/winn/winn3-gateway serve "
             "-plan udp -max-sessions 22 ; ignore_errors=no }")
CALIBRATED = ["limit", "20480", "flow_limit", "256", "refill_delay", "1ms", "quantum", "1280",
              "initial_quantum", "25600"]


def heredoc(opener, terminator, text=SOURCE):
    start = text.index(opener)
    start = text.index("\n", start) + 1
    end = text.index("\n" + terminator + "\n", start)
    return text[start:end] + "\n"


def function(name, text=SOURCE):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", text, re.S | re.M)
    assert match, f"{name}() not found in the installer"
    return match.group(0)


EDGE = heredoc("cat > /usr/local/bin/wins-edge-hardening <<'WINS_EDGE_EOF'", "WINS_EDGE_EOF")
PERF = heredoc("cat > /usr/local/bin/wins-node-perf-readback <<'EOF_PERF'", "EOF_PERF")

# ---------------------------------------------------------------------------
# Stubs. Each is a Python program (this interpreter) or a short bash script.
# ---------------------------------------------------------------------------
TC_STUB = r'''
import json, math, os, subprocess, sys
FX = os.environ["FX"]
NET = os.environ["FX_SYSNET"]
args = sys.argv[1:]
with open(os.path.join(FX, "tc.log"), "a") as fh:
    fh.write(" ".join(args) + "\n")
count_path = os.path.join(FX, "tc.count")
count = int(open(count_path).read()) + 1 if os.path.exists(count_path) else 1
open(count_path, "w").write(str(count))
hook = os.path.join(FX, "on_tc_%d.sh" % count)
if os.path.exists(hook):
    subprocess.run(["/bin/bash", hook], check=True)
DEFAULT = {"limit": 10000, "flow_limit": 100, "quantum": 2746, "initial_quantum": 13730, "refill_delay": "40ms"}
state_path = os.path.join(FX, "tc_state.json")
state = json.load(open(state_path)) if os.path.exists(state_path) else {}


def queues(dev):
    base = os.path.join(NET, dev, "queues")
    return len([n for n in os.listdir(base) if n.startswith("tx-")]) if os.path.isdir(base) else 0


def default(dev):
    n = queues(dev)
    if n > 1:
        return {"root": {"kind": "mq", "handle": "0"}, "children": {str(i): dict(DEFAULT) for i in range(1, n + 1)}}
    return {"root": {"kind": "fq", "handle": "8001", "p": dict(DEFAULT)}, "children": {}}


def size(n):
    kilo, mega = 1024, 1024 * 1024
    if n >= mega and abs(mega * round(n / mega) - n) < 1024:
        return "%dMb" % round(n / mega)
    if n >= kilo and abs(kilo * round(n / kilo) - n) < 16:
        return "%dKb" % round(n / kilo)
    return "%db" % n


def refill(text):
    step = os.path.join(FX, "refill_round_ms")
    if not os.path.exists(step):
        return text
    unit = int(open(step).read())
    value = float(text[:-2]) if text.endswith("ms") else float(text[:-2]) / 1000.0
    return "%dms" % (math.ceil(value / unit) * unit)


def fq(p, where):
    return ("qdisc fq %s limit %dp flow_limit %dp buckets 1024 orphan_mask 1023 quantum %s initial_quantum %s "
            "low_rate_threshold 550Kbit refill_delay %s timer_slack 10us horizon 10s horizon_drop"
            % (where, p["limit"], p["flow_limit"], size(p["quantum"]), size(p["initial_quantum"]),
               refill(p["refill_delay"])))


def parse_fq(rest):
    p = dict(DEFAULT)
    if not rest or rest[0] != "fq" or len(rest) % 2 != 1:
        sys.exit(1)
    for key, value in zip(rest[1::2], rest[2::2]):
        if key not in p:
            sys.exit(1)
        p[key] = value if key == "refill_delay" else int(value)
    return p


def fail_replace():
    path = os.path.join(FX, "tc_fail_replace")
    if not os.path.exists(path):
        return False
    left = open(path).read().strip()
    if left == "all":
        return True
    if int(left) > 0:
        open(path, "w").write(str(int(left) - 1))
        return True
    return False


if args[:2] == ["class", "show"] and len(args) == 4:
    dev = args[3]
    if not os.path.isdir(os.path.join(NET, dev)):
        sys.exit(1)
    dstate = state.get(dev) or default(dev)
    if dstate["root"]["kind"] == "mq":
        h = "" if dstate["root"]["handle"] == "0" else dstate["root"]["handle"]
        for n in range(1, dstate.get("classes", queues(dev)) + 1):
            print("class mq %s:%x root" % (h, n))
    sys.exit(0)
if args[:3] != ["qdisc", args[1] if len(args) > 1 else "", "dev"] or len(args) < 4:
    sys.exit(1)
verb, dev, rest = args[1], args[3], args[4:]
if not os.path.isdir(os.path.join(NET, dev)):
    sys.stderr.write("Cannot find device \"%s\"\n" % dev)
    sys.exit(1)
dstate = state.get(dev) or default(dev)
if verb == "show":
    if os.path.exists(os.path.join(FX, "tc_show_fail")):
        sys.exit(1)
    root = dstate["root"]
    if root["kind"] == "mq":
        lines = ["qdisc mq %s: root" % root["handle"]]
        parent = "" if root["handle"] == "0" else root["handle"]
        hidden = int(open(os.path.join(FX, "tc_hide_children")).read()) if os.path.exists(os.path.join(FX, "tc_hide_children")) else 0
        kids = sorted(dstate["children"].items(), key=lambda kv: int(kv[0]))
        for n, p in kids[:len(kids) - hidden]:
            lines.append(fq(p, "0: parent %s:%x" % (parent, int(n))))
    else:
        lines = [fq(root["p"], "%s: root refcnt 2" % root["handle"])]
    if rest == ["root"]:
        lines = lines[:1]
    print("\n".join(lines))
    sys.exit(0)
if verb != "replace":
    sys.exit(1)
if fail_replace():
    sys.stderr.write("RTNETLINK answers: Operation not permitted\n")
    sys.exit(2)
n_tx = queues(dev)
if rest[:1] == ["root"] and rest[1:2] in (["fq"], ["fq_codel"]) and os.path.exists(os.path.join(FX, "tc_fail_root_fq_" + dev)):
    sys.stderr.write("Error: Specified qdisc kind is unknown.\n")
    sys.exit(2)
if rest[:4] == ["root", "handle", "1:", "mq"] and len(rest) == 4:
    if n_tx < 2 or os.path.exists(os.path.join(FX, "tc_fail_root_mq_" + dev)):
        sys.stderr.write("Error: Operation not supported.\n")
        sys.exit(2)
    classes = dstate.get("classes", n_tx)
    if dstate["root"] == {"kind": "mq", "handle": "1"}:
        sys.exit(0)  # the same kind with no options: the kernel changes nothing
    dstate = {"root": {"kind": "mq", "handle": "1"}, "classes": classes,
              "children": {str(i): dict(DEFAULT) for i in range(1, classes + 1)}}
elif rest[:1] == ["root"]:
    dstate = {"root": {"kind": "fq", "handle": "8002", "p": parse_fq(rest[1:])}, "children": {}}
elif rest[:1] == ["parent"] and len(rest) >= 2:
    major, _, minor = rest[1].partition(":")
    root = dstate["root"]
    classes = dstate.get("classes", n_tx)
    # Like the kernel (sch_api.c qdisc_lookup refuses handle 0): a parent whose
    # major is 0 is never found, so the default "mq 0:" root cannot be named.
    if int(major or "0", 16) == 0 or root["kind"] != "mq" or major != root["handle"] or not minor \
            or int(minor, 16) > classes or int(minor, 16) < 1:
        sys.stderr.write("Error: Failed to find specified qdisc.\n")
        sys.exit(2)
    dstate["children"][str(int(minor, 16))] = parse_fq(rest[2:])
else:
    sys.exit(1)
state[dev] = dstate
json.dump(state, open(state_path, "w"))
'''

IP_STUB = r'''
import os, sys
FX = os.environ["FX"]
NET = os.environ["FX_SYSNET"]
args = sys.argv[1:]
with open(os.path.join(FX, "ip.log"), "a") as fh:
    fh.write(" ".join(args) + "\n")
if args[:2] == ["route", "get"]:
    print("1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0")
    sys.exit(0)
if len(args) == 6 and args[:3] == ["link", "set", "dev"] and args[4] == "txqueuelen":
    if os.path.exists(os.path.join(FX, "ip_fail")) or not os.path.isdir(os.path.join(NET, args[3])):
        sys.exit(2)
    if not os.path.exists(os.path.join(FX, "ip_ignored")):
        open(os.path.join(NET, args[3], "tx_queue_len"), "w").write(args[5] + "\n")
    sys.exit(0)
sys.exit(1)
'''

SYSTEMCTL_STUB = r'''
import json, os, sys
FX = os.environ["FX"]
args = sys.argv[1:]
with open(os.path.join(FX, "systemctl.log"), "a") as fh:
    fh.write(" ".join(args) + "\n")
facts = json.load(open(os.path.join(FX, "systemctl.json")))
if args[:1] != ["show"]:
    sys.exit(0)
names = [args[i + 1] for i, a in enumerate(args) if a == "-p" and i + 1 < len(args)]
for name in names:
    value = facts.get(name, "")
    print(value if "--value" in args else "%s=%s" % (name, value))
'''

SLEEP_STUB = r'''#!/bin/bash
n=$(( $(cat "${FX}/sleep.count" 2>/dev/null || echo 0) + 1 ))
echo "${n}" > "${FX}/sleep.count"
if [[ -f "${FX}/on_sleep_${n}.sh" ]]; then /bin/bash "${FX}/on_sleep_${n}.sh"; fi
exit 0
'''

JOURNALCTL_STUB = r'''#!/bin/bash
inv=""
for a in "$@"; do case "$a" in _SYSTEMD_INVOCATION_ID=*) inv="${a#*=}" ;; esac; done
[[ -n "$inv" ]] || exit 1
case " $* " in *" -g "*) exit 1 ;; esac
f="${FX}/journal_status_${inv}.txt"; [[ -f "$f" ]] || exit 1
cat "$f"
'''

TIMEOUT_STUB = r'''#!/bin/bash
while [[ "${1:-}" == -* ]]; do case "$1" in -k|-s) shift 2 ;; *) shift ;; esac; done
shift
exec "$@"
'''


class Box:
    """One node: a sandbox /sys, /proc, stubs, the edge script and wins-node-perf-readback."""

    def __init__(self, edge=EDGE, perf=PERF):
        self.root = Path(tempfile.mkdtemp(prefix="p5-queues-"))
        self.fx = self.root / "fx"
        self.bin = self.root / "bin"
        self.net = self.root / "sys" / "class" / "net"
        for sub in (self.fx, self.bin, self.net, self.root / "proc/sys/net/core", self.root / "proc/net",
                    self.root / "proc/sys/kernel/random", self.root / "run", self.root / "sysctl.d",
                    self.root / "evidence"):
            sub.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "run" / "winn3gw-queues.state"
        self.edge = self.root / "wins-edge-hardening"
        self.edge.write_text(edge.replace("/sys/class/net/", f"{self.net}/")
                             .replace("/proc/meminfo", f"{self.root}/proc/meminfo"), encoding="utf-8")
        self.perf = self.root / "wins-node-perf-readback"
        self.perf.write_text(perf, encoding="utf-8")
        self.write("node.env", "")
        self.meminfo(8000000)
        self.write("proc/sys/net/core/rmem_max", "134217728\n")
        self.write("proc/sys/net/core/wmem_max", "134217728\n")
        self.write("proc/sys/kernel/random/boot_id", "boot-one\n")
        self.write("proc/net/softnet_stat", "00001000 00000000 00000000\n")
        self.write("sysctl.d/99-winsvpn-node.conf", "net.core.rmem_max=134217728\nnet.core.wmem_max=134217728\n")
        self.gateway()
        self.status()
        for name, body in (("tc", TC_STUB), ("ip", IP_STUB), ("systemctl", SYSTEMCTL_STUB)):
            self.stub(name, f"#!{PY}\n" + body)
        for name, body in (("sleep", SLEEP_STUB), ("journalctl", JOURNALCTL_STUB), ("timeout", TIMEOUT_STUB)):
            self.stub(name, body)
        # The CPU count RPS is sized to (wins_gwq_cpu_count reads nproc): 6, as
        # Canada, unless a case writes fx/nproc.
        self.stub("nproc", '#!/bin/bash\ncat "${FX}/nproc" 2>/dev/null || echo 6\n')

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def meminfo(self, kb):
        self.write("proc/meminfo", f"MemTotal:       {kb} kB\nMemAvailable:   {kb // 2} kB\n")

    def gateway(self, state="active", pid=4242, execstart=FORWARDING, invocation=INVOCATION):
        (self.fx / "systemctl.json").write_text(json.dumps(
            {"ActiveState": state, "MainPID": str(pid), "InvocationID": invocation, "ExecStart": execstart}))

    def status(self, invocation=INVOCATION):
        doc = {"event": "posture", "ready": True, "carrying": 1, "pipe_recv_errors": 0,
               "udp_read_buffer": 33554432, "udp_write_buffer": 33554432, "udp_rcvbuf_errors": 0}
        (self.fx / f"journal_status_{invocation}.txt").write_text(json.dumps(doc, separators=(",", ":")) + "\n")

    def device(self, name="winn3gw0", ifindex=17, queues=2, up=True, rps=True):
        """A new device incarnation on the kernel default queue (qlen 500), its
        receive queues on the kernel default RPS (mask 0, flow count 0); rps=False
        is a kernel without RPS (no rps_cpus file)."""
        base = self.net / name
        if base.exists():
            shutil.rmtree(base)
        (base / "queues").mkdir(parents=True)
        for n in range(queues):
            (base / "queues" / f"tx-{n}").mkdir()
            (base / "queues" / f"rx-{n}").mkdir()
            if rps:
                (base / "queues" / f"rx-{n}" / "rps_cpus").write_text("0\n")
                (base / "queues" / f"rx-{n}" / "rps_flow_cnt").write_text("0\n")
        (base / "ifindex").write_text(f"{ifindex}\n")
        (base / "flags").write_text("0x1091\n" if up else "0x1090\n")
        (base / "tx_queue_len").write_text("500\n")
        self.tc_state(name, None)

    def device_script(self, name="winn3gw0", ifindex=18, queues=2):
        """Shell lines that create (or recreate) the device, for a sleep or tc hook."""
        base = self.net / name
        lines = [f"rm -rf '{base}'", f"mkdir -p '{base}/queues'"]
        lines += [f"mkdir -p '{base}/queues/tx-{n}' '{base}/queues/rx-{n}'" for n in range(queues)]
        lines += [f"echo 0 > '{base}/queues/rx-{n}/rps_cpus'; echo 0 > '{base}/queues/rx-{n}/rps_flow_cnt'"
                  for n in range(queues)]
        lines += [f"echo {ifindex} > '{base}/ifindex'", f"echo 0x1091 > '{base}/flags'",
                  f"echo 500 > '{base}/tx_queue_len'",
                  f"{PY} -c \"import json,os;p='{self.fx}/tc_state.json';"
                  f"s=json.load(open(p)) if os.path.exists(p) else {{}};s.pop('{name}',None);"
                  f"json.dump(s,open(p,'w'))\""]
        return "\n".join(lines) + "\n"

    def tc_state(self, dev, value):
        path = self.fx / "tc_state.json"
        state = json.loads(path.read_text()) if path.exists() else {}
        if value is None:
            state.pop(dev, None)
        else:
            state[dev] = value
        path.write_text(json.dumps(state))

    def env(self, **extra):
        env = {"PATH": f"{self.bin}:{SYSTEM_PATH}", "HOME": str(self.root), "FX": str(self.fx),
               "FX_SYSNET": str(self.net), "NODE_ENV_FILE": str(self.root / "node.env"),
               "WINSVPN_TEST_ROOT": str(self.root / "fsroot"),
               "WINS_PERF_PROC": str(self.root / "proc"), "WINS_PERF_SYS": str(self.root / "sys"),
               "WINS_PERF_STATE": str(self.root / "run" / "node-perf.state"),
               "WINS_PERF_EVIDENCE_DIR": str(self.root / "evidence"),
               "WINS_PERF_TRIAL_ENV": str(self.root / "perf-trial.env"),
               "WINS_PERF_NODE_ENV": str(self.root / "node.env"),
               "WINS_PERF_SYSCTL_DIR": str(self.root / "sysctl.d"),
               "WINS_PERF_QUEUE_STATE": str(self.state_path),
               "WINS_PERF_NOW": "1000000", "WINS_PERF_CHECK_RETRY_S": "0"}
        env.update(extra)
        return env

    def helper(self, **extra):
        return subprocess.run([BASH, str(self.edge), "--winn3gw-queues"], env=self.env(**extra),
                              capture_output=True, text=True, timeout=120, check=False)

    def check(self):
        return subprocess.run([PY, "-B", str(self.perf), "--check"], env=self.env(), capture_output=True,
                              text=True, timeout=60, check=False)

    def report(self):
        proc = subprocess.run([PY, "-B", str(self.perf), "--json"], env=self.env(), capture_output=True,
                              text=True, timeout=60, check=False)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    def state(self):
        raw = self.state_path.read_bytes()
        assert len(raw) < 8192, len(raw)  # wins-node-perf-readback reads at most 8192 bytes
        return json.loads(raw)

    def log(self, name):
        path = self.fx / f"{name}.log"
        return path.read_text().splitlines() if path.exists() else []

    def sleeps(self):
        path = self.fx / "sleep.count"
        return int(path.read_text()) if path.exists() else 0

    def qlen(self, dev="winn3gw0"):
        return (self.net / dev / "tx_queue_len").read_text().strip()


class QueueCase(unittest.TestCase):
    def setUp(self):
        self.box = Box()
        self.addCleanup(self.box.cleanup)

    def assert_ok(self, proc, pid=4242, ifindex=17):
        box = self.box
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        state = box.state()
        self.assertEqual(("ok", pid, ifindex), (state["result"], state["main_pid"], state["ifindex"]), state)
        self.assertEqual("10000", box.qlen())
        check = box.check()
        self.assertEqual(0, check.returncode, check.stdout + check.stderr)
        queues = box.report()["winn3gw"]
        self.assertEqual(("ok", True), (queues["queues"], queues["match"]), queues)
        self.assertFalse([d for d in box.report()["drift"] if d.startswith("winn3gw")])
        return state

    def assert_failed(self, proc, pid=4242, ifindex=17):
        box = self.box
        self.assertNotEqual(0, proc.returncode, proc.stdout + proc.stderr)
        state = box.state()
        self.assertEqual(("failed", pid, ifindex), (state["result"], state["main_pid"], state["ifindex"]), state)
        check = box.check()
        self.assertEqual(1, check.returncode, check.stdout + check.stderr)
        self.assertIn("queue helper's record is", check.stderr)
        return state


class CalibratedQueue(QueueCase):
    def test_the_kernel_default_mq_gets_calibrated_children_and_p1_accepts_the_record(self):
        # The L13 France layout: mq 0: root, default fq children (flow_limit 100p).
        self.box.device(queues=2)
        state = self.assert_ok(self.box.helper())
        replaces = [l for l in self.box.log("tc") if l.startswith("qdisc replace")]
        self.assertEqual(["qdisc replace dev winn3gw0 root handle 1: mq"]
                         + [f"qdisc replace dev winn3gw0 parent 1:{n} fq " + " ".join(CALIBRATED) for n in (1, 2)],
                         replaces)  # the handle-0 default root is re-installed as 1:, then each child is set
        self.assertEqual(["link set dev winn3gw0 txqueuelen 10000"], [l for l in self.box.log("ip") if l.startswith("link")])
        self.assertIn("qdisc mq 1: root", state["qdisc"])
        self.assertIn("quantum 1280b initial_quantum 25Kb", state["qdisc"])
        self.assertEqual(1, state["tries"])
        self.assertEqual(0, self.box.sleeps())
        self.assertEqual(("mq", 2, 10000), tuple(self.box.report()["winn3gw"][k] for k in ("root", "children", "qlen")))

    def test_a_named_mq_root_from_an_earlier_run_is_kept(self):
        # A rerun or a restart that kept the device: the root is already mq 1:,
        # so only the children are set.
        self.box.device(queues=2)
        self.box.tc_state("winn3gw0", {"root": {"kind": "mq", "handle": "1"}, "classes": 2,
                                       "children": {"1": {"limit": 10000, "flow_limit": 100, "quantum": 2746,
                                                          "initial_quantum": 13730, "refill_delay": "40ms"},
                                                    "2": {"limit": 10000, "flow_limit": 100, "quantum": 2746,
                                                          "initial_quantum": 13730, "refill_delay": "40ms"}}})
        state = self.assert_ok(self.box.helper())
        self.assertEqual([f"qdisc replace dev winn3gw0 parent 1:{n} fq " + " ".join(CALIBRATED) for n in (1, 2)],
                         [l for l in self.box.log("tc") if l.startswith("qdisc replace")])
        self.assertIn("qdisc mq 1: root", state["qdisc"])

    def test_an_mq_root_with_a_real_handle_is_kept(self):
        # A rerun (phase C's step after the run the restart pulled in) finds
        # the mq 1: root the first run set and keeps it. (Claude seat.)
        self.box.device(queues=2)
        self.assert_ok(self.box.helper())
        (self.box.fx / "tc.log").unlink()
        self.assert_ok(self.box.helper())
        self.assertEqual([f"qdisc replace dev winn3gw0 parent 1:{n} fq " + " ".join(CALIBRATED) for n in (1, 2)],
                         [l for l in self.box.log("tc") if l.startswith("qdisc replace")])

    def test_no_child_is_ever_named_under_a_major_0_parent(self):
        # The stub refuses a major-0 parent as the kernel does; this pins that
        # the step never even tries one, on every start shape.
        for queues, state in ((2, None), (4, {"root": {"kind": "mq", "handle": "0"}, "children": {}})):
            with self.subTest(queues=queues):
                self.box.device(queues=queues)
                if state:
                    self.box.tc_state("winn3gw0", state)
                (self.box.fx / "tc.log").write_text("")
                self.assert_ok(self.box.helper())
                bad = [l for l in self.box.log("tc") if re.search(r" parent (0)?:", l)]
                self.assertEqual([], bad)

    def test_a_root_that_is_not_mq_is_restored_to_mq_on_a_multiqueue_device(self):
        # Spain's shape: the old ExecStartPost's fq root on the whole device.
        self.box.device(queues=4)
        self.box.tc_state("winn3gw0", {"root": {"kind": "fq", "handle": "8001",
                                                "p": {"limit": 20480, "flow_limit": 512, "quantum": 2746,
                                                      "initial_quantum": 13730, "refill_delay": "1ms"}},
                                       "children": {}})
        self.assert_ok(self.box.helper())
        replaces = [l for l in self.box.log("tc") if l.startswith("qdisc replace")]
        self.assertEqual("qdisc replace dev winn3gw0 root handle 1: mq", replaces[0])
        self.assertEqual([f"qdisc replace dev winn3gw0 parent 1:{n} fq " + " ".join(CALIBRATED) for n in (1, 2, 3, 4)],
                         replaces[1:])
        self.assertEqual(4, self.box.report()["winn3gw"]["children"])

    def test_a_single_queue_device_gets_the_calibrated_fq_root(self):
        self.box.device(queues=1)
        self.assert_ok(self.box.helper())
        self.assertEqual(["qdisc replace dev winn3gw0 root fq " + " ".join(CALIBRATED)],
                         [l for l in self.box.log("tc") if l.startswith("qdisc replace")])
        self.assertEqual("fq", self.box.report()["winn3gw"]["root"])

    def test_a_node_under_about_5_gb_gets_the_small_limit(self):
        self.box.meminfo(3900000)
        self.box.device(queues=2)
        self.assert_ok(self.box.helper())
        replaces = [l for l in self.box.log("tc") if l.startswith("qdisc replace")]
        children = [l for l in replaces if " fq " in l]
        self.assertTrue(children and all(" limit 10240 " in l for l in children), replaces)

    def test_a_refill_delay_rounded_up_by_one_jiffy_reads_back_as_calibrated(self):
        (self.box.fx / "refill_round_ms").write_text("4")  # HZ=250
        self.box.device(queues=2)
        state = self.assert_ok(self.box.helper())
        self.assertIn("refill_delay 4ms", state["qdisc"])

    def test_queue_values_from_the_environment_or_node_env_are_ignored(self):
        overrides = {"VPN_FQ_LIMIT": "1000", "VPN_FQ_FLOW_LIMIT": "100", "VPN_FQ_REFILL_DELAY": "40ms",
                     "VPN_QDISC_QUANTUM": "3028", "VPN_FQ_INITIAL_QUANTUM": "15140", "VPN_TXQUEUELEN": "500",
                     "WINS_GWQ_LIMIT": "1000", "WINS_GWQ_QLEN": "500"}
        self.box.write("node.env", "".join(f'{k}="{v}"\n' for k, v in overrides.items()))
        self.box.device(queues=2)
        self.assert_ok(self.box.helper(**overrides))
        replaces = [l for l in self.box.log("tc") if l.startswith("qdisc replace")]
        children = [l for l in replaces if " fq " in l]
        self.assertTrue(children and all(l.endswith("fq " + " ".join(CALIBRATED)) for l in children), replaces)

    def test_the_queue_mode_reads_no_firewall_input(self):
        # Full hardening refuses an admission file that is not root 0600; a
        # queue mode never reads it, nor the gateway listener file.
        admission = self.box.root / "admission.env"
        admission.write_text("PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        admission.chmod(0o644)
        listener = self.box.root / "winn3-gateway.env"
        listener.write_text("WINN3_GATEWAY_LISTEN=not-a-port\n")
        listener.chmod(0o644)
        self.box.device(queues=2)
        self.assert_ok(self.box.helper(PUBLIC_VPN_INGRESS_ADMISSION_FILE=str(admission),
                                       WINN3_GATEWAY_ENV_FILE=str(listener)))


class P1SizeUnits(QueueCase):
    def test_p1_reads_quantum_and_initial_quantum_in_the_units_tc_prints(self):
        # Lane L13's France read-back prints "quantum 1280b initial_quantum 25Kb"
        # (iproute2 sprint_size). A calibrated queue written that way, with a
        # current record, must read back as calibrated; no helper is run here.
        self.box.device(queues=2)
        calibrated = {"limit": 20480, "flow_limit": 256, "quantum": 1280, "initial_quantum": 25600,
                      "refill_delay": "1ms"}
        self.box.tc_state("winn3gw0", {"root": {"kind": "mq", "handle": "0"},
                                       "children": {"1": dict(calibrated), "2": dict(calibrated)}})
        (self.box.net / "winn3gw0" / "tx_queue_len").write_text("10000\n")
        self.box.state_path.write_text(json.dumps({"result": "ok", "main_pid": 4242, "ifindex": 17}))
        shown = subprocess.run(["tc", "qdisc", "show", "dev", "winn3gw0"], env=self.box.env(),
                               capture_output=True, text=True, check=True).stdout
        self.assertIn("quantum 1280b initial_quantum 25Kb", shown)
        queues = self.box.report()["winn3gw"]
        self.assertEqual(("ok", True), (queues["queues"], queues["match"]), queues)
        self.assertEqual(0, self.box.check().returncode)


class FailedQueue(QueueCase):
    def test_missing_mq_classes_for_the_queue_count_are_failed(self):
        self.box.device(queues=4)
        self.box.tc_state("winn3gw0", {"root": {"kind": "fq", "handle": "8001",
                                                "p": {"limit": 10000, "flow_limit": 100, "quantum": 2746,
                                                      "initial_quantum": 13730, "refill_delay": "40ms"}},
                                       "children": {}, "classes": 2})
        state = self.assert_failed(self.box.helper())
        self.assertIn("1:3", state["reason"])
        self.assertEqual(2, state["tries"])

    def test_a_child_missing_from_the_read_back_is_failed(self):
        self.box.device(queues=2)
        (self.box.fx / "tc_hide_children").write_text("1")
        state = self.assert_failed(self.box.helper())
        self.assertIn("2 TX queues but 1 fq children", state["reason"])
        self.assertIn("winn3gw0_qdisc_mismatch", self.box.report()["drift"])

    def test_a_device_without_a_tx_queue_is_failed(self):
        self.box.device(queues=0)
        state = self.assert_failed(self.box.helper())
        self.assertIn("no TX queue", state["reason"])

    def test_a_forced_tc_failure_after_an_automatic_restart_is_failed_with_the_new_pid_and_ifindex(self):
        # 5.5: the gateway was restarted automatically (new MainPID) and tc fails.
        self.box.gateway(pid=5151)
        self.box.device(queues=2, ifindex=23)
        (self.box.fx / "tc_fail_replace").write_text("all")
        state = self.assert_failed(self.box.helper(), pid=5151, ifindex=23)
        self.assertEqual(2, state["tries"])
        self.assertEqual(1, self.box.sleeps())  # two tries, one pause between them
        report = self.box.report()
        self.assertEqual("failed", report["winn3gw"]["queues"])
        self.assertIn("winn3gw_queues_failed", report["drift"])

    def test_a_qlen_that_cannot_be_set_is_failed(self):
        self.box.device(queues=2)
        (self.box.fx / "ip_fail").write_text("")
        state = self.assert_failed(self.box.helper())
        self.assertIn("qlen", state["reason"])

    def test_a_qlen_that_does_not_read_back_is_failed(self):
        # ip reports success but the device keeps its qlen: the read-back decides.
        self.box.device(queues=2)
        (self.box.fx / "ip_ignored").write_text("")
        state = self.assert_failed(self.box.helper())
        self.assertIn("qlen is 500, not 10000", state["reason"])
        self.assertIn("winn3gw0_qdisc_mismatch", self.box.report()["drift"])

    def test_a_device_that_never_appears_fails_after_the_30_s_wait(self):
        proc = self.box.helper()
        self.assertNotEqual(0, proc.returncode)
        state = self.box.state()
        self.assertEqual(("failed", 4242, None), (state["result"], state["main_pid"], state["ifindex"]))
        self.assertIn("within 30 s", state["reason"])
        self.assertEqual(30, self.box.sleeps())
        self.assertFalse([l for l in self.box.log("tc") if "replace" in l])
        self.assertEqual(1, self.box.check().returncode)

    def test_a_device_that_stays_down_fails_after_the_30_s_wait_and_names_its_ifindex(self):
        self.box.device(queues=2, ifindex=31, up=False)
        state = self.assert_failed(self.box.helper(), ifindex=31)
        self.assertEqual(30, self.box.sleeps())
        self.assertEqual(0, state["tries"])

    def test_a_failed_queue_does_not_stop_the_gateway(self):
        self.box.device(queues=2)
        (self.box.fx / "tc_fail_replace").write_text("all")
        self.box.helper()
        verbs = [l.split()[0] for l in self.box.log("systemctl")]
        self.assertEqual({"show"}, set(verbs))


class Incarnations(QueueCase):
    def test_a_device_that_appears_late_in_the_wait_is_set(self):
        (self.box.fx / "on_sleep_7.sh").write_text(self.box.device_script(ifindex=19))
        self.assert_ok(self.box.helper(), ifindex=19)
        self.assertEqual(7, self.box.sleeps())

    def test_one_failed_try_is_retried_once(self):
        self.box.device(queues=2)
        (self.box.fx / "tc_fail_replace").write_text("1")
        state = self.assert_ok(self.box.helper())
        self.assertEqual(2, state["tries"])
        self.assertEqual(1, self.box.sleeps())

    def test_a_device_recreated_during_the_first_try_is_set_on_the_new_incarnation(self):
        self.box.device(queues=2, ifindex=17)
        # Recreated right before the first child replace (tc call 3: show
        # root, mq 1: root, first child): the first try is on a device that is
        # gone, the second on the new one.
        (self.box.fx / "on_tc_3.sh").write_text(self.box.device_script(ifindex=18))
        state = self.assert_ok(self.box.helper(), ifindex=18)
        self.assertEqual(2, state["tries"])

    def test_an_incarnation_change_after_the_read_back_is_not_claimed_for_the_old_ifindex(self):
        # The ifindex changes during the read-back of try 1 (tc call 5: show
        # root, mq 1: root, two child replaces, show). Try 1 must not record ok
        # for 17.
        self.box.device(queues=2, ifindex=17)
        (self.box.fx / "on_tc_5.sh").write_text(f"echo 18 > '{self.box.net}/winn3gw0/ifindex'\n")
        state = self.assert_ok(self.box.helper(), ifindex=18)
        self.assertEqual(2, state["tries"])

    def test_a_gateway_restart_makes_the_record_stale_and_the_next_run_renews_it(self):
        self.box.device(queues=2)
        self.assert_ok(self.box.helper())
        self.box.gateway(pid=6000)
        self.assertEqual("stale", self.box.report()["winn3gw"]["queues"])
        self.assertEqual(1, self.box.check().returncode)
        self.assert_ok(self.box.helper(), pid=6000)

    def test_a_recreated_device_makes_the_record_stale(self):
        self.box.device(queues=2)
        self.assert_ok(self.box.helper())
        self.box.device(queues=2, ifindex=40)
        self.assertEqual("stale", self.box.report()["winn3gw"]["queues"])

    def test_a_reflector_gateway_gets_no_record_and_no_wait(self):
        self.box.gateway(execstart=REFLECTOR)
        self.box.state_path.write_text(json.dumps({"result": "ok", "main_pid": 1, "ifindex": 1}))
        proc = self.box.helper()
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertFalse(self.box.state_path.exists())
        self.assertEqual(0, self.box.sleeps())
        self.assertEqual([], self.box.log("tc"))


class WanParentFallback(QueueCase):
    """apply_wan_qdisc's per-parent fallback (--queues-only) under the same
    kernel-faithful stub: it never names a parent whose major is 0."""

    def queues_only(self):
        self.box.write("node.env", 'VPN_INTERFACES=""\nWAN_IFACE="eth0"\n')
        return subprocess.run([BASH, str(self.box.edge), "--queues-only"], env=self.box.env(WAN_IFACE="eth0"),
                              capture_output=True, text=True, timeout=120, check=False)

    def test_a_default_mq_wan_root_is_renamed_before_its_classes_are_set(self):
        self.box.device("eth0", ifindex=2, queues=4)
        (self.box.fx / "tc_fail_root_fq_eth0").write_text("")
        proc = self.queues_only()
        # The fallback leaves no fq root, so the queue read-back still fails, as
        # verify_wan_qdisc states; what changes is that the children are set.
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        log = self.box.log("tc")
        self.assertEqual([], [l for l in log if re.search(r" parent (0)?:", l)])
        self.assertIn("qdisc replace dev eth0 root handle 1: mq", log)
        # The WAN root carries the v3 tunnel as ONE flow: limit 131072 and
        # flow_limit 32768 are the limits in the supplied Canada measurement
        # records (tunnel-speed round 2, Turn 14).
        wan = ["limit", "131072", "flow_limit", "32768", "refill_delay", "1ms", "quantum", "1280", "initial_quantum", "25600"]
        for n in range(1, 5):
            self.assertIn(f"qdisc replace dev eth0 parent 1:{n} fq " + " ".join(wan), log)
        state = json.loads((self.box.fx / "tc_state.json").read_text())["eth0"]
        self.assertEqual(4, sum(1 for c in state["children"].values() if c["flow_limit"] == 32768))

    def test_a_default_mq_wan_root_that_cannot_be_renamed_is_never_named_as_parent_0(self):
        self.box.device("eth0", ifindex=2, queues=4)
        (self.box.fx / "tc_fail_root_fq_eth0").write_text("")
        (self.box.fx / "tc_fail_root_mq_eth0").write_text("")
        self.assertEqual(1, self.queues_only().returncode)
        log = self.box.log("tc")
        self.assertIn("qdisc replace dev eth0 root handle 1: mq", log)
        self.assertEqual([], [l for l in log if re.search(r" parent (0)?:", l)])

    def test_a_renamed_wan_root_sets_its_hex_numbered_classes(self):
        # tc prints mq classes in hex: 12 TX queues give 1:1 to 1:c.
        self.box.device("eth0", ifindex=2, queues=12)
        (self.box.fx / "tc_fail_root_fq_eth0").write_text("")
        self.queues_only()
        log = self.box.log("tc")
        self.assertEqual([f"qdisc replace dev eth0 parent 1:{n:x}" for n in range(1, 13)],
                         sorted({" ".join(l.split()[:6]) for l in log if l.startswith("qdisc replace dev eth0 parent ")},
                                key=lambda l: int(l.rsplit(":", 1)[1], 16)))

    def test_a_named_mq_wan_root_keeps_its_handle(self):
        self.box.device("eth0", ifindex=2, queues=2)
        self.box.tc_state("eth0", {"root": {"kind": "mq", "handle": "1"}, "classes": 2,
                                   "children": {"1": {"limit": 10000, "flow_limit": 100, "quantum": 2746,
                                                      "initial_quantum": 13730, "refill_delay": "40ms"},
                                                "2": {"limit": 10000, "flow_limit": 100, "quantum": 2746,
                                                      "initial_quantum": 13730, "refill_delay": "40ms"}}})
        (self.box.fx / "tc_fail_root_fq_eth0").write_text("")
        self.queues_only()
        log = self.box.log("tc")
        self.assertNotIn("qdisc replace dev eth0 root handle 1: mq", log)
        self.assertEqual(2, len([l for l in log if l.startswith("qdisc replace dev eth0 parent 1:")]))


class RpsSteering(QueueCase):
    """Tunnel-speed round 2 (owner ruling 2026-10-10, multicore always on): the
    queue owner writes the RPS mask for every CPU and the RFS flow count on
    every receive queue of winn3gw0, reads both back, and records them."""

    def rps(self, dev="winn3gw0"):
        base = self.box.net / dev / "queues"
        return {q.name: ((q / "rps_cpus").read_text().strip(), (q / "rps_flow_cnt").read_text().strip())
                for q in sorted(base.iterdir()) if q.name.startswith("rx-") and (q / "rps_cpus").exists()}

    def reset_hooks(self, text, count=40):
        # Every tc call rewrites the receive queues, so each try's read-back
        # sees what the kernel kept, not what the helper wrote.
        for n in range(1, count):
            (self.box.fx / f"on_tc_{n}.sh").write_text(
                "".join(f"echo {text} > '{self.box.net}/winn3gw0/queues/rx-{q}/rps_cpus'\n" for q in range(2)))

    def test_every_receive_queue_gets_the_mask_for_every_cpu_and_the_flow_count(self):
        self.box.device(queues=4)
        proc = self.box.helper()
        state = self.assert_ok(proc)
        self.assertEqual({f"rx-{n}": ("3f", "16384") for n in range(4)}, self.rps())
        self.assertEqual(("3f", 16384), (state["rps_cpus"], state["rps_flow_cnt"]), state)
        self.assertIn("rps_cpus 3f, rps_flow_cnt 16384", proc.stdout)

    def test_a_host_above_32_cpus_gets_the_comma_grouped_mask(self):
        (self.box.fx / "nproc").write_text("72\n")
        self.box.device(queues=2)
        state = self.assert_ok(self.box.helper())
        self.assertEqual({"rx-0": ("ff,ffffffff,ffffffff", "16384"), "rx-1": ("ff,ffffffff,ffffffff", "16384")},
                         self.rps())
        self.assertEqual("ff,ffffffff,ffffffff", state["rps_cpus"])

    def test_a_small_node_gets_the_small_flow_count(self):
        self.box.meminfo(3900000)
        self.box.device(queues=2)
        state = self.assert_ok(self.box.helper())
        self.assertEqual({"rx-0": ("3f", "8192"), "rx-1": ("3f", "8192")}, self.rps())
        self.assertEqual(8192, state["rps_flow_cnt"])

    def test_one_cpu_gets_no_steering_and_the_record_says_so(self):
        (self.box.fx / "nproc").write_text("1\n")
        self.box.device(queues=2)
        proc = self.box.helper()
        state = self.assert_ok(proc)
        self.assertEqual({"rx-0": ("0", "0"), "rx-1": ("0", "0")}, self.rps())
        self.assertEqual("", state["rps_cpus"])
        self.assertIn("rps_cpus none", proc.stdout)

    def test_a_kernel_without_rps_is_left_alone(self):
        self.box.device(queues=2, rps=False)
        state = self.assert_ok(self.box.helper())
        self.assertEqual({}, self.rps())
        self.assertEqual("", state["rps_cpus"])

    def test_a_mask_the_kernel_does_not_keep_is_failed(self):
        self.box.device(queues=2)
        self.reset_hooks("0")
        state = self.assert_failed(self.box.helper())
        self.assertIn("rps_cpus reads 0, not the 6-CPU mask 3f", state["reason"])
        self.assertEqual(2, state["tries"])
        self.assertIn("winn3gw_queues_failed", self.box.report()["drift"])

    def test_a_read_back_padded_to_the_kernel_mask_width_is_the_written_mask(self):
        self.box.device(queues=2)
        self.reset_hooks("00000000,0000003f")
        self.assert_ok(self.box.helper())

    def test_a_flow_count_that_does_not_read_back_is_failed(self):
        self.box.device(queues=2)
        for n in range(1, 40):
            (self.box.fx / f"on_tc_{n}.sh").write_text(
                f"echo 0 > '{self.box.net}/winn3gw0/queues/rx-1/rps_flow_cnt'\n")
        state = self.assert_failed(self.box.helper())
        self.assertIn("rps_flow_cnt reads 0, not 16384", state["reason"])


class RpsMask(unittest.TestCase):
    """The mask and its normalization, run as the functions the edge script defines."""

    def run_fn(self, name, *args):
        script = function(name, EDGE) + f'\n{name} "$@"\n'
        proc = subprocess.run([BASH, "-c", script, name, *args], capture_output=True, text=True,
                              timeout=30, check=True)
        return proc.stdout.strip()

    def test_the_mask_is_grouped_by_32_bits_as_the_kernel_prints_it(self):
        for cpus, want in ((1, "1"), (2, "3"), (6, "3f"), (31, "7fffffff"), (32, "ffffffff"),
                           (33, "1,ffffffff"), (40, "ff,ffffffff"), (64, "ffffffff,ffffffff"),
                           (72, "ff,ffffffff,ffffffff"), (96, "ffffffff,ffffffff,ffffffff"),
                           (0, "0"), ("x", "0")):
            with self.subTest(cpus=cpus):
                self.assertEqual(want, self.run_fn("wins_gwq_rps_mask", str(cpus)))

    def test_normalization_drops_commas_leading_zeros_and_case(self):
        for raw, want in (("3f", "3f"), ("3F", "3f"), ("00000000,0000003f", "3f"), ("ff,ffffffff", "ffffffffff"),
                          ("0", "0"), ("00000000", "0"), ("", "0")):
            with self.subTest(raw=raw):
                self.assertEqual(want, self.run_fn("wins_gwq_mask_norm", raw))


# ---------------------------------------------------------------------------
# The unit and phase C (design P-5 semantics paragraph, 5.6 policy mutant)
# ---------------------------------------------------------------------------
UNIT_OPENER = "cat > /etc/systemd/system/wins-winn3gw-queues.service <<'EOF_WINN3GW_QUEUES'"
UNIT = heredoc(UNIT_OPENER, "EOF_WINN3GW_QUEUES") if UNIT_OPENER in SOURCE else None


def unit_settings(text=UNIT):
    assert text is not None, "the installer writes no wins-winn3gw-queues.service"
    settings = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            key, _, value = line.partition("=")
            settings.setdefault(key, []).append(value)
    return settings


class QueueUnit(unittest.TestCase):
    def test_the_unit_is_a_oneshot_without_remain_after_exit_pulled_in_by_every_gateway_start(self):
        settings = unit_settings()
        self.assertEqual(["oneshot"], settings["Type"])
        self.assertNotIn("RemainAfterExit", settings)
        self.assertNotIn("RestartMode", settings)
        self.assertEqual(["winn3-gateway.service"], settings["After"])
        self.assertEqual(["winn3-gateway.service"], settings["PartOf"])
        self.assertEqual(["winn3-gateway.service"], settings["WantedBy"])
        self.assertEqual(["/usr/local/bin/wins-edge-hardening --winn3gw-queues"], settings["ExecStart"])
        # Helper success is deliberately not a gateway requirement.
        for key in ("Requires", "BindsTo", "Requisite", "Before"):
            self.assertNotIn(key, settings)

    def test_the_unit_and_the_mode_are_written_where_they_run(self):
        self.assertIn('if [[ "${1:-}" == "--winn3gw-queues" ]]; then', EDGE)
        self.assertEqual(1, SOURCE.count("cat > /etc/systemd/system/wins-winn3gw-queues.service <<"))
        self.assertIn("winn3gw_install_queue_unit || return 1", function("winn3gw_phase_c"))


PHASE_C_HARNESS = r'''
set -Eeuo pipefail
log() { echo "LOG $*"; }
warn() { echo "WARN $*"; }
err() { echo "ERR $*" >&2; }
check_gateway_egress_mtu() { return 0; }
winn3gw_activate() { echo "activate" >> "${FX}/order.log"; }
winn3gw_bundle_digest() { cat "${FX}/bundle"; }
WINN3_GATEWAY_PRIOR_BUNDLE="$(cat "${FX}/prior")"
'''

PHASE_SYSTEMCTL = r'''#!/bin/bash
echo "systemctl $*" >> "${FX}/order.log"
case "$1" in
  show)
    for a in "$@"; do case "$a" in
      MainPID) echo 4242 ;; InvocationID) echo 0123456789abcdef0123456789abcdef ;;
    esac; done ;;
  is-active) [[ -f "${FX}/active" ]] ;;
  enable)
    if [[ ! -f "${FX}/no_wants" ]]; then
      mkdir -p "${FX}/etc/winn3-gateway.service.wants"
      ln -sf ../wins-winn3gw-queues.service "${FX}/etc/winn3-gateway.service.wants/$2"
    fi ;;
  start) [[ ! -f "${FX}/start_fails" ]] ;;
  *) exit 0 ;;
esac
'''


class PhaseC(unittest.TestCase):
    def setUp(self):
        if shutil.which("jq") is None:
            self.skipTest("jq is needed by phase C's readiness check")
        self.tmp = Path(tempfile.mkdtemp(prefix="p5-phase-c-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = self.tmp / "fx"
        (self.fx / "etc").mkdir(parents=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        stubs = {
            "systemctl": PHASE_SYSTEMCTL,
            "ss": '#!/bin/bash\necho "UNCONN 0 0 0.0.0.0:9111 0.0.0.0:* users:((\\"winn3-gateway\\",pid=4242,fd=3))"\n',
            "journalctl": '#!/bin/bash\necho \'{"event":"posture","ready":true}\'\n',
            "sleep": "#!/bin/bash\nexit 0\n",
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        functions = "".join(function(name) for name in
                            ("winn3gw_install_queue_unit", "winn3gw_run_queue_step", "winn3gw_phase_c"))
        self.script = self.tmp / "phase_c.sh"
        self.script.write_text(PHASE_C_HARNESS + functions.replace("/etc/systemd/system/", f"{self.fx}/etc/")
                               + "\nwinn3gw_phase_c\necho \"phase-c-rc=$?\"\n")

    def run_phase(self, bundle="new", prior="old", active=True):
        (self.fx / "bundle").write_text(bundle)
        (self.fx / "prior").write_text(prior)
        if active:
            (self.fx / "active").write_text("")
        proc = subprocess.run([BASH, str(self.script)], env={"PATH": f"{self.bin}:{SYSTEM_PATH}", "FX": str(self.fx)},
                              capture_output=True, text=True, timeout=60, check=False)
        order = [l for l in (self.fx / "order.log").read_text().splitlines()
                 if not l.startswith(("systemctl show", "systemctl is-active"))]
        return proc, order

    def test_a_restart_follows_the_queue_unit_and_the_step_runs_after_readiness(self):
        proc, order = self.run_phase()
        self.assertIn("phase-c-rc=0", proc.stdout, proc.stdout + proc.stderr)
        self.assertEqual(["activate", "systemctl daemon-reload", "systemctl enable wins-winn3gw-queues.service",
                          "systemctl restart winn3-gateway.service", "systemctl start wins-winn3gw-queues.service"],
                         order)
        self.assertEqual(UNIT, (self.fx / "etc" / "wins-winn3gw-queues.service").read_text())
        self.assertEqual(0o644, (self.fx / "etc" / "wins-winn3gw-queues.service").stat().st_mode & 0o777)

    def test_an_unchanged_running_gateway_still_gets_the_queue_step(self):
        proc, order = self.run_phase(bundle="same", prior="same")
        self.assertIn("phase-c-rc=0", proc.stdout, proc.stdout + proc.stderr)
        self.assertNotIn("systemctl restart winn3-gateway.service", order)
        self.assertEqual("systemctl start wins-winn3gw-queues.service", order[-1])

    def test_a_failed_queue_step_is_left_to_the_postflight_read_back(self):
        (self.fx / "start_fails").write_text("")
        proc, order = self.run_phase()
        self.assertIn("phase-c-rc=0", proc.stdout, proc.stdout + proc.stderr)
        self.assertIn("WARN wins-winn3gw-queues.service failed", proc.stdout)

    def test_no_wants_link_stops_phase_c_before_the_gateway_restarts(self):
        (self.fx / "no_wants").write_text("")
        proc, order = self.run_phase()
        self.assertNotIn("phase-c-rc=0", proc.stdout)
        self.assertNotIn("systemctl restart winn3-gateway.service", order)


if __name__ == "__main__":
    unittest.main()
