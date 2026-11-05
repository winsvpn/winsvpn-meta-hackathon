#!/usr/bin/env python3
"""Slice P1 (design 10.2, 5.5, 5.7): the node-side performance read-backs.

wins-node-perf-readback is extracted from the data-plane installer's heredoc and
run against a sandbox: fake /proc and /sys trees, state and evidence paths, and
stub tc, ethtool, systemctl, journalctl and ip programs on PATH. Nothing touches
the host. What it proves:

  P-1  the sysctl floor (live and persisted, and the former gateway file's
       value), and the gateway's granted UDP buffers: below the floor makes
       --check fail, an unreadable value never does;
  P-2  softnet drop deltas and gateway inbox-drop deltas: no delta on the first
       report, after a reboot or a gateway restart, or after a counter went
       backwards; a report too soon after the last keeps the earlier baseline;
  P-4  the WAN root qdisc against the fleet constants, the queue override names
       (never their values) and the harness trial file;
  P-5  the winn3gw0 helper state (ok, failed, stale, absent, unreadable) and
       the live queue read-back; on a forwarding gateway the postflight needs
       a current helper record and a queue read back as calibrated, so an
       absent record, a mismatch and an unverifiable queue all fail it;
  P-6  ethtool -k and -g evidence: read only, with an explicit unsupported,
       partial and missing-ethtool result;
  P-8  the carrying and -max-sessions figures;
  P-9  the forward-async gate line (live, or kept for the same invocation),
       the computed CPU count as report only, and the fail-closed cases;
  and the heartbeat joins the report to its payload and sends null, never a
  failed heartbeat, when the program is absent or prints garbage.

usage: python3 -B -m pytest -q -p no:cacheprovider server/test_wins_node_perf_readback_p1.py
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
INSTALLER = Path(os.environ.get("P1_DATA_PLANE_INSTALLER", ROOT / "wins_data_plane_setup_ONETOUCH.sh"))
SOURCE = INSTALLER.read_text(encoding="utf-8")
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

FQ_ROOT = ("qdisc fq 8001: root refcnt 2 limit {limit}p flow_limit {flow}p buckets 1024 orphan_mask 1023 "
           "quantum 1280 initial_quantum 25600 low_rate_threshold 550Kbit refill_delay 1ms "
           "timer_slack 10us horizon 10s horizon_drop\n")
FQ_CHILD = ("qdisc fq 0: parent 1:{n} limit {limit}p flow_limit {flow}p buckets 1024 orphan_mask 1023 "
            "quantum 1280 initial_quantum 25600 low_rate_threshold 550Kbit refill_delay 1ms "
            "timer_slack 10us horizon 10s horizon_drop\n")
INVOCATION = "0123456789abcdef0123456789abcdef"


def extract(tag_open, tag_close, text=SOURCE):
    lines = text.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if tag_open in line)
    end = next(j for j in range(start + 1, len(lines)) if lines[j].rstrip("\n") == tag_close)
    return "".join(lines[start + 1:end])


PERF_SCRIPT = extract("cat > /usr/local/bin/wins-node-perf-readback <<'EOF_PERF'", "EOF_PERF")


class Sandbox:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="p1-perf-"))
        self.bin = self.root / "bin"
        self.fx = self.root / "fx"
        for sub in ("bin", "fx", "proc/net", "proc/sys/net/core", "proc/sys/kernel/random",
                    "sys/class/net", "sysctl.d", "run", "evidence"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        self.program = self.root / "wins-node-perf-readback"
        self.program.write_text(PERF_SCRIPT, encoding="utf-8")
        self.set_proc(rmem=134217728, wmem=134217728)
        self.write("proc/meminfo", "MemTotal:       8000000 kB\n")
        self.write("proc/sys/kernel/random/boot_id", "boot-one\n")
        self.write("proc/net/softnet_stat", self.softnet(0))
        self.write("sysctl.d/99-winsvpn-node.conf",
                   "net.core.rmem_max=134217728\nnet.core.wmem_max=134217728\n")
        self.systemctl(state="inactive")
        self.write("fx/ip_route.txt", "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0\n")
        self.install_stubs()
        self.now = 1000000.0

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def set_proc(self, rmem, wmem):
        self.write("proc/sys/net/core/rmem_max", f"{rmem}\n")
        self.write("proc/sys/net/core/wmem_max", f"{wmem}\n")

    @staticmethod
    def softnet(dropped, cpus=2):
        # processed dropped time_squeeze, hex, one line per CPU.
        return "".join(f"{1000 + i:08x} {dropped if i == 0 else 0:08x} 00000000\n" for i in range(cpus))

    def systemctl(self, state="active", pid=4242, invocation=INVOCATION, execstart=None):
        if execstart is None:
            execstart = ("{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve "
                         "-plan udp -max-sessions 22 -forward -forward-if winn3gw0 -peer-registry /etc/winn/winn3-peers.json ;"
                         " ignore_errors=no ; start_time=[n/a] }")
        self.write("fx/systemctl_show.txt",
                   f"ActiveState={state}\nMainPID={pid}\nInvocationID={invocation}\nExecStart={execstart}\n")

    def status(self, carrying=3, recv_errors=0, read=33554432, write=33554432, rcvbuf=0, extra=None,
               invocation=INVOCATION):
        doc = {"event": "posture", "ready": True, "carrying": carrying, "pipe_recv_errors": recv_errors,
               "udp_read_buffer": read, "udp_write_buffer": write, "udp_rcvbuf_errors": rcvbuf}
        if extra:
            doc.update(extra)
        for key in [k for k, v in doc.items() if v is None]:
            del doc[key]
        self.write(f"fx/journal_status_{invocation}.txt", json.dumps(doc, separators=(",", ":")) + "\n")

    def gate(self, text, invocation=INVOCATION):
        self.write(f"fx/journal_gate_{invocation}.txt", text)

    def queue_ready(self, limit=20480, flow=256, queues=2, pid=4242, ifindex=17):
        """winn3gw0 on the calibrated mq/fq layout with a current helper record (P-5).

        A forwarding gateway's postflight needs both: the helper's record for this
        incarnation and a queue read back as calibrated.
        """
        self.write("sys/class/net/winn3gw0/ifindex", f"{ifindex}\n")
        self.write("sys/class/net/winn3gw0/tx_queue_len", "10000\n")
        for n in range(queues):
            (self.root / f"sys/class/net/winn3gw0/queues/tx-{n}").mkdir(parents=True, exist_ok=True)
        self.write("fx/tc_winn3gw0.txt", "qdisc mq 1: root\n" + "".join(
            FQ_CHILD.format(n=n + 1, limit=limit, flow=flow) for n in range(queues)))
        self.write("run/winn3gw-queues.state", json.dumps(
            {"result": "ok", "main_pid": pid, "ifindex": ifindex, "qdisc": "mq"}))

    def cgroup(self, rel="system.slice/winn3-gateway.service", affinity="0-5", cpu_max="max 100000",
               cpuset="0-5", top_controllers="", mid_controllers=None):
        """A cgroup v2 tree under the sandbox /sys for the gateway process (pid 4242)."""
        self.write("proc/4242/status", f"Name:\twinn3-gateway\nCpus_allowed_list:\t{affinity}\n")
        self.write("proc/4242/cgroup", f"0::/{rel}\n")
        top = "sys/fs/cgroup"
        self.write(f"{top}/cgroup.subtree_control", top_controllers + "\n")
        parts = rel.split("/")
        for depth in range(1, len(parts)):
            if mid_controllers is not None:
                self.write(f"{top}/{'/'.join(parts[:depth])}/cgroup.subtree_control", mid_controllers + "\n")
        leaf = f"{top}/{rel}"
        if cpuset is not None:
            self.write(f"{leaf}/cpuset.cpus.effective", cpuset + "\n")
        if cpu_max is not None:
            self.write(f"{leaf}/cpu.max", cpu_max + "\n")

    def install_stubs(self):
        stubs = {
            "tc": r'''#!/bin/bash
# tc qdisc show dev DEV [root]
[[ "$1 $2 $3" == "qdisc show dev" ]] || exit 1
dev="$4"; if [[ "${5:-}" == root ]]; then f="${FX}/tc_${dev}_root.txt"; else f="${FX}/tc_${dev}.txt"; fi
[[ -f "$f" ]] || exit 1
cat "$f"
''',
            "ethtool": r'''#!/bin/bash
echo "$*" >> "${FX}/ethtool.log"
case "$1" in
  -k) f="${FX}/ethtool_k"; ;;
  -g) f="${FX}/ethtool_g"; ;;
  *) echo "unexpected ethtool call: $*" >> "${FX}/ethtool.bad"; exit 9 ;;
esac
[[ -f "${f}.txt" ]] && cat "${f}.txt"
[[ -f "${f}.err" ]] && cat "${f}.err" >&2
[[ -f "${f}.rc" ]] && exit "$(cat "${f}.rc")"
exit 0
''',
            "systemctl": r'''#!/bin/bash
[[ "$1" == show ]] || exit 1
cat "${FX}/systemctl_show.txt"
''',
            "journalctl": r'''#!/bin/bash
# Every read is bound to one invocation: journalctl _SYSTEMD_INVOCATION_ID=ID ...
# -g reads the gate line, anything else the status line. A read with no
# invocation id fails, as it has nothing to select by.
echo "$*" >> "${FX}/journalctl.log"
inv=""
for a in "$@"; do case "$a" in _SYSTEMD_INVOCATION_ID=*) inv="${a#*=}" ;; esac; done
[[ -n "$inv" ]] || exit 1
case " $* " in
  *" -g "*) f="${FX}/journal_gate_${inv}.txt"; [[ -s "$f" ]] || exit 1; cat "$f" ;;
  *)
    f="${FX}/journal_status_${inv}.txt"; [[ -f "$f" ]] || exit 1
    if [[ -f "${FX}/status_fail_first" ]]; then
      n="$(cat "${FX}/status_fail_first")"
      if (( n > 0 )); then echo $((n - 1)) > "${FX}/status_fail_first"; exit 1; fi
    fi
    cat "$f" ;;
esac
''',
            "ip": r'''#!/bin/bash
[[ "$1 $2" == "route get" ]] || exit 1
cat "${FX}/ip_route.txt"
''',
            "timeout": r'''#!/bin/bash
# GNU timeout is absent on a Mac: drop its options and the duration, run the command.
while [[ "${1:-}" == -* ]]; do case "$1" in -k|-s) shift 2 ;; *) shift ;; esac; done
shift
exec "$@"
''',
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def remove_stub(self, name):
        (self.bin / name).unlink()

    def env(self, **extra):
        env = {
            "PATH": f"{self.bin}:{SYSTEM_PATH}", "HOME": str(self.root), "FX": str(self.fx),
            "WINS_PERF_PROC": str(self.root / "proc"), "WINS_PERF_SYS": str(self.root / "sys"),
            "WINS_PERF_STATE": str(self.root / "run" / "node-perf.state"),
            "WINS_PERF_EVIDENCE_DIR": str(self.root / "evidence"),
            "WINS_PERF_TRIAL_ENV": str(self.root / "perf-trial.env"),
            "WINS_PERF_NODE_ENV": str(self.root / "node.env"),
            "WINS_PERF_SYSCTL_DIR": str(self.root / "sysctl.d"),
            "WINS_PERF_QUEUE_STATE": str(self.root / "run" / "winn3gw-queues.state"),
            "WINS_PERF_NOW": str(self.now),
        }
        env.update(extra)
        return env

    def run(self, mode="--json", **extra):
        proc = subprocess.run([sys.executable, "-B", str(self.program), mode], env=self.env(**extra),
                              capture_output=True, text=True, timeout=60, check=False)
        return proc

    def report(self, **extra):
        proc = self.run("--json", **extra)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    def advance(self, seconds):
        self.now += seconds


class PerfCase(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.addCleanup(self.sb.cleanup)


class SysctlFloorP1(PerfCase):
    def test_floor_met_is_clean(self):
        report = self.sb.report()
        self.assertTrue(report["sysctl"]["ok"])
        self.assertNotIn("sysctl_below_floor", report["drift"])
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_live_value_below_floor_fails_check(self):
        self.sb.set_proc(rmem=212992, wmem=134217728)
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("below the 134217728 floor", proc.stderr)
        self.assertIn("sysctl_below_floor", self.sb.report()["drift"])

    def test_persisted_value_below_floor_fails_check(self):
        self.sb.write("sysctl.d/99-winsvpn-node.conf", "net.core.rmem_max=134217728\nnet.core.wmem_max=67108864\n")
        self.assertEqual(self.sb.run("--check").returncode, 1)

    def test_former_gateway_file_value_is_a_floor_too(self):
        # No merged key may be below either source: a higher value kept in the
        # former gateway file raises the floor for that key.
        self.sb.write("sysctl.d/60-winn3-gateway-udp-buffers.conf", "net.core.rmem_max = 268435456\n")
        self.assertEqual(self.sb.run("--check").returncode, 1)
        self.sb.write("sysctl.d/99-winsvpn-node.conf", "net.core.rmem_max=268435456\nnet.core.wmem_max=134217728\n")
        self.sb.set_proc(rmem=268435456, wmem=134217728)
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_unreadable_sysctl_is_unknown_not_a_failure(self):
        for name in ("rmem_max", "wmem_max"):
            (self.sb.root / "proc/sys/net/core" / name).unlink()
        (self.sb.root / "sysctl.d/99-winsvpn-node.conf").unlink()
        report = self.sb.report()
        self.assertIsNone(report["sysctl"]["ok"])
        self.assertEqual(self.sb.run("--check").returncode, 0)


class GrantedBuffersP1(PerfCase):
    def setUp(self):
        super().setUp()
        self.sb.systemctl()
        self.sb.queue_ready()

    def test_granted_at_the_doubled_request_passes(self):
        self.sb.status(read=33554432, write=33554432)
        report = self.sb.report()
        self.assertEqual(report["gateway"]["udp_read_buffer"], 33554432)
        self.assertNotIn("udp_buffers_below_floor", report["drift"])
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_granted_below_the_doubled_request_fails(self):
        self.sb.status(read=16777216, write=33554432)
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("granted UDP buffers", proc.stderr)

    def test_granted_below_the_binary_floor_fails(self):
        self.sb.status(read=262144, write=262144)
        self.assertEqual(self.sb.run("--check").returncode, 1)

    # Unknown is fine in the heartbeat (a null field) but cannot satisfy a
    # postflight that requires a granted size: a forwarding gateway prints a
    # status line every second, so a missing one at postflight is a fault.
    def test_no_status_line_on_an_active_forwarding_gateway_fails_the_check(self):
        report = self.sb.report()
        self.assertIsNone(report["gateway"]["udp_read_buffer"])
        proc = self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("could not be read", proc.stderr)

    def test_a_status_line_without_the_fields_fails_the_check(self):
        self.sb.status(read=None, write=None)
        self.assertIsNone(self.sb.report()["gateway"]["udp_write_buffer"])
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 1)

    def test_one_missing_field_fails_the_check(self):
        self.sb.status(read=33554432, write=None)
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 1)

    def test_a_gateway_that_has_only_just_started_is_given_a_few_tries(self):
        # The first two reads find no status line yet; the third finds it.
        self.sb.status()
        self.sb.write("fx/status_fail_first", "2\n")
        proc = self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # The retries are bounded: a gateway that never prints one still fails.
        self.sb.write("fx/status_fail_first", "99\n")
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 1)

    def test_a_reflector_or_stopped_gateway_has_no_grant_to_read(self):
        self.sb.systemctl(execstart="{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve -plan udp -max-sessions 22 ; ignore_errors=no }")
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 0)
        self.sb.systemctl(state="inactive")
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 0)

    def test_a_status_line_of_an_earlier_invocation_is_not_this_gateways_grant(self):
        # The process that was replaced a few seconds ago logged an adequate
        # grant; the current invocation has logged nothing yet.
        self.sb.status(invocation="e" * 32)
        report = self.sb.report()
        self.assertIsNone(report["gateway"]["udp_read_buffer"])
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 1)

    def test_a_malformed_invocation_id_is_never_handed_to_journalctl(self):
        self.sb.systemctl(invocation="not-an-id")
        self.sb.status(invocation="not-an-id")
        self.assertIsNone(self.sb.report()["gateway"]["udp_read_buffer"])
        self.assertFalse((self.sb.root / "fx/journalctl.log").exists())

    def test_the_status_read_is_selected_by_the_invocation_id(self):
        self.sb.status()
        self.sb.report()
        log = (self.sb.root / "fx/journalctl.log").read_text()
        self.assertIn("_SYSTEMD_INVOCATION_ID=" + INVOCATION, log)
        self.assertNotIn("-u ", log)


class DropDeltasP1(PerfCase):
    def test_first_report_has_no_delta_then_the_second_does(self):
        self.sb.systemctl()
        self.sb.status(recv_errors=10)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        first = self.sb.report()
        self.assertIsNone(first["softnet"]["dropped_delta"])
        self.assertIsNone(first["gateway"]["inbox_drops_delta"])
        self.sb.advance(120)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(12))
        self.sb.status(recv_errors=25)
        second = self.sb.report()
        self.assertEqual(second["softnet"]["dropped_delta"], 7)
        self.assertEqual(second["gateway"]["inbox_drops_delta"], 15)
        self.assertEqual(second["interval_s"], 120)

    def test_a_report_too_soon_keeps_the_earlier_baseline(self):
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        self.sb.report()
        self.sb.advance(2)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(9))
        soon = self.sb.report()
        self.assertIsNone(soon["softnet"]["dropped_delta"])
        self.sb.advance(118)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(20))
        later = self.sb.report()
        self.assertEqual(later["softnet"]["dropped_delta"], 15)
        self.assertEqual(later["interval_s"], 120)

    def test_the_manual_check_never_moves_the_baseline(self):
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        self.sb.report()
        self.sb.advance(120)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(8))
        self.sb.run("--check")
        self.assertEqual(self.sb.report()["softnet"]["dropped_delta"], 3)

    def test_a_reboot_has_no_delta(self):
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        self.sb.report()
        self.sb.advance(120)
        self.sb.write("proc/sys/kernel/random/boot_id", "boot-two\n")
        # Higher than the old counter on purpose: only the boot id says it is a new count.
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(50))
        self.assertIsNone(self.sb.report()["softnet"]["dropped_delta"])

    def test_a_backwards_clock_step_does_not_freeze_the_baseline(self):
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        self.sb.report()
        self.sb.advance(-86400)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(9))
        self.sb.report()
        self.sb.advance(120)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(20))
        self.assertEqual(self.sb.report()["softnet"]["dropped_delta"], 11)

    def test_the_host_wide_udp_receive_drops_are_a_monotonic_delta(self):
        # The gateway's pipe_recv_errors is summed over live sessions and falls
        # when one closes. Udp RcvbufErrors is the host counter: it only grows
        # until a reboot, so it survives session churn and a gateway restart.
        self.sb.systemctl()
        self.sb.status(recv_errors=100, rcvbuf=1000)
        self.sb.report()
        self.sb.advance(120)
        # One session with 100 closes, another accrues 50: the proxy sees -50.
        self.sb.status(recv_errors=50, rcvbuf=1080)
        report = self.sb.report()
        self.assertIsNone(report["gateway"]["inbox_drops_delta"])
        self.assertEqual(report["gateway"]["udp_rcvbuf_errors_delta"], 80)
        self.sb.advance(120)
        self.sb.systemctl(invocation="f" * 32)
        self.sb.status(recv_errors=0, rcvbuf=1100, invocation="f" * 32)
        report = self.sb.report()
        self.assertIsNone(report["gateway"]["inbox_drops_delta"])
        self.assertEqual(report["gateway"]["udp_rcvbuf_errors_delta"], 20)

    def test_the_inbox_figure_is_labelled_as_the_proxy_it_is(self):
        self.sb.systemctl()
        self.sb.status()
        self.assertEqual(self.sb.report()["gateway"]["inbox_drops_source"], "pipe_recv_errors_live_sessions")

    def test_a_counter_that_went_backwards_has_no_delta(self):
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(50))
        self.sb.report()
        self.sb.advance(120)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(10))
        self.assertIsNone(self.sb.report()["softnet"]["dropped_delta"])

    def test_a_long_gap_has_no_delta(self):
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        self.sb.report()
        self.sb.advance(1200)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(9))
        self.assertIsNone(self.sb.report()["softnet"]["dropped_delta"])

    def test_a_gateway_restart_has_no_inbox_delta_but_softnet_keeps_its_own(self):
        self.sb.systemctl()
        self.sb.status(recv_errors=500)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(5))
        self.sb.report()
        self.sb.advance(120)
        self.sb.systemctl(invocation="f" * 32)
        # Higher than the old counter on purpose: only the new invocation says it restarted.
        self.sb.status(recv_errors=800)
        self.sb.write("proc/net/softnet_stat", self.sb.softnet(6))
        report = self.sb.report()
        self.assertIsNone(report["gateway"]["inbox_drops_delta"])
        self.assertEqual(report["softnet"]["dropped_delta"], 1)

    def test_unreadable_softnet_is_null(self):
        (self.sb.root / "proc/net/softnet_stat").unlink()
        self.assertIsNone(self.sb.report()["softnet"]["dropped_delta"])
        self.sb.write("proc/net/softnet_stat", "not hex at all\n")
        self.assertIsNone(self.sb.report()["softnet"]["dropped_delta"])


class SessionsP1(PerfCase):
    def test_a_forwarding_gateway_reports_carrying_and_max(self):
        self.sb.systemctl()
        self.sb.status(carrying=19)
        gateway = self.sb.report()["gateway"]
        self.assertEqual((gateway["mode"], gateway["carrying"], gateway["max_sessions"]), ("active", 19, 22))

    def test_a_reflector_reports_no_session_figures(self):
        self.sb.systemctl(execstart="{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve -plan udp -max-sessions 22 ; ignore_errors=no }")
        self.sb.status(carrying=19)
        gateway = self.sb.report()["gateway"]
        self.assertEqual(gateway["mode"], "reflector")
        self.assertIsNone(gateway["carrying"])

    def test_a_stopped_gateway_is_stopped(self):
        self.sb.systemctl(state="failed")
        self.assertEqual(self.sb.report()["gateway"]["mode"], "stopped")

    def test_no_status_line_leaves_carrying_unknown(self):
        self.sb.systemctl()
        self.assertIsNone(self.sb.report()["gateway"]["carrying"])


class ForwardAsyncGateP1(PerfCase):
    ASYNC = ("{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve -plan udp "
             "-max-sessions 22 -forward -forward-async-write -forward-if winn3gw0 ; ignore_errors=no }")

    def setUp(self):
        super().setUp()
        self.sb.systemctl(execstart=self.ASYNC)
        self.sb.status()
        self.sb.queue_ready()

    def test_usable_cpus_are_reported_even_without_the_flag(self):
        # P-9: the fleet record keeps each node's real CPU count.
        self.sb.systemctl()
        self.sb.cgroup()
        gateway = self.sb.report()["gateway"]
        self.assertEqual((gateway["usable_cpus"], gateway["usable_cpus_source"], gateway["async_gate"]),
                         (6.0, "computed", None))
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_flag_unset_asks_nothing_of_the_gate(self):
        self.sb.systemctl()
        report = self.sb.report()
        self.assertFalse(report["gateway"]["async_flag"])
        self.assertNotIn("forward_async_gate", report["drift"])

    def test_gate_line_enabled_with_two_cpus_passes(self):
        self.sb.gate("winn3-gateway: -forward-async-write enabled: 2.00 usable CPUs (affinity 2, no cgroup CPU limit)\n")
        report = self.sb.report()
        self.assertEqual(report["gateway"]["async_gate"], "enabled")
        self.assertEqual(report["gateway"]["usable_cpus"], 2.0)
        self.assertEqual(report["gateway"]["usable_cpus_source"], "gate_line")
        self.assertEqual(report["gateway"]["gate_line"],
                         "winn3-gateway: -forward-async-write enabled: 2.00 usable CPUs (affinity 2, no cgroup CPU limit)")
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_the_upper_case_spelling_of_the_design_also_reads(self):
        self.sb.gate("winn3-gateway: -forward-async-write ENABLED: 4.00 usable CPUs (affinity 4)\n")
        self.assertEqual(self.sb.report()["gateway"]["async_gate"], "enabled")

    def test_gate_line_disabled_fails_check(self):
        self.sb.gate("winn3-gateway: -forward-async-write DISABLED (below 2 usable CPUs; forwarding writes synchronously, as without the flag): 1.00 usable CPUs (affinity 1, no cgroup CPU limit)\n")
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("forward-async-write", proc.stderr)
        self.assertIn("forward_async_gate", self.sb.report()["drift"])

    def test_enabled_with_under_two_cpus_fails_check(self):
        self.sb.gate("winn3-gateway: -forward-async-write enabled: 1.50 usable CPUs (affinity 2, cgroup CPU limit 1.50)\n")
        self.assertEqual(self.sb.run("--check").returncode, 1)

    def test_a_computed_count_is_not_the_gateways_gate_decision(self):
        # No gate line anywhere, six usable CPUs by every fact on the host: the
        # count is reported, but only the gateway's own gate line can say the
        # gate enabled the async path, so the gate is unknown and the check
        # fails closed (P-9, MCR condition 3).
        self.sb.cgroup()
        report = self.sb.report()
        gateway = report["gateway"]
        self.assertEqual((gateway["async_gate"], gateway["usable_cpus"], gateway["usable_cpus_source"]),
                         (None, 6.0, "computed"))
        self.assertIn("forward_async_gate", report["drift"])
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("gate None", proc.stderr)

    def test_computed_count_honours_affinity_and_quota(self):
        self.sb.cgroup(affinity="0", cpuset="0")
        self.assertEqual(self.sb.report()["gateway"]["usable_cpus"], 1.0)
        self.sb.cgroup(affinity="0-3", cpuset="0-3", cpu_max="150000 100000")
        self.assertEqual(self.sb.report()["gateway"]["usable_cpus"], 1.5)
        self.sb.cgroup(affinity="0-5", cpuset="0-2", cpu_max="max 100000")
        self.assertEqual(self.sb.report()["gateway"]["usable_cpus"], 3.0)

    def test_an_ancestor_quota_limits_the_count(self):
        # The gateway's own rule walks up to the hierarchy root: a quota on the
        # slice above the service limits it too.
        self.sb.cgroup(mid_controllers="")
        self.sb.write("sys/fs/cgroup/system.slice/cpu.max", "200000 100000\n")
        self.sb.write("sys/fs/cgroup/cgroup.subtree_control", "cpu memory\n")
        self.assertEqual(self.sb.report()["gateway"]["usable_cpus"], 2.0)

    def test_an_unreadable_or_malformed_limit_is_not_no_limit(self):
        for bad in ("garbage", "100000", "x 100000", "50000 0", "50000 y", ""):
            self.sb.cgroup(cpu_max=bad)
            gateway = self.sb.report()["gateway"]
            self.assertIsNone(gateway["usable_cpus"], bad)
            self.assertEqual(gateway["usable_cpus_source"], "none", bad)
        self.sb.cgroup()
        quota = self.sb.root / "sys/fs/cgroup/system.slice/winn3-gateway.service/cpu.max"
        quota.unlink()
        quota.mkdir()  # exists but cannot be read as a file
        self.assertIsNone(self.sb.report()["gateway"]["usable_cpus"])

    def test_a_missing_cpu_max_is_unlimited_only_where_the_parent_has_no_cpu_controller(self):
        self.sb.cgroup(cpu_max=None, mid_controllers="memory pids")
        (self.sb.root / "sys/fs/cgroup/system.slice/cpu.max").write_text("max 100000\n")
        self.assertEqual(self.sb.report()["gateway"]["usable_cpus"], 6.0)
        # The parent enables cpu, yet the file is not there: unreadable.
        self.sb.write("sys/fs/cgroup/system.slice/cgroup.subtree_control", "cpu memory\n")
        self.assertIsNone(self.sb.report()["gateway"]["usable_cpus"])
        # The parent's controller list cannot be read: unreadable.
        (self.sb.root / "sys/fs/cgroup/system.slice/cgroup.subtree_control").unlink()
        self.assertIsNone(self.sb.report()["gateway"]["usable_cpus"])

    def test_an_unreadable_cpuset_or_a_missing_cgroup_is_unknown(self):
        self.sb.cgroup(cpuset="")
        self.assertIsNone(self.sb.report()["gateway"]["usable_cpus"])
        self.sb.cgroup()
        shutil.rmtree(self.sb.root / "sys/fs/cgroup/system.slice")
        self.assertIsNone(self.sb.report()["gateway"]["usable_cpus"])
        # A path with a ".." component is not followed, even where it resolves
        # to a directory that looks like a healthy cgroup under the hierarchy.
        self.sb.cgroup(rel="b")
        self.sb.write("sys/fs/cgroup/a/cgroup.subtree_control", "\n")
        self.sb.write("proc/4242/cgroup", "0::/a/../b\n")
        self.assertIsNone(self.sb.report()["gateway"]["usable_cpus"])
        self.sb.write("proc/4242/cgroup", "0::/b\n")
        self.assertEqual(self.sb.report()["gateway"]["usable_cpus"], 6.0)

    def test_nothing_readable_fails_closed(self):
        # The flag is set, no gate line, no process facts: the gate cannot be
        # proven enabled, so the check fails (MCR condition 3, fail closed).
        report = self.sb.report()
        self.assertEqual(report["gateway"]["usable_cpus_source"], "none")
        self.assertEqual(self.sb.run("--check").returncode, 1)

    def test_the_gate_line_is_kept_for_the_invocation_and_survives_the_journal(self):
        # The gateway prints the line once per start; a volatile journal or a
        # rotation drops it. The heartbeat keeps it for the invocation, so the
        # gate does not turn unknown, and the next beats skip the journal scan.
        self.sb.gate("winn3-gateway: -forward-async-write enabled: 6.00 usable CPUs (affinity 6)\n")
        self.assertEqual(self.sb.report()["gateway"]["async_gate"], "enabled")
        (self.sb.root / f"fx/journal_gate_{INVOCATION}.txt").unlink()
        (self.sb.root / "fx/journalctl.log").unlink()
        self.sb.advance(120)
        gateway = self.sb.report()["gateway"]
        self.assertEqual((gateway["async_gate"], gateway["usable_cpus"], gateway["usable_cpus_source"]),
                         ("enabled", 6.0, "gate_line"))
        log = (self.sb.root / "fx/journalctl.log").read_text() if (self.sb.root / "fx/journalctl.log").exists() else ""
        self.assertNotIn(" -g ", log)
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_a_kept_gate_line_is_not_another_invocations(self):
        self.sb.gate("winn3-gateway: -forward-async-write enabled: 6.00 usable CPUs (affinity 6)\n")
        self.sb.report()
        (self.sb.root / f"fx/journal_gate_{INVOCATION}.txt").unlink()
        self.sb.systemctl(execstart=self.ASYNC, invocation="d" * 32)
        self.sb.status(invocation="d" * 32)
        self.sb.advance(120)
        gateway = self.sb.report()["gateway"]
        self.assertIsNone(gateway["async_gate"])
        self.assertEqual(self.sb.run("--check").returncode, 1)

    def test_a_check_reads_the_kept_line_but_never_writes_one(self):
        self.sb.gate("winn3-gateway: -forward-async-write enabled: 6.00 usable CPUs (affinity 6)\n")
        self.assertEqual(self.sb.run("--check").returncode, 0)
        self.assertFalse((self.sb.root / "run/node-perf.state.gate").exists())
        self.sb.report()
        cache = self.sb.root / "run/node-perf.state.gate"
        self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o600)

    def test_a_damaged_kept_line_is_ignored(self):
        for body in ("{", "[]", json.dumps({"invocation": INVOCATION, "gate": ["enabled", "many", "x"]}),
                     json.dumps({"invocation": INVOCATION, "gate": ["maybe", 6.0, "x"]})):
            self.sb.write("run/node-perf.state.gate", body)
            self.assertIsNone(self.sb.report()["gateway"]["async_gate"], body)


class WanQdiscP1(PerfCase):
    def tc_root(self, text, dev="eth0"):
        self.sb.write(f"fx/tc_{dev}_root.txt", text)

    def test_the_fleet_constants_match(self):
        # 131072 / 32768 (tunnel-speed round 2, Turn 14): what every Canada
        # measurement and today's production ran on the WAN root.
        self.tc_root(FQ_ROOT.format(limit=131072, flow=32768))
        wan = self.sb.report()["wan_qdisc"]
        self.assertEqual((wan["dev"], wan["root"], wan["limit"], wan["flow_limit"], wan["match"]),
                         ("eth0", "fq", 131072, 32768, True))
        self.assertEqual(self.sb.report()["drift"], [])

    def test_the_old_fleet_flow_limit_256_is_drift(self):
        self.tc_root(FQ_ROOT.format(limit=131072, flow=256))
        self.assertEqual(self.sb.report()["drift"], ["wan_qdisc_flow_limit"])

    def test_the_round_2_installer_values_1024_and_20480_are_drift(self):
        # The values the installer wrote before Turn 14 (phase D measured them
        # as drops at the qdisc) read back as both kinds of drift.
        self.tc_root(FQ_ROOT.format(limit=20480, flow=1024))
        self.assertEqual(self.sb.report()["drift"], ["wan_qdisc_flow_limit", "wan_qdisc_limit"])

    def test_a_small_ram_node_wants_16384(self):
        self.sb.write("proc/meminfo", "MemTotal:       1967000 kB\n")
        self.tc_root(FQ_ROOT.format(limit=16384, flow=32768))
        self.assertTrue(self.sb.report()["wan_qdisc"]["match"])
        self.tc_root(FQ_ROOT.format(limit=131072, flow=32768))
        self.assertIn("wan_qdisc_limit", self.sb.report()["drift"])

    def test_wan_parameters_are_drift(self):
        good = FQ_ROOT.format(limit=131072, flow=32768)
        for wrong in (good.replace("quantum 1280 ", "quantum 16384 "),
                      good.replace("initial_quantum 25600 ", "initial_quantum 16384 "),
                      good.replace("refill_delay 1ms", "refill_delay 40ms"),
                      good.rstrip() + " nopacing\n",
                      good.rstrip() + " maxrate 1Gbit\n"):
            with self.subTest(wrong=wrong):
                self.assertNotEqual(wrong, good)
                self.tc_root(wrong)
                self.assertEqual(self.sb.report()["drift"], ["wan_qdisc_parameters"])

    def test_flow_limit_100_is_drift(self):
        self.tc_root(FQ_ROOT.format(limit=131072, flow=100))
        self.assertEqual(self.sb.report()["drift"], ["wan_qdisc_flow_limit"])

    def test_the_fleet_flow_limit_on_a_wrong_limit_is_limit_drift_only(self):
        self.tc_root(FQ_ROOT.format(limit=32768, flow=32768))
        self.assertEqual(self.sb.report()["drift"], ["wan_qdisc_limit"])

    def test_an_mq_root_is_drift(self):
        self.tc_root("qdisc mq 1: root\n")
        wan = self.sb.report()["wan_qdisc"]
        self.assertEqual((wan["root"], wan["match"]), ("mq", False))
        self.assertEqual(self.sb.report()["drift"], ["wan_qdisc_root"])

    def test_no_tc_or_no_device_is_unknown_not_drift(self):
        self.sb.remove_stub("tc")
        wan = self.sb.report()["wan_qdisc"]
        self.assertIsNone(wan["match"])
        self.assertEqual(self.sb.report()["drift"], [])

    def test_wan_iface_from_the_environment_wins(self):
        self.sb.write("fx/tc_ens3_root.txt", FQ_ROOT.format(limit=20480, flow=256))
        self.assertEqual(self.sb.report(WAN_IFACE="ens3")["wan_qdisc"]["dev"], "ens3")

    def test_override_names_are_reported_and_values_never(self):
        self.tc_root(FQ_ROOT.format(limit=20480, flow=256))
        self.sb.write("node.env", "NODE_TOKEN=do-not-print-me-7f3a\nWAN_FQ_FLOW_LIMIT=100\n"
                      "export RPS_CPU_MASK=3\nVPN_FQ_LIMIT=1\nWAN_QDISC_MODE=fq_codel\nOTHER=1\n")
        proc = self.sb.run("--json")
        self.assertEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertEqual(report["env_overrides"],
                         ["RPS_CPU_MASK", "VPN_FQ_LIMIT", "WAN_FQ_FLOW_LIMIT", "WAN_QDISC_MODE"])
        self.assertIn("wan_env_override", report["drift"])
        self.assertNotIn("do-not-print-me-7f3a", proc.stdout + proc.stderr)
        self.assertNotIn("fq_codel", proc.stdout)

    def test_wan_and_override_drift_is_reported_never_fatal_in_the_postflight(self):
        # Pin (design 10.2 P-4, P-5): until the helper that converges the queues
        # exists, environment overrides are still honoured, so failing the
        # postflight on the WAN read-back would reject every install. The
        # read-back is a report; --check fails only for P-1, P-9 and the P-5
        # queue read-back. The gateway here forwards, with a current helper
        # record and a calibrated winn3gw0, so only the WAN side is off.
        self.sb.systemctl()
        self.sb.status()
        self.sb.queue_ready()
        for root in ("qdisc mq 1: root\n", FQ_ROOT.format(limit=32768, flow=100), FQ_ROOT.format(limit=20480, flow=32768)):
            self.tc_root(root)
            self.assertTrue([r for r in self.sb.report()["drift"] if r.startswith("wan_qdisc")], root)
            self.assertEqual(self.sb.run("--check").returncode, 0, root)
        self.sb.write("node.env", "WAN_FQ_FLOW_LIMIT=100\n")
        self.sb.write("perf-trial.env", "WAN_FQ_FLOW_LIMIT=1024\n")
        self.assertIn("wan_env_override", self.sb.report()["drift"])
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_the_trial_file_is_reported_while_it_exists(self):
        self.tc_root(FQ_ROOT.format(limit=131072, flow=32768))
        self.assertFalse(self.sb.report()["perf_trial_env"])
        self.sb.write("perf-trial.env", "WAN_FQ_FLOW_LIMIT=1024\n")
        report = self.sb.report()
        self.assertTrue(report["perf_trial_env"])
        self.assertEqual(report["drift"], ["perf_trial_env"])


class Winn3gwQueuesP1(PerfCase):
    def setUp(self):
        super().setUp()
        self.sb.systemctl()
        self.sb.status()
        self.sb.write("sys/class/net/winn3gw0/ifindex", "17\n")
        self.sb.write("sys/class/net/winn3gw0/tx_queue_len", "10000\n")
        for n in range(2):
            (self.sb.root / f"sys/class/net/winn3gw0/queues/tx-{n}").mkdir(parents=True, exist_ok=True)
        self.mq(limit=20480, flow=256)

    def mq(self, limit, flow, children=2):
        self.sb.write("fx/tc_winn3gw0.txt", "qdisc mq 1: root\n" + "".join(
            FQ_CHILD.format(n=n + 1, limit=limit, flow=flow) for n in range(children)))

    def state(self, result="ok", pid=4242, ifindex=17):
        self.sb.write("run/winn3gw-queues.state", json.dumps(
            {"result": result, "main_pid": pid, "ifindex": ifindex, "qdisc": "mq"}))

    def test_an_absent_helper_with_the_calibrated_queue_is_no_drift(self):
        queues = self.sb.report()["winn3gw"]
        self.assertEqual((queues["queues"], queues["match"]), ("absent", True))
        self.assertEqual(self.sb.report()["drift"], [])

    def test_an_absent_helper_does_not_hide_a_measured_wrong_queue(self):
        # Helper absence and an observed queue mismatch are different facts and
        # both are fatal on a forwarding gateway (P-5): the mismatch is drift and
        # fails the postflight, and the missing record fails it by itself.
        self.sb.write("fx/tc_winn3gw0.txt", "qdisc mq 1: root\n" + FQ_CHILD.format(n=1, limit=20480, flow=100))
        queues = self.sb.report()["winn3gw"]
        self.assertEqual(queues["queues"], "absent")
        self.assertIs(queues["match"], False)
        self.assertEqual(self.sb.report()["drift"], ["winn3gw0_qdisc_mismatch"])
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not on the calibrated queue", proc.stderr)
        self.assertIn("no current queue-helper record", proc.stderr)

    def test_an_absent_helper_on_a_forwarding_gateway_fails_even_with_the_calibrated_queue(self):
        # The queue reads as calibrated but nothing recorded who set it: the
        # postflight does not accept a read-back without the owner's record.
        queues = self.sb.report()["winn3gw"]
        self.assertEqual((queues["queues"], queues["match"]), ("absent", True))
        self.assertEqual(self.sb.report()["drift"], [])
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no current queue-helper record", proc.stderr)
        self.assertNotIn("not on the calibrated queue", proc.stderr)
        self.state()
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_a_missing_helper_record_is_fine_where_no_gateway_forwards(self):
        # A reflector and a stopped gateway have no forwarding queue to judge.
        self.sb.systemctl(execstart="{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve -plan udp -max-sessions 22 ; ignore_errors=no }")
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 0)
        self.sb.systemctl(state="inactive")
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 0)

    def test_a_helper_record_that_says_failed_or_stale_fails_the_postflight(self):
        self.state(result="failed")
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("queue helper", proc.stderr)
        self.state(pid=999)
        self.assertEqual(self.sb.run("--check").returncode, 1)
        self.state(ifindex=18)
        self.assertEqual(self.sb.run("--check").returncode, 1)
        self.sb.write("run/winn3gw-queues.state", "{broken")
        self.assertEqual(self.sb.run("--check").returncode, 1)
        self.state()
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_a_helper_that_ran_but_left_a_wrong_queue_fails_the_postflight(self):
        self.state()
        self.mq(limit=20480, flow=100)
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("calibrated queue", proc.stderr)
        self.mq(limit=20480, flow=256)
        self.sb.write("sys/class/net/winn3gw0/tx_queue_len", "1000\n")
        self.assertEqual(self.sb.run("--check").returncode, 1)

    def test_a_failed_helper_beside_a_wrong_queue_names_both(self):
        self.state(result="failed")
        self.mq(limit=20480, flow=100)
        self.assertEqual(self.sb.report()["drift"], ["winn3gw0_qdisc_mismatch", "winn3gw_queues_failed"])

    def test_every_tx_queue_needs_its_own_calibrated_child(self):
        # Two TX queues and one calibrated child: the second queue runs the
        # default qdisc, so the read-back must not match.
        self.state()
        self.mq(limit=20480, flow=256, children=1)
        queues = self.sb.report()["winn3gw"]
        self.assertEqual((queues["children"], queues["match"]), (1, False))
        self.assertEqual(self.sb.report()["drift"], ["winn3gw0_qdisc_mismatch"])
        self.assertEqual(self.sb.run("--check").returncode, 1)
        # Two children on the same parent still leave one queue uncovered.
        self.sb.write("fx/tc_winn3gw0.txt", "qdisc mq 1: root\n" + "".join(
            FQ_CHILD.format(n=1, limit=20480, flow=256) for _ in range(2)))
        self.assertIs(self.sb.report()["winn3gw"]["match"], False)
        # More children than queues is not the calibrated layout either.
        self.mq(limit=20480, flow=256, children=3)
        self.assertIs(self.sb.report()["winn3gw"]["match"], False)
        self.mq(limit=20480, flow=256, children=2)
        self.assertIs(self.sb.report()["winn3gw"]["match"], True)

    def test_an_unreadable_queue_count_is_unknown_not_a_mismatch(self):
        # The report keeps the unknown honest (no mismatch drift), but a forwarding
        # gateway's postflight cannot take "unknown" for a successful read-back.
        self.state()
        shutil.rmtree(self.sb.root / "sys/class/net/winn3gw0/queues")
        queues = self.sb.report()["winn3gw"]
        self.assertIsNone(queues["match"])
        self.assertEqual(self.sb.report()["drift"], [])
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("could not be verified", proc.stderr)
        # Where nothing forwards, there is no queue to verify.
        self.sb.systemctl(execstart="{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway serve -plan udp -max-sessions 22 ; ignore_errors=no }")
        self.assertEqual(self.sb.run("--check", WINS_PERF_CHECK_RETRY_S="0").returncode, 0)

    def test_an_ok_record_with_a_queue_that_cannot_be_read_fails_the_postflight(self):
        # tc missing from PATH, and tc failing: the helper says ok but the live
        # queue was never read back, so match stays unknown.
        self.state()
        self.sb.remove_stub("tc")
        proc = self.sb.run("--check", PATH=f"{self.sb.bin}:{SYSTEM_PATH}")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("could not be verified", proc.stderr)
        (self.sb.root / "fx/tc_winn3gw0.txt").unlink()
        self.sb.install_stubs()
        self.assertIsNone(self.sb.report()["winn3gw"]["match"])
        self.assertEqual(self.sb.run("--check").returncode, 1)

    def test_an_unreadable_helper_record_is_failed_not_absent(self):
        # A record that exists but cannot be read (here a directory stands where
        # the file should be, which opens with an OSError other than "not found")
        # is a failed record. It must not collapse to "absent" and then pass.
        state = self.sb.root / "run/winn3gw-queues.state"
        state.mkdir()
        queues = self.sb.report()["winn3gw"]
        self.assertEqual(queues["queues"], "failed")
        self.assertEqual(self.sb.report()["drift"], ["winn3gw_queues_failed"])
        proc = self.sb.run("--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("record is failed", proc.stderr)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads a mode 000 file")
    def test_a_helper_record_without_read_permission_is_failed_not_absent(self):
        self.state()
        path = self.sb.root / "run/winn3gw-queues.state"
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        self.assertEqual(self.sb.report()["winn3gw"]["queues"], "failed")
        self.assertEqual(self.sb.run("--check").returncode, 1)
        path.chmod(0o600)
        self.assertEqual(self.sb.report()["winn3gw"]["queues"], "ok")

    def test_ok_state_with_the_live_queue_matching(self):
        self.state()
        queues = self.sb.report()["winn3gw"]
        self.assertEqual((queues["queues"], queues["root"], queues["match"], queues["qlen"]), ("ok", "mq", True, 10000))
        self.assertEqual(self.sb.report()["drift"], [])

    def test_a_small_ram_node_wants_children_at_10240(self):
        self.state()
        self.sb.write("proc/meminfo", "MemTotal:       1967000 kB\n")
        self.assertIs(self.sb.report()["winn3gw"]["match"], False)
        self.mq(limit=10240, flow=256)
        self.assertIs(self.sb.report()["winn3gw"]["match"], True)

    def test_failed_state_is_drift(self):
        self.state(result="failed")
        self.assertEqual(self.sb.report()["drift"], ["winn3gw_queues_failed"])

    def test_a_state_for_another_incarnation_is_stale(self):
        self.state(pid=999)
        self.assertEqual(self.sb.report()["winn3gw"]["queues"], "stale")
        self.state(ifindex=18)
        self.assertEqual(self.sb.report()["drift"], ["winn3gw_queues_stale"])

    def test_an_unreadable_state_file_is_failed(self):
        self.sb.write("run/winn3gw-queues.state", "{broken")
        self.assertEqual(self.sb.report()["winn3gw"]["queues"], "failed")

    def test_ok_state_but_a_wrong_live_queue_is_drift(self):
        self.state()
        self.mq(limit=20480, flow=100)
        self.assertEqual(self.sb.report()["drift"], ["winn3gw0_qdisc_mismatch"])

    def test_ok_state_but_a_wrong_qlen_is_drift(self):
        self.state()
        self.sb.write("sys/class/net/winn3gw0/tx_queue_len", "1000\n")
        self.assertEqual(self.sb.report()["drift"], ["winn3gw0_qdisc_mismatch"])

    def test_a_single_queue_device_may_carry_the_fq_root(self):
        self.state()
        shutil.rmtree(self.sb.root / "sys/class/net/winn3gw0/queues/tx-1")
        self.sb.write("fx/tc_winn3gw0.txt", FQ_ROOT.format(limit=20480, flow=256))
        self.assertTrue(self.sb.report()["winn3gw"]["match"])

    def test_a_stopped_gateway_has_no_queue_to_judge(self):
        self.state(result="failed")
        self.sb.systemctl(state="inactive")
        queues = self.sb.report()["winn3gw"]
        self.assertEqual((queues["queues"], queues["device"]), ("absent", False))
        self.assertEqual(self.sb.report()["drift"], [])


class NicEvidenceP1(PerfCase):
    K = textwrap.dedent("""\
        Features for eth0:
        rx-checksumming: on
        tx-checksumming: on
        generic-segmentation-offload: on
        generic-receive-offload: on
        large-receive-offload: off [fixed]
        tx-udp-segmentation: off [fixed]
        rx-gro-list: off
        rx-udp-gro-forwarding: off
        """)
    G = textwrap.dedent("""\
        Ring parameters for eth0:
        Pre-set maximums:
        RX:\t\t4096
        TX:\t\t4096
        Current hardware settings:
        RX:\t\t256
        TX:\t\t256
        """)

    def test_a_supported_nic_is_recorded_with_read_only_calls(self):
        self.sb.write("fx/ethtool_k.txt", self.K)
        self.sb.write("fx/ethtool_g.txt", self.G)
        proc = self.sb.run("--record-evidence")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        record = json.loads((self.sb.root / "evidence/nic.json").read_text())
        self.assertEqual(record["result"], "ok")
        self.assertEqual(record["dev"], "eth0")
        self.assertEqual(record["features"]["tx-udp-segmentation"], "off [fixed]")
        self.assertEqual(record["ring"], {"max": {"rx": 4096, "tx": 4096}, "current": {"rx": 256, "tx": 256}})
        self.assertEqual((self.sb.root / "fx/ethtool.log").read_text().split("\n")[:2], ["-k eth0", "-g eth0"])
        self.assertFalse((self.sb.root / "fx/ethtool.bad").exists())
        self.assertIn("Features for eth0", (self.sb.root / "evidence/ethtool-k.txt").read_text())

    def test_an_unsupported_nic_is_recorded_as_unsupported(self):
        for part in ("k", "g"):
            self.sb.write(f"fx/ethtool_{part}.err", "Cannot get device settings: Operation not supported\n")
            self.sb.write(f"fx/ethtool_{part}.rc", "75\n")
        self.assertEqual(self.sb.run("--record-evidence").returncode, 0)
        record = json.loads((self.sb.root / "evidence/nic.json").read_text())
        self.assertEqual(record["result"], "unsupported")
        self.assertIn("Operation not supported", record["detail"])

    def test_one_query_failing_is_partial(self):
        self.sb.write("fx/ethtool_k.txt", self.K)
        self.sb.write("fx/ethtool_g.err", "Cannot get device ring settings: Operation not supported\n")
        self.sb.write("fx/ethtool_g.rc", "75\n")
        self.sb.run("--record-evidence")
        self.assertEqual(json.loads((self.sb.root / "evidence/nic.json").read_text())["result"], "partial")

    def test_a_missing_ethtool_is_recorded_not_skipped(self):
        self.sb.remove_stub("ethtool")
        proc = self.sb.run("--record-evidence", PATH=f"{self.sb.bin}:{SYSTEM_PATH}")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads((self.sb.root / "evidence/nic.json").read_text())["result"], "ethtool_missing")

    def test_no_wan_device_is_recorded(self):
        (self.sb.root / "fx/ip_route.txt").write_text("", encoding="utf-8")
        self.sb.run("--record-evidence")
        self.assertEqual(json.loads((self.sb.root / "evidence/nic.json").read_text())["result"], "no_wan_device")

    def test_the_heartbeat_carries_the_recorded_evidence_not_a_live_probe(self):
        self.assertIsNone(self.sb.report()["nic"])
        self.sb.write("fx/ethtool_k.txt", self.K)
        self.sb.write("fx/ethtool_g.txt", self.G)
        self.sb.run("--record-evidence")
        (self.sb.root / "fx/ethtool.log").unlink()
        nic = self.sb.report()["nic"]
        self.assertEqual(nic["result"], "ok")
        self.assertFalse((self.sb.root / "fx/ethtool.log").exists())

    def test_the_program_never_changes_a_nic(self):
        # ethtool -K, -G, -s and -A change the device; only -k and -g are allowed.
        calls = re.findall(r'\["ethtool", ("[^"]+")', PERF_SCRIPT)
        self.assertEqual(sorted(set(calls)), ['"-g"', '"-k"'])
        self.assertNotRegex(PERF_SCRIPT, r'"(tc|ip|sysctl|ifconfig)",\s*"(qdisc\s*)?(replace|add|del|change|set|-w)')


class ProgramContractP1(PerfCase):
    def test_json_is_one_compact_object_with_the_designed_keys(self):
        proc = self.sb.run("--json")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.count("\n"), 1)
        report = json.loads(proc.stdout)
        for key in ("v", "interval_s", "softnet", "gateway", "sysctl", "wan_qdisc", "winn3gw",
                    "env_overrides", "perf_trial_env", "nic", "drift"):
            self.assertIn(key, report)
        self.assertLess(len(proc.stdout), 3000)

    def test_a_bare_node_reports_unknowns_and_exits_zero(self):
        shutil.rmtree(self.sb.root / "proc")
        shutil.rmtree(self.sb.root / "sys")
        for name in ("tc", "systemctl", "journalctl", "ip"):
            self.sb.remove_stub(name)
        proc = self.sb.run("--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["drift"], [])
        self.assertIsNone(report["gateway"]["carrying"])
        self.assertEqual(self.sb.run("--check").returncode, 0)

    def test_garbage_from_every_source_never_breaks_the_report(self):
        self.sb.systemctl(execstart="garbage")
        self.sb.write(f"fx/journal_status_{INVOCATION}.txt", '{"event":"posture","carrying":"many","udp_read_buffer":-4}\nnot json\n')
        self.sb.write("fx/tc_eth0_root.txt", "\x00\xff garbage\n")
        self.sb.write("proc/meminfo", "MemTotal: lots kB\n")
        self.sb.write("run/node-perf.state", "{{{")
        self.sb.write("run/winn3gw-queues.state", "[]")
        proc = self.sb.run("--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        json.loads(proc.stdout)

    def test_an_unknown_mode_is_refused(self):
        proc = self.sb.run("--frobnicate")
        self.assertEqual(proc.returncode, 2)

    def test_state_is_written_private(self):
        self.sb.report()
        state = self.sb.root / "run" / "node-perf.state"
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)

    def test_the_program_writes_nothing_but_its_state_and_evidence(self):
        self.assertNotRegex(PERF_SCRIPT, r"os\.(remove|unlink|rename|chmod|system|setuid)\b|shutil\.(rmtree|move|copy)")


class HeartbeatJoinP1(unittest.TestCase):
    """The register script asks the program and joins its report to the payload."""

    REGISTER = extract("cat > /usr/local/bin/wins-node-register <<'EOF'", "EOF")
    ACQUIRE = REGISTER[REGISTER.index('perf_report="null"'):REGISTER.index("# IA-DP-02: NODE_TOKEN")]
    MERGE = REGISTER[REGISTER.index('if [[ "${perf_report:-null}" != "null" ]]'):
                     REGISTER.index('registration_response=""')]

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="p1-hb-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        stub = self.root / "bin"
        stub.mkdir()
        (stub / "timeout").write_text('#!/bin/bash\nwhile [[ "${1:-}" == -* ]]; do case "$1" in -k|-s) shift 2 ;; *) shift ;; esac; done\nshift\nexec "$@"\n')
        (stub / "timeout").chmod(0o755)
        self.stub = stub

    def program(self, body):
        path = self.root / "perf"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def run_snippet(self, perf_path):
        acquire = self.ACQUIRE.replace("/usr/local/bin/wins-node-perf-readback", str(perf_path))
        merge = self.MERGE
        script = (f"set -Eeuo pipefail\n{acquire}\n"
                  "payload='{\"slug\":\"x\",\"winn3_gateway\":{\"state\":\"active\"}}'\n"
                  f"{merge}\nprintf '%s' \"${{payload}}\"\n")
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False,
                              env={"PATH": f"{self.stub}:{SYSTEM_PATH}", "HOME": str(self.root)})
        return proc

    def test_the_report_joins_the_payload(self):
        perf = self.program('#!/bin/bash\n[[ "$1" == --json ]] || exit 3\necho \'{"v":1,"drift":["wan_qdisc_root"]}\'\n')
        proc = self.run_snippet(perf)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["performance"], {"v": 1, "drift": ["wan_qdisc_root"]})
        self.assertEqual(payload["winn3_gateway"], {"state": "active"})
        self.assertEqual(payload["slug"], "x")

    def test_a_failing_program_sends_no_key(self):
        proc = self.run_snippet(self.program("#!/bin/bash\nexit 7\n"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("performance", json.loads(proc.stdout))

    def test_garbage_output_sends_no_key(self):
        proc = self.run_snippet(self.program("#!/bin/bash\necho 'not json'\n"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("performance", json.loads(proc.stdout))

    def test_a_non_object_sends_no_key(self):
        proc = self.run_snippet(self.program("#!/bin/bash\necho '[1,2]'\n"))
        self.assertNotIn("performance", json.loads(proc.stdout))

    def test_a_missing_program_sends_no_key(self):
        proc = self.run_snippet(self.root / "absent")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("performance", json.loads(proc.stdout))

    def test_the_acquisition_sits_outside_the_load_block_other_suites_extract(self):
        block = SOURCE[SOURCE.index("# Load inputs for the per-server load bar"):
                       SOURCE.index("# Data-plane code provenance, recomputed")]
        self.assertNotIn("wins-node-perf-readback", block)


class InstallerWiringP1(unittest.TestCase):
    def test_main_writes_the_program_before_the_register_script(self):
        main = SOURCE[SOURCE.index("\nmain() {"):]
        self.assertLess(main.index("  write_perf_readback_script\n"), main.index("  write_register_script\n"))

    def test_postflight_records_the_evidence_then_requires_the_check(self):
        body = SOURCE[SOURCE.index("\npostflight_data_plane() {"):SOURCE.index("# --- F-11: crash dumps")]
        self.assertIn("/usr/local/bin/wins-node-perf-readback --record-evidence", body)
        record = body.index("--record-evidence")
        check = body.index("/usr/local/bin/wins-node-perf-readback --check")
        self.assertLess(record, check)
        self.assertLess(check, body.index('log "Data-plane post-deployment validation passed"'))
        # The evidence is a report: its failure warns. The check is required.
        self.assertRegex(body, r"--record-evidence \\\n\s+\|\| warn ")
        self.assertRegex(body, r"--check \|\| \{\n\s+err ")

    def test_the_register_unit_estimate_counts_the_readback_before_the_registration_post(self):
        # SYNC-10: wins-node-perf-readback runs before the registration POST under
        # timeout -k 5 25, so the worst-case stage list gains up to 30 s and the
        # estimate, the stage times and the place the 300 s cut lands move with it.
        start = SOURCE.index("# SYNC-10: a oneshot has no start timeout")
        comment = SOURCE[start:SOURCE.index("TimeoutStartSec=300", start)]
        self.assertIn("timeout -k 5 25", SOURCE[SOURCE.index("perf_report="):][:400])
        for text in ("wins-node-perf-readback", "estimate of 428 s", "done by 261 s", "done by 308 s",
                     "starts by 338 s", "284 s to 338 s", "one of three places"):
            self.assertIn(text, comment)
        for stale in ("398 s", "done by 231 s", "done by 278 s", "starts by 308 s", "278 s to 308 s", "one of two places"):
            self.assertNotIn(stale, comment)
        # The stages add up to the stated figures.
        self.assertEqual(40 + 10 + 1 + 30 + 180, 261)
        self.assertEqual(261 + 23 + 24, 308)
        self.assertEqual(308 + 30, 338)
        self.assertEqual(338 + 90, 428)

    def test_the_program_is_installed_executable(self):
        fn = SOURCE[SOURCE.index("write_perf_readback_script() {"):SOURCE.index("write_register_script() {")]
        self.assertIn("chmod 0755 /usr/local/bin/wins-node-perf-readback", fn)

    def test_the_program_compiles_and_has_no_long_dashes(self):
        compile(PERF_SCRIPT, "wins-node-perf-readback", "exec")
        self.assertNotIn(chr(0x2014), PERF_SCRIPT)
        self.assertNotIn(chr(0x2013), PERF_SCRIPT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
