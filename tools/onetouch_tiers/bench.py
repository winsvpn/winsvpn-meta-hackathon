"""The 5.7 / 10.x benchmark plan as data: which trial runs when, with which arms, and what each run must record.

Nothing here measures anything. It fixes the order (design 5.7 "Bench order"), the arms and the record shape, and it
gives `tier_b.py`'s throughput scenario its steps, so a bench run on aicore or a canary node follows the design's order
and cannot silently skip a recorded field. Every number a trial produces is judged by rule R over both netem
profiles (`readbacks.rule_r_adopt_profiles`) and never by this module.
"""

# Fields every throughput / latency run records (5.7 "Recorded in the same run").
RECORD_FIELDS = (
    "node_class", "binary_sha256", "profile", "direction", "flows", "loaded_ping_p50_ms", "loaded_ping_p99_ms", "jitter_ms",
    "probe_loss", "session_start_failures", "per_cpu_softirq_share", "softnet_drops", "gateway_inbox_drops", "rcvbuf_errors",
    "winn3gw0_tx_drops", "tcp_retransmissions", "awg_loaded_latency_ms", "xray_loaded_latency_ms", "base_rise_ms", "rule_r_branch",
)

# Bench order stage 1: P-17 first. Stage 2: the remaining latency trials. Stage 3: the throughput trials.
STAGE_FIRST, STAGE_LATENCY, STAGE_THROUGHPUT = 1, 2, 3

TRIALS = [
    {"id": "P-17", "stage": STAGE_FIRST, "host": "aicore, then one canary node at its natural CPU count", "kind": "latency",
     "design": "winn3gw0 ring 10000 (base), 4096, 2048 and 1024 with the gateway pinned to 1 and to 2 CPUs, under the canonical bench lock",
     "arms": [{"ring": r, "cpus": c} for c in (1, 2) for r in (10000, 4096, 2048, 1024)],
     "set": "ethtool -G winn3gw0 rx {ring} tx {ring} 2>&1 || ip link set dev winn3gw0 txqueuelen {ring}; systemctl set-property winn3-gateway.service AllowedCPUs=0-{cpu_last}",
     "restore": "ip link set dev winn3gw0 txqueuelen 10000; systemctl set-property winn3-gateway.service AllowedCPUs="},
    {"id": "P-4", "stage": STAGE_LATENCY, "host": "canary node", "kind": "latency",
     "design": "WAN flow_limit arms 100, 256 (release base), 1024 and 2048, single v3 session download",
     "arms": [{"flow_limit": f} for f in (100, 256, 1024, 2048)],
     "set": "tc qdisc replace dev {wan} root fq flow_limit {flow_limit}", "restore": "systemctl restart wins-edge-queues.service"},
    {"id": "P-22", "stage": STAGE_LATENCY, "host": "canary node", "kind": "latency",
     "design": "WAN fq quantum 1280 against 1514", "arms": [{"quantum": q} for q in (1514, 1280)],
     "set": "tc qdisc replace dev {wan} root fq quantum {quantum} flow_limit {fleet_flow_limit}", "restore": "systemctl restart wins-edge-queues.service"},
    {"id": "P-3", "stage": STAGE_LATENCY, "host": "canary node", "kind": "latency",
     "design": "busy poll off against busy_poll=50 with busy_read=50", "arms": [{"busy": 0}, {"busy": 50}],
     "set": "sysctl -w net.core.busy_poll={busy} net.core.busy_read={busy}", "restore": "sysctl -w net.core.busy_poll=0 net.core.busy_read=0"},
    {"id": "P-10", "stage": STAGE_LATENCY, "host": "canary node", "kind": "latency",
     "design": "gateway CPUWeight/IOWeight against the defaults, with Suricata, AWG and Xray loaded at the same time",
     "arms": [{"weight": 100}, {"weight": 200}, {"weight": 500}],
     "set": "systemctl set-property winn3-gateway.service CPUWeight={weight} IOWeight={weight}",
     "restore": "systemctl set-property winn3-gateway.service CPUWeight= IOWeight="},
    {"id": "P-18-P-41-P-46", "stage": STAGE_LATENCY, "host": "aicore", "kind": "latency",
     "design": "the gateway-round latency trials P-18, P-41 and P-46", "arms": [{"candidate": "base"}, {"candidate": "P-18"}, {"candidate": "P-41"}, {"candidate": "P-46"}],
     "set": "# a candidate gateway binary is staged by the gateway round; arms are binary digests", "restore": "# restore the certified binary"},
    {"id": "P-24", "stage": STAGE_THROUGHPUT, "host": "aicore", "kind": "throughput",
     "design": "only if P-17 shows fq child backlog at about 0 while winn3gw0 TX drops rise: noqueue on winn3gw0 against mq with fq children",
     "arms": [{"qdisc": "mq-fq"}, {"qdisc": "noqueue"}], "condition": "P-17 shows fq child backlog about 0 and winn3gw0 TX drops rising",
     "set": "tc qdisc replace dev winn3gw0 root {qdisc_cmd}", "restore": "systemctl restart wins-winn3gw-queues.service"},
]
for _id in ("P-20", "P-21", "P-25", "P-26", "P-27", "P-28", "P-29", "P-31", "P-32", "P-35", "P-36", "P-39", "P-40", "P-44"):
    TRIALS.append({"id": _id, "stage": STAGE_THROUGHPUT, "host": "aicore", "kind": "throughput",
                   "design": "throughput trial %s (gateway round or 10A to 10E proposal; P-44 is trialled together with P-39)" % _id,
                   "arms": [{"candidate": "base"}, {"candidate": _id}], "set": "# staged candidate", "restore": "# restore the certified binary"})

# Measured in Tier A as functional timing, not in the bench order (5.7 and 10.6).
INSTALLER_SIDE = ("P-33", "P-34", "P-37", "P-38", "P-42", "P-43", "P-45", "P-47")

IPERF = {
    "profiles": {"a": "clean, about 70 ms RTT", "b": "cellular, about 80 to 95 Mbit/s with a bufferbloat queue"},
    "matrix": [{"direction": d, "flows": f, "proto": p} for d in ("up", "down") for f, p in ((1, "tcp"), (4, "tcp"), (1, "udp-paced"))],
    "command": {"tcp": "iperf3 -c {server} -p {port} -P {flows} -t 20 {reverse} --json",
                "udp-paced": "iperf3 -c {server} -p {port} -u -b {rate} -t 20 {reverse} --json"},
}

# 5.7 replay-journal storm (P-19, measurement only) and the one-time PERF-1 decline check.
STORM = {
    "fio": "fio --name=journal --rw=write --bs=4k --fsync=1 --size=64m --runtime=20 --time_based --output-format=json",
    "sessions": "min(64, the node's -max-sessions); Chicago's fit is 22 (G 4292-4298)",
    "timeout_s": 30,
    "refusals_above_limit": 4,
}
EPOLL_DECLINE = "strace -f -c -e epoll_ctl -p $(systemctl show winn3-gateway.service -p MainPID --value) -o {out} & sleep 20; kill %1"


def ordered():
    """Trials in the design's bench order: P-17 first, then latency, then throughput; stable inside a stage."""
    return sorted(TRIALS, key=lambda t: (t["stage"], TRIALS.index(t)))


def trial_steps(trial, variables):
    """Owner-visible steps for one trial: set each arm, run the matrix, record, restore. Used by tier_b's TB-31."""
    steps = []
    for arm in trial["arms"]:
        text = "arm %s: %s" % (arm, trial["set"].format(**dict(variables, **arm, cpu_last=max(0, arm.get("cpus", 1) - 1))))
        steps.append(("owner", "trial %s on %s. %s. Run the iperf3 matrix on profiles a and b, record %s, judge with rule R."
                      % (trial["id"], trial["host"], text, ", ".join(RECORD_FIELDS[:6]) + ", ...")))
    steps.append(("owner", "trial %s: restore with: %s" % (trial["id"], trial["restore"])))
    return steps
