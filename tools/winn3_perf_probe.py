#!/usr/bin/env python3
"""In-namespace load and latency probe for the local functional trial of winn3_perf_bench.py.

Why it exists: the l80 VM has no iperf3, ping or fio and nothing may be installed, so the local
netns trial needs a load generator of its own. It models what the v3 session does to a queue: ONE
UDP flow (one 5-tuple) carries bulk download data and the latency probes together, so the probes
wait behind the bulk packets in whatever fq flow queue they share. It is a functional tool for
checking the harness. It makes no claim about v3 speed, and a run from it is never adoptable.

  server --bind IP:PORT
      echo pings ('P' -> 'R'); on 'S' (mbps, secs, size) send paced 'D' datagrams to the asker
  client --server IP:PORT --profile a|b --secs N --offered a=130,b=130 [--dev DEV]
      idle pings, then bulk download plus pings; prints one JSON run record on its last line

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True

# netem shaping applied on the client's own veth before a run (the server side holds the fq under test)
PROFILES = {"a": "delay 5ms", "b": "delay 20ms 5ms loss 0.5%"}
HDR = struct.Struct("!cIq")      # type, sequence, sender timestamp (ns)
START = struct.Struct("!dId")    # offered Mbit/s, datagram size, seconds
PING_GAP_S = 0.02


def set_sndbuf(sock, nbytes):
    for opt in (getattr(socket, "SO_SNDBUFFORCE", 32), socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, nbytes)
            return
        except OSError:
            continue


def serve(bind, max_secs):
    host, port = bind.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))
    set_sndbuf(sock, 64 << 20)
    sock.settimeout(0.5)
    deadline = time.monotonic() + max_secs
    stats = {"pings": 0, "bulk_sent": 0}

    def blast(addr, mbps, size, secs):
        payload = bytearray(size)
        t0 = time.perf_counter()
        sent_bytes = 0
        seq = 0
        while True:
            now = time.perf_counter() - t0
            if now >= secs:
                break
            due = int(mbps * 1e6 / 8 * now)
            while sent_bytes < due:
                payload[:HDR.size] = HDR.pack(b"D", seq, 0)
                try:
                    sock.sendto(payload, addr)
                except OSError:
                    break
                sent_bytes += size
                seq += 1
            time.sleep(0.0005)
        stats["bulk_sent"] += seq
        for _ in range(5):
            sock.sendto(HDR.pack(b"E", 0, 0), addr)
            time.sleep(0.01)

    while time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if not data:
            continue
        kind = data[:1]
        if kind == b"P":
            stats["pings"] += 1
            sock.sendto(b"R" + data[1:], addr)
        elif kind == b"S":
            mbps, size, secs = START.unpack(data[1:1 + START.size])
            threading.Thread(target=blast, args=(addr, mbps, int(size), secs), daemon=True).start()
    print(json.dumps(stats))
    return 0


def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    k = max(1, -(-int(p * len(sorted_vals)) // 100))
    return sorted_vals[k - 1]


def client(server, profile, secs, offered, size, idle_secs, dev):
    host, port = server.rsplit(":", 1)
    if dev:
        subprocess.run(["tc", "qdisc", "replace", "dev", dev, "root", "netem"] + PROFILES[profile].split(),
                       check=True, capture_output=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((host, int(port)))
    sock.settimeout(0.2)
    sent = {}
    rtts = {"idle": [], "loaded": []}
    phase = {"name": "idle"}
    bulk = {"bytes": 0, "t_first": None, "t_last": None}
    stop = threading.Event()

    def recv_loop():
        buf = bytearray(4096)
        while not stop.is_set():
            try:
                n = sock.recv_into(buf)
            except (socket.timeout, ConnectionRefusedError):
                continue
            now = time.perf_counter_ns()
            kind = bytes(buf[:1])
            if kind == b"R":
                _, seq, _ = HDR.unpack_from(buf)
                tx = sent.pop(seq, None)
                if tx is not None:
                    rtts[tx[1]].append((now - tx[0]) / 1e6)
            elif kind == b"D":
                bulk["bytes"] += n
                bulk["t_first"] = bulk["t_first"] or now
                bulk["t_last"] = now

    rt = threading.Thread(target=recv_loop, daemon=True)
    rt.start()
    seq = 0

    def ping_for(seconds, name):
        nonlocal seq
        end = time.monotonic() + seconds
        phase["name"] = name
        count = 0
        while time.monotonic() < end:
            seq += 1
            sent[seq] = (time.perf_counter_ns(), name)
            sock.send(HDR.pack(b"P", seq, 0))
            count += 1
            time.sleep(PING_GAP_S)
        return count

    n_idle = ping_for(idle_secs, "idle")
    sock.send(b"S" + START.pack(float(offered[profile]), size, float(secs)))
    n_loaded = ping_for(secs, "loaded")
    time.sleep(0.4)
    stop.set()
    rt.join(timeout=1.0)
    idle, loaded = sorted(rtts["idle"]), sorted(rtts["loaded"])
    seqd = [b - a for a, b in zip(rtts["loaded"], rtts["loaded"][1:])]
    span = (bulk["t_last"] - bulk["t_first"]) / 1e9 if bulk["t_first"] and bulk["t_last"] and bulk["t_last"] > bulk["t_first"] else None
    rec = {
        "started": bool(idle) and bool(loaded),
        "alive": bool(loaded),
        "idle_p50_ms": pct(idle, 50),
        "ld_p50_ms": pct(loaded, 50),
        "ld_p99_ms": pct(loaded, 99),
        "ld_jitter_ms": (sum(abs(d) for d in seqd) / len(seqd)) if seqd else None,
        "ld_loss_pct": 100.0 * (n_loaded - len(loaded)) / n_loaded if n_loaded else None,
        "thr_mbps": (bulk["bytes"] * 8 / 1e6 / span) if span else None,
        "sessions_started": 1 if idle else 0,
        "sessions_failed": 0 if idle else 1,
        "failure_class": None if idle else "no_idle_reply",
        "tool": "winn3_perf_probe",
        "probes_idle": n_idle,
        "probes_loaded": n_loaded,
    }
    print(json.dumps(rec))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server")
    s.add_argument("--bind", required=True)
    s.add_argument("--max-secs", type=float, default=3600.0)
    c = sub.add_parser("client")
    c.add_argument("--server", required=True)
    c.add_argument("--profile", choices=sorted(PROFILES), required=True)
    c.add_argument("--secs", type=float, default=5.0)
    c.add_argument("--idle-secs", type=float, default=1.5)
    c.add_argument("--size", type=int, default=1400)
    c.add_argument("--offered", default="a=130,b=130", help="Mbit/s per profile, for example a=130,b=130")
    c.add_argument("--dev", default="", help="client veth that gets the profile's netem")
    a = ap.parse_args(argv)
    if a.cmd == "server":
        return serve(a.bind, a.max_secs)
    offered = {k: float(v) for k, v in (x.split("=") for x in a.offered.split(","))}
    return client(a.server, a.profile, a.secs, offered, a.size, a.idle_secs, a.dev)


if __name__ == "__main__":
    sys.exit(main())
