#!/usr/bin/env python3
"""Live proof of the proxy boundary, against the real harness-host binary.

Runs the compiled host, drives it over real native-messaging frames, and then
checks with the OPERATING SYSTEM'S OWN VIEW (lsof) where the proxy is bound --
rather than trusting the source code that says `loopbackIPv4`.

Proves:
  1. The proxy listens on 127.0.0.1 and on NO other address.
  2. It is unreachable from this machine's LAN address.
  3. It refuses an authenticated request while the tunnel is down (fail closed).
  4. It refuses an unauthenticated request.

THE TOKEN IS NEVER PRINTED. It is read from the host's reply, held in a local
variable, and used to build one Authorization header. Nothing writes it to a
file or to stdout.

The executable must be compiled from wins_bridge_host_harness.dart. The probe
creates its own private state file, opens the proxy while the state is connected,
then closes the gate before sending any CONNECT target. The production entry
point's refusal while the app is absent is covered by framing_conformance_probe.py.

Usage: python3 live_boundary_probe.py <path-to-harness-host-executable>
"""

import base64
import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def frame(obj):
    body = json.dumps(obj).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def read_frame(stream):
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    return json.loads(stream.read(length).decode("utf-8"))


def lan_addresses():
    """Non-loopback IPv4 addresses of this machine."""
    out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    found = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return [a for a in found if not a.startswith("127.")]


def http_probe(port, authorization=None):
    """Send one CONNECT and return the status line."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    req = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n"
    if authorization:
        req += "Proxy-Authorization: %s\r\n" % authorization
    req += "\r\n"
    s.sendall(req.encode())
    data = s.recv(4096).decode("utf-8", "replace")
    s.close()
    return data.split("\r\n")[0]


def main():
    if len(sys.argv) < 2:
        print("usage: live_boundary_probe.py <harness-host-executable>")
        return 2
    host = sys.argv[1]
    failures = []

    state_dir = tempfile.TemporaryDirectory(prefix="wins-bridge-boundary-")
    state_file = Path(state_dir.name) / "state.json"

    def write_state(status, proxy_ready):
        temporary = state_file.with_suffix(".new")
        temporary.write_text(
            json.dumps({
                "status": status,
                "detail": status,
                "winn": "unavailable_on_this_platform",
                "selectedSlug": "",
                "nodes": [],
                "canRequestConnect": False,
                "proxyReady": proxy_ready,
                "rxKib": 0,
                "txKib": 0,
            }),
            encoding="utf-8",
        )
        temporary.replace(state_file)

    write_state("connected", True)

    proc = subprocess.Popen(
        [host, "--state-file", str(state_file)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    proc.stdin.write(frame({"v": 1, "id": "p1", "type": "issue_proxy_credential"}))
    proc.stdin.flush()
    reply = read_frame(proc.stdout)

    if not isinstance(reply, dict) or reply.get("type") != "proxy_credential":
        proc.kill()
        stderr = proc.stderr.read(4096).decode("utf-8", "replace")
        state_dir.cleanup()
        print("FAIL: harness did not issue a proxy credential: %r" % reply)
        if stderr:
            print("host stderr: %s" % stderr.strip())
        return 1

    token = reply.get("token")          # never printed
    port = reply.get("proxyPort")
    if not isinstance(token, str) or not token or not isinstance(port, int):
        proc.kill()
        state_dir.cleanup()
        print("FAIL: malformed proxy credential reply")
        return 1
    print("host pid %d, proxy port %s, token length %d (value not shown)"
          % (proc.pid, port, len(token or "")))
    print("reported tunnel state: %s / winn: %s"
          % (reply.get("status"), reply.get("winn")))

    time.sleep(0.4)

    # ---- 1. What the OS says the socket is bound to -----------------------
    lsof = subprocess.run(
        ["lsof", "-nP", "-iTCP", "-a", "-p", str(proc.pid)],
        capture_output=True, text=True).stdout
    listen_lines = [l for l in lsof.splitlines() if "LISTEN" in l]
    print("\nlsof LISTEN lines for the host process:")
    for line in listen_lines:
        print("  " + " ".join(line.split()))

    if not listen_lines:
        failures.append("no listening socket found for the host process")
    for line in listen_lines:
        m = re.search(r"(\S+):(\d+) \(LISTEN\)", line)
        if not m:
            failures.append("could not parse: %s" % line)
            continue
        bound = m.group(1)
        if bound != "127.0.0.1":
            failures.append(
                "proxy bound to %s, not 127.0.0.1 -- anything on the LAN "
                "could use the tunnel" % bound)
        if bound in ("*", "0.0.0.0", "::"):
            failures.append("WILDCARD BIND: %s" % bound)

    # ---- 2. Unreachable from the LAN address ------------------------------
    lan = lan_addresses()
    print("\nnon-loopback IPv4 addresses on this machine: %s" % (lan or "none"))
    for address in lan:
        try:
            s = socket.create_connection((address, port), timeout=2)
            s.close()
            failures.append(
                "proxy ANSWERED on %s:%d -- it is not loopback-only"
                % (address, port))
        except (socket.timeout, ConnectionRefusedError, OSError):
            print("  %s:%d refused, as required" % (address, port))

    # ---- 3. Close the gate before naming any CONNECT target ---------------
    write_state("disconnected", False)
    proc.stdin.write(frame({"v": 1, "id": "p2", "type": "get_status"}))
    proc.stdin.flush()
    down = read_frame(proc.stdout)
    if not isinstance(down, dict) or down.get("status") != "disconnected":
        failures.append("harness did not acknowledge the disconnected state")

    # ---- 4. Fail closed, authenticated ------------------------------------
    auth = "Basic " + base64.b64encode(("bridge:%s" % token).encode()).decode()
    status = http_probe(port, auth)
    print("\nauthenticated CONNECT while tunnel is down -> %s" % status)
    if "503" not in status:
        failures.append(
            "authenticated request was not refused while the tunnel was down "
            "(got %r) -- THIS IS THE LEAK THE FEATURE MUST NOT HAVE" % status)

    # ---- 5. Unauthenticated ------------------------------------------------
    status_noauth = http_probe(port)
    print("unauthenticated CONNECT                   -> %s" % status_noauth)
    if "407" not in status_noauth:
        failures.append("unauthenticated request was not challenged (got %r)"
                        % status_noauth)

    # ---- 6. The port dies with the process --------------------------------
    proc.stdin.close()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        failures.append("host did not exit when the browser closed stdin")
    time.sleep(0.3)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        failures.append("proxy port %d still open after the host exited" % port)
    except OSError:
        print("\nproxy port %d closed after host exit, as required" % port)
    state_dir.cleanup()

    print("\n" + "=" * 60)
    if failures:
        for f in failures:
            print("FAIL: %s" % f)
        return 1
    print("PASS: loopback-only, LAN-unreachable, fails closed while the "
          "tunnel is down, challenges unauthenticated callers, and the "
          "listener dies with the browser session.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
