import subprocess, struct, json, sys, time, threading, os

EXE = r"C:\src\wins_vpn_build_20260803\build\windows\x64\runner\Debug\winn-datapath.exe"
OUT = r"C:\fleet\dp_probe.log"

def log(m):
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(m + "\n")

def frame(opcode, payload):
    return struct.pack("<IHHII", 0x334E4E57, 1, opcode, len(payload), 0) + payload

def read_frame(stream):
    hdr = stream.read(16)
    if len(hdr) < 16:
        return None
    magic, ver, opcode, length, reserved = struct.unpack("<IHHII", hdr)
    payload = stream.read(length) if length else b""
    return opcode, payload

create_json = json.dumps({
    "contract": "winn-datapath/1",
    "payload": "awg-datagram",
    "carrier": "direct-awg",
    "gateway_endpoint": "<DATA_SIM_IP>:9110",
    "max_datagram": 1420,
    "session_id": "0123456789abcdef0123456789abcdef",
    "allow_own_socket": True,
    "awg_header_types": {"h1": 11, "h2": 22, "h3": 33, "h4": 44,
                          "s1": 16, "s2": 80, "s3": 16, "s4": 0},
}).encode("utf-8")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("probe start\n")

p = subprocess.Popen([EXE, "-transport", "stdio"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)

log("spawned pid=%d" % p.pid)

p.stdin.write(frame(0x0001, create_json))
p.stdin.flush()
log("sent create")

deadline = time.time() + 6
responses = []
while time.time() < deadline:
    opcode, payload = read_frame(p.stdout)
    if opcode is None:
        break
    log("resp opcode=0x%04x payload=%s" % (opcode, payload[:300].decode("utf-8", "replace")))
    if opcode == 0x0002:
        break

fake = b"\x04" + bytes(147)
for i in range(5):
    p.stdin.write(frame(0x0010, fake))
    p.stdin.flush()
    log("sent inbound #%d (%d bytes)" % (i, len(fake)))
    time.sleep(0.4)

p.stdin.write(frame(0x0020, b""))
p.stdin.flush()
log("sent status request")

deadline = time.time() + 10
while time.time() < deadline:
    opcode, payload = read_frame(p.stdout)
    if opcode is None:
        break
    log("post resp opcode=0x%04x payload=%s" % (opcode, payload[:500].decode("utf-8", "replace")))

p.stdin.write(frame(0x0030, b""))
p.stdin.flush()
time.sleep(1)
try:
    p.stdin.close()
except Exception:
    pass
try:
    p.terminate()
except Exception:
    pass
time.sleep(1)
if p.poll() is None:
    p.kill()
err = b""
try:
    err = p.stderr.read()
except Exception:
    pass
log("exit=%s stderr=%s" % (p.poll(), err.decode("utf-8", "replace")[:800]))
log("probe end")
