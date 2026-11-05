import socket, struct, json, subprocess, time, os, threading

D = r"C:\src\wins_vpn_build_20260803\build\windows\x64\runner\Debug"
LOG = r"C:\fleet\seam_replica.log"
CONF = r"C:\fleet\seam_replica.conf"

PRIVATE_KEY = os.environ.get("WINS_AWG_TEST_PRIVATE_KEY", "").strip()
if not PRIVATE_KEY:
    raise RuntimeError("WINS_AWG_TEST_PRIVATE_KEY is required")

def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
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

with open(LOG, "w", encoding="utf-8") as f:
    f.write("seam replica start\n")

# 1. seam socket
seam = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
seam.bind(("127.0.0.1", 0))
seam_port = seam.getsockname()[1]
log("seam bound 127.0.0.1:%d" % seam_port)

CONFIG = f"""[Interface]
PrivateKey = {PRIVATE_KEY}
Jc = 2
Jmin = 10
Jmax = 30
S1 = 16
S2 = 80
S3 = 16
S4 = 0
H1 = 11
H2 = 22
H3 = 33
H4 = 44

[Peer]
PublicKey = 3jeHy5jOFHWp4snc5btOGhx4Fu+yFcQUlwnDldxwgm0=
Endpoint = 127.0.0.1:%d
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
""" % seam_port
with open(CONF, "w", encoding="utf-8") as f:
    f.write(CONFIG)

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, cwd=D)
        return (r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))
    except Exception as e:
        return (-1, "", str(e))

run("awg.exe down winsvpn 2>nul & taskkill /F /IM winsvpn_awg_engine.exe 2>nul & taskkill /F /IM winn-datapath.exe 2>nul & ping -n 2 127.0.0.1 >nul")

eng = subprocess.Popen([os.path.join(D, "winsvpn_awg_engine.exe")], cwd=D,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
log("engine pid=%d" % eng.pid)
time.sleep(2)
code, out, err = run("awg.exe setconf winsvpn %s" % CONF)
log("setconf rc=%d %s %s" % (code, out.strip()[:200], err.strip()[:200]))

dp = subprocess.Popen([os.path.join(D, "winn-datapath.exe"), "-transport", "stdio"],
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
log("datapath pid=%d" % dp.pid)

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
dp.stdin.write(frame(0x0001, create_json))
dp.stdin.flush()
log("create sent")
ack = read_frame(dp.stdout)
log("ack: %s" % (ack[1][:200].decode("utf-8", "replace") if ack else None))

awg_peer = [None]
counters = {"seam_to_engine": 0, "engine_to_seam": 0}

def pump_seam_to_engine():
    seam.settimeout(0.5)
    while True:
        try:
            data, sender = seam.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        if awg_peer[0] is None:
            awg_peer[0] = sender
            log("awg_peer learned: %s" % (sender,))
        elif awg_peer[0] != sender:
            log("unexpected sender %s (pinned %s)" % (sender, awg_peer[0]))
            continue
        dp.stdin.write(frame(0x0010, data))
        dp.stdin.flush()
        counters["seam_to_engine"] += 1

def pump_engine_to_seam():
    dp.stdout.flush()
    while True:
        f = read_frame(dp.stdout)
        if f is None:
            log("datapath stdout EOF")
            break
        opcode, payload = f
        if opcode == 0x0011:
            if awg_peer[0] is None:
                log("outbound frame before peer known: dropped")
                continue
            seam.sendto(payload, awg_peer[0])
            counters["engine_to_seam"] += 1
        elif opcode in (0x0021, 0x0002):
            log("status/ack: %s" % payload[:200].decode("utf-8", "replace"))
        else:
            log("opcode 0x%04x payload %d" % (opcode, len(payload)))

t1 = threading.Thread(target=pump_seam_to_engine, daemon=True)
t2 = threading.Thread(target=pump_engine_to_seam, daemon=True)
t1.start(); t2.start()

for i in range(20):
    time.sleep(2)
    code, out, err = run("awg.exe show winsvpn transfer")
    log("t=%ds counters=%s transfer=%s" % (i * 2, counters, (out or err).strip()[:120]))
    code, out, err = run("awg.exe show winsvpn | findstr handshake")
    if out.strip():
        log("handshake: %s" % out.strip()[:120])

dp.stdin.write(frame(0x0020, b""))
dp.stdin.flush()
time.sleep(1)
f = read_frame(dp.stdout)
if f:
    log("final status: %s" % f[1][:400].decode("utf-8", "replace"))

run("awg.exe down winsvpn 2>nul")
for p in (eng, dp):
    try:
        p.terminate()
    except Exception:
        pass
log("seam replica end")
