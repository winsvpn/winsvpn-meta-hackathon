import socket, subprocess, time, os, threading

D = r"C:\src\wins_vpn_build_20260803\build\windows\x64\runner\Debug"
LOG = r"C:\fleet\seam_probe2.log"
CONF = r"C:\fleet\seam_probe2.conf"

PRIVATE_KEY = os.environ.get("WINS_AWG_TEST_PRIVATE_KEY", "").strip()
if not PRIVATE_KEY:
    raise RuntimeError("WINS_AWG_TEST_PRIVATE_KEY is required")

def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(m + "\n")

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, cwd=D)
        return (r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))
    except Exception as e:
        return (-1, "", str(e))

with open(LOG, "w", encoding="utf-8") as f:
    f.write("seam probe2 start\n")

seam = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
seam.bind(("127.0.0.1", 0))
seam.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
seam_port = seam.getsockname()[1]
log("seam 127.0.0.1:%d" % seam_port)

ctrl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ctrl.sendto(b"CONTROL_PROBE_1", ("127.0.0.1", seam_port))
seam.settimeout(2)
try:
    d, sender = seam.recvfrom(2048)
    log("control received: %r from %s" % (d, sender))
except socket.timeout:
    log("CONTROL NOT RECEIVED")

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

run("awg.exe down winsvpn 2>nul & taskkill /F /IM winsvpn_awg_engine.exe 2>nul & ping -n 2 127.0.0.1 >nul")
eng = subprocess.Popen([os.path.join(D, "winsvpn_awg_engine.exe")], cwd=D,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
log("engine pid=%d" % eng.pid)
time.sleep(2)
code, out, err = run("awg.exe setconf winsvpn %s" % CONF)
log("setconf rc=%d err=%s" % (code, err.strip()[:200]))
code, out, err = run("netstat -ano -p udp | findstr %d" % eng.pid)
log("engine sockets:\n%s" % (out or err))

received = []
seam.settimeout(0.5)
def drain():
    while True:
        try:
            d, sender = seam.recvfrom(2048)
            received.append((d, sender))
        except socket.timeout:
            continue
        except OSError:
            break
t = threading.Thread(target=drain, daemon=True)
t.start()

for i in range(10):
    time.sleep(2)
    code, out, err = run("awg.exe show winsvpn transfer")
    log("t=%ds received=%d transfer=%s" % (i * 2, len(received), (out or err).strip()[:100]))
    if received:
        log("sample: %r from %s" % (received[0][0][:40], received[0][1]))

code, out, err = run("awg.exe show winsvpn dump")
log("dump: %s" % out.strip()[:300])
run("awg.exe down winsvpn 2>nul")
eng.terminate()
try:
    errout = eng.communicate(timeout=3)[1].decode("utf-8", "replace")
    log("engine stderr:\n%s" % errout[:600])
except Exception:
    eng.kill()
log("seam probe2 end")
