import subprocess, time, os

D = r"C:\src\wins_vpn_build_20260803\build\windows\x64\runner\Debug"
LOG = r"C:\fleet\awg_engine_probe.log"
CONF = r"C:\fleet\manual_awg.conf"

PRIVATE_KEY = os.environ.get("WINS_AWG_TEST_PRIVATE_KEY", "").strip()
if not PRIVATE_KEY:
    raise RuntimeError("WINS_AWG_TEST_PRIVATE_KEY is required")

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
Endpoint = <DATA_SIM_IP>:9110
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(m + "\n")

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout,
                           cwd=D)
        return (r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))
    except Exception as e:
        return (-1, "", str(e))

with open(LOG, "w", encoding="utf-8") as f:
    f.write("engine probe start\n")

with open(CONF, "w", encoding="utf-8") as f:
    f.write(CONFIG)

code, out, err = run('awg.exe down winsvpn 2>nul & taskkill /F /IM winsvpn_awg_engine.exe 2>nul & ping -n 2 127.0.0.1 >nul')
log("cleanup: %s" % (out + err).strip()[:200])

eng = subprocess.Popen([os.path.join(D, "winsvpn_awg_engine.exe")],
                       cwd=D, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
log("engine spawned pid=%d" % eng.pid)
time.sleep(3)
code, out, err = run("awg.exe show")
log("awg show before setconf rc=%d out=%s err=%s" % (code, out.strip()[:300], err.strip()[:200]))

code, out, err = run("awg.exe setconf winsvpn %s" % CONF)
log("setconf rc=%d out=%s err=%s" % (code, out.strip()[:300], err.strip()[:300]))

time.sleep(2)
code, out, err = run("awg.exe show winsvpn")
log("awg show winsvpn rc=%d:\n%s\nerr=%s" % (code, out.strip(), err.strip()[:200]))

for i in range(12):
    time.sleep(2)
    code, out, err = run("awg.exe show winsvpn transfer")
    log("t=%ds transfer: %s" % (i * 2, (out or err).strip()[:200]))

code, out, err = run("awg.exe show winsvpn")
log("final show:\n%s" % out.strip())

run("awg.exe down winsvpn")
eng.terminate()
try:
    out2 = eng.communicate(timeout=3)[1]
    log("engine stderr: %s" % out2.decode("utf-8", "replace")[:400])
except Exception:
    eng.kill()
log("engine probe end")
