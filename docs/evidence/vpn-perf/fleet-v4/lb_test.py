import socket, traceback

LOG = r"C:\fleet\lb_test.log"
def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(m + "\n")

with open(LOG, "w") as f:
    f.write("lb test start\n")

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    log("bound 127.0.0.1:%d" % p)
    s.settimeout(3)

    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.sendto(b"hello1", ("127.0.0.1", p))
    log("sent from ephemeral socket")
    try:
        d, a = s.recvfrom(100)
        log("recv1 ok: %r from %s" % (d, a))
    except Exception as e:
        log("recv1 FAIL: %r %s" % (e, traceback.format_exc()[:400]))

    c2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c2.bind(("0.0.0.0", 0))
    c2.sendto(b"hello2", ("127.0.0.1", p))
    log("sent from 0.0.0.0-bound socket %s" % (c2.getsockname(),))
    try:
        d, a = s.recvfrom(100)
        log("recv2 ok: %r from %s" % (d, a))
    except Exception as e:
        log("recv2 FAIL: %r %s" % (e, traceback.format_exc()[:400]))

    # respond back
    s.sendto(b"echo", a)
    log("sent echo to %s" % (a,))
    try:
        d, a2 = c2.recvfrom(100)
        log("echo ok: %r from %s" % (d, a2))
    except Exception as e:
        log("echo FAIL: %r %s" % (e, traceback.format_exc()[:400]))
except Exception as e:
    log("outer FAIL: %r %s" % (e, traceback.format_exc()[:600]))
log("lb test end")
