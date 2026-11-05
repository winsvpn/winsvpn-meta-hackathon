import socket, traceback
LOG = r"C:\fleet\lb_test2.log"
def log(m):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(m + "\n")
with open(LOG, "w") as f:
    f.write("start\n")
try:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    p = srv.getsockname()[1]
    srv.listen(1)
    log("tcp bound 127.0.0.1:%d" % p)
    srv.settimeout(5)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.settimeout(5)
    try:
        cli.connect(("127.0.0.1", p))
        log("tcp connect OK")
    except Exception as e:
        log("tcp connect FAIL: %r %s" % (e, traceback.format_exc()[:300]))
    try:
        srv.listen(1)
        c, a = srv.accept()
        log("tcp accept OK from %s" % (a,))
        c.close()
    except Exception as e:
        log("tcp accept FAIL: %r %s" % (e, traceback.format_exc()[:300]))
    cli.close(); srv.close()
except Exception as e:
    log("outer FAIL: %r %s" % (e, traceback.format_exc()[:400]))
log("end")
