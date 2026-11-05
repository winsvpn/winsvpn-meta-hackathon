"""TB-09 variant 9's harness proxy between the docker client and dockerd's socket (design v17 5.3, v14 fix 4).

usage: s7_docker_proxy.py LISTEN_SOCKET TRIGGER_FILE DELAY_SECONDS LOG

Every request is relayed to /var/run/docker.sock at once, except a container `restart` POST: the proxy accepts it,
logs `accepted`, and forwards it to dockerd DELAY_SECONDS after TRIGGER_FILE appears (the harness creates it at the
handler's last-stop hook), whether or not the client is still connected. It logs `forwarded` and `completed`, with
epoch times, so the run can tell acceptance from the later synthetic dispatch. The proxy runs outside the activation
scope (it is started by the harness, not by the gated child) and holds no fd 6.
"""
import os
import re
import socket
import sys
import threading
import time

DOCKER = "/var/run/docker.sock"
RESTART = re.compile(rb"^POST \S*/containers/[^/\s]+/restart\b")


def log(path, text):
    with open(path, "a") as stream:
        stream.write("%s %.3f\n" % (text, time.time()))


def read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    match = re.search(rb"(?im)^content-length:\s*(\d+)", head)
    want = int(match.group(1)) if match else 0
    while len(body) < want:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def relay(request, client, logpath, name):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.connect(DOCKER)
    upstream.sendall(request)
    upstream.shutdown(socket.SHUT_WR)
    answer = b""
    while True:
        chunk = upstream.recv(65536)
        if not chunk:
            break
        answer += chunk
        try:
            client.sendall(chunk)
        except OSError:
            pass
    upstream.close()
    status = answer.split(b"\r\n", 1)[0].decode(errors="replace")
    log(logpath, "completed %s %s" % (name, status.replace(" ", "_")))


def handle(client, trigger, delay, logpath):
    try:
        request = read_request(client)
        first = request.split(b"\r\n", 1)[0]
        name = first.decode(errors="replace").replace(" ", "_")[:120]
        if RESTART.match(first):
            log(logpath, "accepted POST %s" % name)
            while not os.path.exists(trigger):
                time.sleep(0.05)
            time.sleep(delay)
            log(logpath, "forwarded %s" % name)
        relay(request, client, logpath, name)
    except OSError as exc:
        log(logpath, "error %s" % exc)
    finally:
        try:
            client.close()
        except OSError:
            pass


def main(argv):
    listen, trigger, delay, logpath = argv[1], argv[2], float(argv[3]), argv[4]
    if os.path.exists(listen):
        os.unlink(listen)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(listen)
    os.chmod(listen, 0o600)
    server.listen(16)
    log(logpath, "listening %s" % listen)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client, trigger, delay, logpath), daemon=True).start()


if __name__ == "__main__":
    main(sys.argv)
