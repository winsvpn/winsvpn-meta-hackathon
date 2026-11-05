"""Tier A fixture probe, run inside the client namespace.

For each port it tries a TCP connect and a UDP round trip to the node and prints
`tcp:<port>=answered|refused|silent udp:<port>=...`. `answered` means a service accepted the
connection or echoed. `refused` is an RST or ICMP unreachable: the node's kernel replied but no service
did. `silent` is a drop. Network-level darkness needs silence, service-level darkness only needs
that nothing answered.
"""
import socket
import sys
import threading

host = sys.argv[1]
ports = [int(p) for p in sys.argv[2:]]
results = {}


def tcp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        sock.connect((host, port))
        results["tcp:%d" % port] = "answered"
    except socket.timeout:
        results["tcp:%d" % port] = "silent"
    except OSError:
        results["tcp:%d" % port] = "refused"
    finally:
        sock.close()


def udp(port):
    # A connected UDP socket receives the ICMP port-unreachable as ECONNREFUSED; an unconnected one never sees it,
    # which would read a kernel refusal as silence.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    try:
        sock.connect((host, port))
        sock.send(b"probe")
        sock.recv(2048)
        results["udp:%d" % port] = "answered"
    except socket.timeout:
        results["udp:%d" % port] = "silent"
    except OSError:
        results["udp:%d" % port] = "refused"
    finally:
        sock.close()


threads = [threading.Thread(target=fn, args=(p,)) for p in ports for fn in (tcp, udp)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(" ".join("%s=%s" % (k, results[k]) for k in sorted(results)))
