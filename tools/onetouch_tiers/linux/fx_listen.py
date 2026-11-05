"""Tier A fixture listener: TCP accept and UDP echo on the given ports, on all addresses."""
import select
import socket
import sys

ports = [int(p) for p in sys.argv[1:]]
sockets = []
for port in ports:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", port))
    tcp.listen(16)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", port))
    sockets += [tcp, udp]
while True:
    ready, _, _ = select.select(sockets, [], [], 1.0)
    for sock in ready:
        if sock.type == socket.SOCK_STREAM:
            conn, _ = sock.accept()
            conn.close()
        else:
            data, peer = sock.recvfrom(2048)
            sock.sendto(b"echo:" + data, peer)
