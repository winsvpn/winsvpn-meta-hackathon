"""A minimal Chrome DevTools Protocol client, standard library only.

Written rather than pulled from a package registry for the same reason the rest
of this build has no dependencies: the thing being verified is a
censorship-circumvention tool, and a verification harness that installs
packages is a verification harness that can be told what to conclude.

The historical path is about a hundred lines of RFC 6455 -- an HTTP upgrade, a
masked client frame, and an unmasked server frame -- plus a command/response
loop. Authenticated browser runtime execution uses ``--remote-debugging-pipe``
instead: JSON messages delimited by a NUL byte on inherited file descriptors 3
(commands Chrome reads) and 4 (replies Chrome writes). That pipe is created by
the parent and tied to the spawned process; an arbitrary loopback claimant
cannot satisfy it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import socket
import struct
import threading
import time
import urllib.request


CHROME_PIPE_READ_FD = 3
CHROME_PIPE_WRITE_FD = 4
_PIPE_PRODUCER_TOKEN = object()


class WebSocket:
    def __init__(self, url: str, timeout: float = 20.0):
        if not url.startswith("ws://"):
            raise ValueError(f"only ws:// is supported, got {url[:24]}")
        rest = url[len("ws://") :]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {hostport}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("the debugging endpoint closed during the handshake")
            buf += chunk
        head, _, remainder = buf.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise ConnectionError(f"upgrade refused: {head.splitlines()[0]!r}")

        # The RFC 6455 accept value is computed and compared, but a mismatch is
        # recorded rather than fatal. Chrome 151's embedded DevTools server
        # answers with the pre-RFC status line "101 WebSocket Protocol
        # Handshake" and an accept value that does not match
        # base64(sha1(key + GUID)) for any casing or padding of the key that was
        # tried. Rather than guess at what it is computing, the check is
        # downgraded: this endpoint is on loopback, was started by this harness
        # a moment ago, and the accept value defends against cache poisoning by
        # an intermediary, of which there is none. Saying "verified" here would
        # be the same species of overclaim the extension itself is built to
        # avoid, so it says what it actually knows.
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-5AB0DC85B11C").encode()).digest()
        ).decode()
        self.accept_verified = expected.encode() in head
        self._buf = remainder
        self._lock = threading.Lock()

    @property
    def timeout(self) -> float | None:
        return self.sock.gettimeout()

    @timeout.setter
    def timeout(self, value: float | None) -> None:
        self.sock.settimeout(value)

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("the debugging endpoint closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._lock:
            self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        while True:
            b0, b1 = self._recv_exact(2)
            opcode = b0 & 0x0F
            length = b1 & 0x7F
            if length == 126:
                (length,) = struct.unpack(">H", self._recv_exact(2))
            elif length == 127:
                (length,) = struct.unpack(">Q", self._recv_exact(8))
            if b1 & 0x80:
                mask = self._recv_exact(4)
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(self._recv_exact(length)))
            else:
                data = self._recv_exact(length)
            if opcode == 0x9:  # ping
                with self._lock:
                    self.sock.sendall(bytes([0x8A, 0x80]) + b"\x00\x00\x00\x00")
                continue
            if opcode == 0x8:
                raise ConnectionError("the debugging endpoint sent a close frame")
            if opcode in (0x1, 0x0):
                return data.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class PipeTransport:
    """CDP over Chrome ``--remote-debugging-pipe`` file descriptors."""

    def __init__(
        self,
        read_fd: int,
        write_fd: int,
        timeout: float = 20.0,
        *,
        producer: object | None = None,
    ):
        if producer is not _PIPE_PRODUCER_TOKEN:
            raise TypeError("debugging pipe must be produced by authenticated spawn")
        if read_fd < 0 or write_fd < 0 or read_fd == write_fd:
            raise ValueError("debugging pipe requires two distinct inherited file descriptors")
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._producer = producer
        self.timeout = timeout
        self._buf = b""
        self._lock = threading.Lock()
        self.sock = self

    def settimeout(self, value: float | None) -> None:
        self.timeout = 0.4 if value is None else value

    def send(self, text: str) -> None:
        payload = text.encode("utf-8") + b"\x00"
        with self._lock:
            view = memoryview(payload)
            while view:
                written = os.write(self._write_fd, view)
                if written <= 0:
                    raise ConnectionError("the debugging pipe rejected a command")
                view = view[written:]

    def recv(self) -> str:
        deadline = time.time() + float(self.timeout or 0)
        while True:
            nul = self._buf.find(b"\x00")
            if nul >= 0:
                message, self._buf = self._buf[:nul], self._buf[nul + 1 :]
                return message.decode("utf-8", "replace")
            remaining = None if not self.timeout else max(0.0, deadline - time.time())
            if remaining == 0:
                raise TimeoutError("the debugging pipe did not answer")
            ready, _, _ = select.select([self._read_fd], [], [], remaining)
            if not ready:
                raise TimeoutError("the debugging pipe did not answer")
            chunk = os.read(self._read_fd, 65536)
            if not chunk:
                raise ConnectionError("the debugging pipe closed")
            self._buf += chunk

    def close(self) -> None:
        for fd in (self._read_fd, self._write_fd):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
        self._read_fd = -1
        self._write_fd = -1


def produce_pipe_transport(read_fd: int, write_fd: int, timeout: float = 20.0) -> PipeTransport:
    return PipeTransport(read_fd, write_fd, timeout, producer=_PIPE_PRODUCER_TOKEN)


class Connection:
    """One CDP command stream: a WebSocket or a debugging pipe."""

    def __init__(self, transport: WebSocket | PipeTransport):
        self.transport = transport
        self._id = 0
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float = 25.0,
        session_id: str | None = None,
    ):
        with self._lock:
            self._id += 1
            mid = self._id
        message = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            message["sessionId"] = session_id
        self.transport.send(json.dumps(message, separators=(",", ":")))
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.05, deadline - time.time())
            self.transport.timeout = remaining
            received = json.loads(self.transport.recv())
            if received.get("id") == mid:
                if session_id and received.get("sessionId") not in (None, session_id):
                    self.events.append(received)
                    continue
                if "error" in received:
                    raise RuntimeError(f"{method}: {received['error']}")
                return received.get("result", {})
            if "method" in received:
                self.events.append(received)
        raise TimeoutError(f"{method} did not answer within {timeout}s")


class Target:
    """One attached CDP target: a page, or an extension service worker."""

    def __init__(
        self,
        ws_url: str | None = None,
        *,
        connection: Connection | None = None,
        session_id: str | None = None,
        transport: WebSocket | PipeTransport | None = None,
    ):
        if connection is not None:
            self._connection = connection
            self.ws = connection.transport
        elif transport is not None:
            self._connection = Connection(transport)
            self.ws = transport
        else:
            if not ws_url:
                raise ValueError("Target requires a websocket URL or an existing connection")
            self.ws = WebSocket(ws_url)
            self._connection = Connection(self.ws)
        self.session_id = session_id
        self._id = 0
        self.events = self._connection.events

    def call(self, method: str, params: dict | None = None, timeout: float = 25.0):
        return self._connection.call(
            method, params, timeout=timeout, session_id=self.session_id
        )

    def pump(self, seconds: float) -> None:
        """Collect events for a while without issuing a command."""
        end = time.time() + seconds
        previous = self.ws.timeout
        self.ws.timeout = 0.4
        try:
            while time.time() < end:
                try:
                    message = json.loads(self.ws.recv())
                except (socket.timeout, TimeoutError):
                    continue
                if "method" in message:
                    self.events.append(message)
        finally:
            self.ws.timeout = previous

    def take_events(self, method: str) -> list[dict]:
        return [e["params"] for e in self.events if e.get("method") == method]

    def clear_events(self) -> None:
        self.events.clear()

    def evaluate(self, expression: str, await_promise: bool = True, timeout: float = 25.0):
        result = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": await_promise,
                "returnByValue": True,
                "userGesture": True,
            },
            timeout=timeout,
        )
        if result.get("exceptionDetails"):
            detail = result["exceptionDetails"]
            text = detail.get("exception", {}).get("description") or detail.get("text")
            raise RuntimeError(f"evaluate threw: {text}")
        return result.get("result", {}).get("value")

    def close(self) -> None:
        if self.session_id:
            return
        self.ws.close()


class BrowserSession:
    """Browser-level CDP session owned by ``--remote-debugging-pipe``.

    Loopback TCP DevTools helpers below are not an authenticated transport.
    Authenticated browser runtime execution must use ``PipeTransport``.
    """

    def __init__(self, transport: PipeTransport):
        if type(transport) is not PipeTransport:
            raise TypeError("BrowserSession requires a process-owned debugging pipe")
        if getattr(transport, "_producer", None) is not _PIPE_PRODUCER_TOKEN:
            raise TypeError("BrowserSession requires a process-owned debugging pipe")
        self.connection = Connection(transport)
        self.browser = Target(connection=self.connection)
        self.browser.call("Target.setDiscoverTargets", {"discover": True})
        self.browser.call(
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True},
        )

    def attach(self, target_id: str, timeout: float = 25.0) -> Target:
        result = self.browser.call(
            "Target.attachToTarget",
            {"targetId": target_id, "flatten": True},
            timeout=timeout,
        )
        session_id = result.get("sessionId")
        if not session_id:
            raise RuntimeError("Target.attachToTarget did not return a sessionId")
        return Target(connection=self.connection, session_id=session_id)

    def list_targets(self, timeout: float = 25.0) -> list[dict]:
        return list(self.browser.call("Target.getTargets", timeout=timeout).get("targetInfos") or [])

    def wait_for_target(self, predicate, timeout: float = 25.0) -> Target:
        deadline = time.time() + timeout
        last: list[dict] = []
        while time.time() < deadline:
            last = self.list_targets(timeout=max(1.0, deadline - time.time()))
            for info in last:
                if predicate(info):
                    return self.attach(info["targetId"], timeout=max(1.0, deadline - time.time()))
            time.sleep(0.2)
        raise RuntimeError(f"no matching CDP target: {last!r}")

    def close(self) -> None:
        self.browser.close()


def http_json(port: int, path: str, timeout: float = 10.0):
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - loopback only
        return json.loads(response.read().decode("utf-8"))


def wait_for_endpoint(port: int, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return http_json(port, "/json/version")
        except Exception as e:  # noqa: BLE001 - any failure means "not up yet"
            last = e
            time.sleep(0.3)
    raise TimeoutError(f"no debugging endpoint on {port}: {last}")


def list_targets(port: int) -> list[dict]:
    return http_json(port, "/json/list")


def unpacked_extension_id(path: str) -> str:
    """Chrome's deterministic id for an unpacked extension.

    The id is the first 128 bits of the SHA-256 of the absolute directory path,
    with each hex digit mapped onto a..p. Computing it removes a dependency on
    the target list being populated at the moment we happen to look.
    """
    digest = hashlib.sha256(os.path.abspath(path).encode("utf-8")).hexdigest()
    return "".join(chr(ord("a") + int(c, 16)) for c in digest[:32])
