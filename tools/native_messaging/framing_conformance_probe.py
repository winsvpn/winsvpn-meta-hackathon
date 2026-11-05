#!/usr/bin/env python3
"""Independent conformance probe for the Win's VPN native-messaging host.

This deliberately does NOT use the project's Dart codec. It implements the
framing straight from the Chrome/Firefox specification -- 4-byte length prefix
in native byte order, then UTF-8 JSON -- and speaks it to the compiled host
exactly as a browser would. Testing the Dart encoder with the Dart decoder only
proves self-consistency; this proves conformance.

Usage:
    python3 framing_conformance_probe.py <path-to-host-executable>

Exit status is 0 only if every case passes. No credential is printed: the probe
redacts any token field before showing a payload.
"""

import json
import struct
import subprocess
import sys


def frame(obj):
    """Encode as the browser does."""
    body = json.dumps(obj).encode("utf-8")
    # '<I' is explicit little-endian, which is what the browsers' "native byte
    # order" means on every platform this app targets. Using '=I' (native)
    # here would hide an endianness bug on a big-endian host rather than
    # exposing it.
    return struct.pack("<I", len(body)) + body


def redact(payload):
    if isinstance(payload, dict) and "token" in payload:
        clone = dict(payload)
        clone["token"] = "<redacted:%d chars>" % len(str(payload["token"]))
        return clone
    return payload


def read_frame(stream):
    header = stream.read(4)
    if len(header) < 4:
        return None, "host closed before sending a length prefix"
    (length,) = struct.unpack("<I", header)
    if length == 0 or length > 1024 * 1024:
        return None, "implausible declared length %d" % length
    body = stream.read(length)
    if len(body) < length:
        return None, "short body: declared %d, got %d" % (length, len(body))
    return json.loads(body.decode("utf-8")), header.hex(" ")


def main():
    if len(sys.argv) < 2:
        print("usage: framing_conformance_probe.py <host-executable>")
        return 2
    host = sys.argv[1]

    # Cases are sent as ONE write, back to back, so the host must also prove it
    # can split several frames out of a single read.
    requests = [
        {"v": 1, "id": "probe1", "type": "hello"},
        {"v": 1, "id": "probe2", "type": "get_status"},
        {"v": 1, "id": "probe3", "type": "issue_proxy_credential"},
        # Burmese round-trip: the length must be the UTF-8 BYTE count.
        {"v": 1, "id": "probe4", "type": "get_status", "note": "ချိတ်ဆက်ပြီး"},
        # Unknown request: must be answered, not ignored.
        {"v": 1, "id": "probe5", "type": "definitely_not_a_request"},
        # Wrong protocol version: must be refused.
        {"v": 99, "id": "probe6", "type": "hello"},
    ]

    blob = b"".join(frame(r) for r in requests)
    print("wrote %d frames as one %d-byte write" % (len(requests), len(blob)))
    print("first prefix bytes: %s  (little-endian %d)"
          % (blob[:4].hex(" "), struct.unpack("<I", blob[:4])[0]))

    proc = subprocess.Popen(
        [host],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.stdin.write(blob)
    proc.stdin.flush()

    failures = []
    seen = []
    for expected_id in ["probe1", "probe2", "probe3", "probe4", "probe5", "probe6"]:
        payload, note = read_frame(proc.stdout)
        if payload is None:
            failures.append("%s: %s" % (expected_id, note))
            break
        seen.append(payload)
        print("\n<- prefix %s  %s" % (note, json.dumps(redact(payload))[:220]))
        if payload.get("id") != expected_id:
            failures.append(
                "expected id %s, got %s" % (expected_id, payload.get("id")))

    proc.stdin.close()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        failures.append("host did not exit when stdin closed")

    # Assertions about content, not just framing.
    if len(seen) >= 1:
        hello = seen[0]
        if hello.get("type") != "hello":
            failures.append("first reply was not a hello")
        # The v1 snapshot is deliberately flat. A nested {"status": {...}}
        # reply is incompatible with the extension parser and must not be
        # normalized away by this independent probe.
        if hello.get("winn") != "unavailable_on_this_platform":
            failures.append(
                "winn state on this platform should be "
                "unavailable_on_this_platform, got %r" % hello.get("winn"))
        if hello.get("status") != "app_not_running":
            failures.append(
                "expected app_not_running, got %r" % hello.get("status"))
    if len(seen) >= 3:
        credential = seen[2]
        if credential.get("error") != "app_not_running":
            failures.append(
                "production host issued or misclassified a proxy credential "
                "while the desktop app was absent")
        if "token" in credential or "proxyPort" in credential:
            failures.append(
                "credential refusal leaked a token or proxy port while the app was absent")
    if len(seen) >= 5 and seen[4].get("error") != "unknown_request":
        failures.append("unknown request was not refused as unknown_request")
    if len(seen) >= 6 and seen[5].get("error") != "unsupported_version":
        failures.append("wrong version was not refused as unsupported_version")

    # No message may carry an address.
    flat = json.dumps(seen)
    import re
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", flat):
        failures.append("an IPv4 literal appeared in a reply")

    print("\n" + "=" * 60)
    if failures:
        for f in failures:
            print("FAIL: %s" % f)
        return 1
    print("PASS: %d framed replies, prefixes little-endian, "
          "UTF-8 byte lengths, no address in any reply" % len(seen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
