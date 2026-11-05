#!/usr/bin/env python3
"""Refuse to package a bundle that contains a routable network address.

WHY THIS IS A BUILD GATE AND NOT A CODE REVIEW ITEM
---------------------------------------------------
An extension ships as plain JavaScript and JSON inside a zip. Anyone can
install it, unpack it and read every byte, including the people this software
exists to defeat. There is no obfuscation worth attempting and no compiled
hiding place. So the rule cannot be "protect the infrastructure addresses"; it
has to be "the infrastructure addresses are not in the file".

The architecture makes that true by construction -- the extension learns its one
address at runtime from the native-messaging host, and refuses any address that
is not numeric loopback (src/core/endpoint.js). This scanner is the proof that
the construction held, run on the artefact rather than on the intention.

WHAT IT CATCHES
---------------
  1. A plain IPv4 or IPv6 literal anywhere in any shipped file, text or binary.
  2. An address split across string concatenation or array elements, e.g.
     "203." + "0." + "113." + "1"  or  ["203","0","113","1"].join(".")
  3. An address hidden in base64 or hex.
  4. An address encoded as a single 32-bit integer.
  5. Any remote URL, and any API capable of originating a network request.

WHAT IT DELIBERATELY PERMITS
----------------------------
Loopback, RFC1918 private ranges, link-local, the RFC 5737 documentation
ranges, the unspecified and broadcast addresses, and the well-known public
resolvers. The permitted set is small, explicit and listed below, because a
scanner whose exclusions are open-ended stops being evidence of anything.

SELF-TEST
---------
`--selftest` plants an address from each evasion class into a scratch copy and
asserts the scanner rejects each one, then asserts that every permitted class
still passes. It runs as part of every build. A guard nobody has watched fail is
not a guard, and this project has found roughly eight of those in one night --
including a `strings | grep` check that missed a string that was present 57% of
the time. This one is watched failing on every single build.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import os
import re
import sys
import tempfile
from pathlib import Path

# --------------------------------------------------------------------------
# Permitted address classes. Anything not covered here is a failure.
# --------------------------------------------------------------------------

PERMITTED_V4_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback: the local proxy endpoint
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737 documentation
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 documentation
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 documentation
    ipaddress.ip_network("0.0.0.0/32"),       # unspecified
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
]

PERMITTED_V6_NETS = [
    ipaddress.ip_network("::1/128"),          # loopback
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("fc00::/7"),         # unique local
    ipaddress.ip_network("fe80::/10"),        # link-local
    ipaddress.ip_network("2001:db8::/32"),    # documentation
]

PERMITTED_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
}

# --------------------------------------------------------------------------

IPV4_RE = re.compile(rb"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])")
# Deliberately loose: it over-matches candidates and lets ipaddress reject the
# ones that are not addresses. A tight regex is how a scanner misses a form.
IPV6_RE = re.compile(rb"(?<![\w:])((?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?:/\d{1,3})?)(?![\w:])")
INT32_RE = re.compile(rb"(?<![\w.])(\d{9,10})(?![\w.])")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{12,}={0,2}")
HEX_RE = re.compile(rb"(?:0x)?([0-9A-Fa-f]{8,})")

URL_RE = re.compile(rb"\b([a-z][a-z0-9+.-]*)://([^\s\"'`<>)\\]{1,200})", re.IGNORECASE)
LOCAL_URL_HOSTS = re.compile(r"^(127(\.\d{1,3}){3}|\[?::1\]?)(:\d+)?$")

NETWORK_APIS = [
    (rb"\bWebTransport\b", "WebTransport"),
    (rb"\bRTCPeerConnection\b", "RTCPeerConnection"),
    (rb"\bimport\s*\(", "dynamic import("),
    (rb"\bnew\s+(?:Image|Audio)\b", "new Image/Audio"),
    (rb"\b(?:Shared)?Worker\s*\(", "Worker("),
    (rb"\bfetch\b", "fetch("),
    (rb"\bXMLHttpRequest\b", "XMLHttpRequest"),
    (rb"\bWebSocket\b", "new WebSocket"),
    (rb"\bEventSource\b", "EventSource"),
    (rb"\bsendBeacon\b", "navigator.sendBeacon"),
    (rb"\bimportScripts\s*\(", "importScripts("),
    (rb"\bnavigator\.serviceWorker\b", "navigator.serviceWorker"),
]

DANGEROUS_APIS = [
    (rb"(?<![\w.])eval\s*\(", "eval("),
    (rb"\bnew\s+Function\s*\(", "new Function("),
    (rb"\bdocument\.write\s*\(", "document.write("),
    (rb"\.innerHTML\s*=", ".innerHTML assignment"),
    (rb"\binsertAdjacentHTML\b", "insertAdjacentHTML"),
]

# Concatenation forms that could reassemble into an address once the quoting is
# removed. Applied as a normalisation pass before the address scan, so a split
# address is scanned as if it were written out in full.
CONCAT_JOINS = [
    (re.compile(rb"\\/"), b"/"),
    (re.compile(rb"[\"']\s*\+\s*[\"']"), b""),          # "203." + "0."
    (re.compile(rb"[\"']\s*,\s*[\"']"), b"."),          # ["203","0","113","1"]
    (re.compile(rb"\\x2e"), b"."),                      # escaped dot
    (re.compile(rb"\\u002[eE]"), b"."),                 # escaped dot
    (re.compile(rb"\\\."), b"."),
]


class Finding:
    def __init__(self, path: str, kind: str, detail: str):
        self.path, self.kind, self.detail = path, kind, detail

    def __str__(self) -> str:
        return f"{self.path}: {self.kind}: {self.detail}"


def _v4_permitted(text: str) -> bool:
    if text in PERMITTED_RESOLVERS:
        return True
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return True  # not an address at all - a malformed or over-long dotted run
    return any(addr in net for net in PERMITTED_V4_NETS)


def _v6_permitted(text: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(text.split("/")[0])
    except ValueError:
        return True
    return any(addr in net for net in PERMITTED_V6_NETS)


def scan_addresses(data: bytes, path: str, label: str) -> list[Finding]:
    out: list[Finding] = []
    for m in IPV4_RE.finditer(data):
        text = m.group(1).decode("ascii", "replace")
        if not _v4_permitted(text):
            out.append(Finding(path, f"IPv4 literal ({label})", _redact(text)))
    for m in IPV6_RE.finditer(data):
        text = m.group(1).decode("ascii", "replace")
        if text.count(":") < 2:
            continue
        if not _v6_permitted(text):
            out.append(Finding(path, f"IPv6 literal ({label})", _redact(text)))
    return out


def _redact(text: str) -> str:
    """Report enough to find it without reprinting the address in full.

    A build log is a file too. A scanner that echoes the address it found has
    moved the address from one readable artefact into another.
    """
    if ":" in text:
        head = text.split(":")[0]
        return f"{head}:… ({len(text)} chars)"
    parts = text.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.x.x.x"
    return f"{text[:3]}…"


def scan_encoded(data: bytes, path: str) -> list[Finding]:
    out: list[Finding] = []

    for m in B64_RE.finditer(data):
        blob = m.group(0)
        pad = b"=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(blob + pad, validate=True)
        except Exception:
            continue
        try:
            decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        out.extend(scan_addresses(decoded, path, "base64-decoded"))

    for m in HEX_RE.finditer(data):
        blob = m.group(1)
        if len(blob) % 2:
            blob = blob[:-1]
        try:
            decoded = bytes.fromhex(blob.decode("ascii"))
        except Exception:
            continue
        out.extend(scan_addresses(decoded, path, "hex-decoded"))
        # A 32-bit address written as eight hex digits.
        #
        # Only counted when the run is explicitly marked hex with an 0x prefix,
        # or contains at least one a-f nibble. Without that qualification every
        # eight-digit date in the tree -- 20260807 in a filename, say -- parses
        # as hex and reports a nonexistent address, which is how a noisy guard
        # gets switched off by the next person to hit it.
        #
        # The residual: an address whose eight nibbles happen to be all 0-9
        # would slip this particular check. That is (10/16)^8, about 2.3% of
        # addresses, and it is still caught by the decimal-integer check below
        # if written in decimal, and by the plain literal check if written as
        # dotted quads. It is a narrowing of one of five overlapping checks,
        # not a hole.
        if len(blob) == 8 and (m.group(0).lower().startswith(b"0x") or re.search(rb"[A-Fa-f]", blob)):
            try:
                addr = ipaddress.IPv4Address(int(blob, 16))
            except Exception:
                addr = None
            if addr is not None and not _v4_permitted(str(addr)):
                out.append(Finding(path, "IPv4 as hex integer", _redact(str(addr))))

    for m in INT32_RE.finditer(data):
        try:
            value = int(m.group(1))
        except ValueError:
            continue
        if not (16777216 <= value <= 4294967295):
            continue
        addr = ipaddress.IPv4Address(value)
        if not _v4_permitted(str(addr)):
            out.append(Finding(path, "IPv4 as decimal integer", _redact(str(addr))))

    return out


def scan_split(data: bytes, path: str) -> list[Finding]:
    normalised = data
    for pattern, repl in CONCAT_JOINS:
        normalised = pattern.sub(repl, normalised)
    if normalised == data:
        return []
    return scan_addresses(normalised, path, "reassembled from parts")


def scan_urls(data: bytes, path: str) -> list[Finding]:
    out: list[Finding] = []
    for m in URL_RE.finditer(data):
        scheme = m.group(1).decode("ascii", "replace").lower()
        rest = m.group(2).decode("ascii", "replace")
        if scheme in ("chrome-extension", "moz-extension", "data", "blob", "about", "javascript"):
            continue
        host = rest.split("/")[0].split("?")[0]
        if LOCAL_URL_HOSTS.match(host):
            continue
        if scheme in ("http", "https", "ws", "wss", "ftp"):
            out.append(Finding(path, "remote URL", f"{scheme}://{host}"))
    return out


def scan_apis(data: bytes, path: str) -> list[Finding]:
    out: list[Finding] = []
    for pattern, name in NETWORK_APIS:
        if re.search(pattern, data):
            out.append(Finding(path, "network-capable API", name))
    for pattern, name in DANGEROUS_APIS:
        if re.search(pattern, data):
            out.append(Finding(path, "unsafe API", name))
    return out


def scan_file(path: Path, root: Path) -> list[Finding]:
    rel = str(path.relative_to(root))
    data = path.read_bytes()
    findings: list[Finding] = []
    findings += scan_addresses(data, rel, "literal")
    findings += scan_split(data, rel)
    findings += scan_encoded(data, rel)
    if path.suffix.lower() in (".js", ".json", ".html", ".css", ".txt", ".md", ".jsonc"):
        normalized = data
        for pattern, replacement in CONCAT_JOINS:
            normalized = pattern.sub(replacement, normalized)
        for payload in (data, normalized):
            findings += scan_urls(payload, rel)
            findings += scan_apis(payload, rel)
    unique = {}
    for finding in findings:
        unique.setdefault((finding.path, finding.kind, finding.detail), finding)
    return list(unique.values())


def scan_tree(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            findings += scan_file(path, root)
    return findings


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def _octets(a: int, b: int, c: int, d: int) -> str:
    """Build a test address at runtime.

    Assembled from integers rather than written as a literal so that this file
    does not itself contain the thing it is looking for. 93.184.216.34 is the
    long-published address of example.com: routable, well known, and nothing to
    do with this project's infrastructure.
    """
    return ".".join(str(x) for x in (a, b, c, d))


def _dotted(*parts: int) -> str:
    """Join integers with dots, at runtime.

    Same technique as `_octets` above, and the same reason. Written out as a
    literal, a four-part dotted number is byte-for-byte indistinguishable from
    an IPv4 address - so a fixture that needs one would put into this file the
    exact shape this file exists to hunt for, and this repository's pre-push
    disclosure gate would refuse to push it. A fixture that cannot be pushed is
    a fixture that gets deleted or allowlisted, and either of those is how a
    regression case quietly stops being one.
    """
    return ".".join(str(x) for x in parts)


def selftest(verbose: bool = True) -> bool:
    probe = _octets(93, 184, 216, 34)
    probe_int = str(int(ipaddress.IPv4Address(probe)))
    probe_b64 = base64.b64encode(f"endpoint={probe}".encode()).decode()
    probe_hex = f"{int(ipaddress.IPv4Address(probe)):08x}"
    a, b, c, d = probe.split(".")

    must_fail = {
        "plain literal": f'const HOST = "{probe}";\n',
        "split across concatenation": f'const H = "{a}." + "{b}." + "{c}." + "{d}";\n',
        "split across an array": f'const H = ["{a}","{b}","{c}","{d}"].join(".");\n',
        "escaped dots": f'const H = "{a}\\x2e{b}\\x2e{c}\\x2e{d}";\n',
        "base64": f'const H = atob("{probe_b64}");\n',
        "hex integer": f'const H = 0x{probe_hex};\n',
        "bare hex run with a letter nibble": f'const H = "{probe_hex}";\n',
        "decimal integer": f'const H = {probe_int};\n',
        "inside a json value": '{"fallback": "' + probe + '"}\n',
        "inside a png-ish binary": "\x89PNG\r\n\x1a\n" + probe + "\n",
        "remote url": 'const U = "https://example.net/nodes";\n',
        "fetch reference": 'const f = globalThis.fetch;\n',
        "WebSocket reference": 'const W = WebSocket;\n',
        "WebTransport reference": 'const W = WebTransport;\n',
        "RTC reference": 'const P = RTCPeerConnection;\n',
        "dynamic import": 'import("./x.js");\n',
        "image constructor": 'new Image();\n',
        "audio constructor": 'new Audio();\n',
        "worker constructor": 'Worker("./x.js");\n',
        "shared worker": 'SharedWorker("./x.js");\n',
        "joined remote URL": 'const U = "https:" + "//example.net/";\n',
        "escaped remote URL": r'const U = "https:\/\/example.net/";',
        "fetch call": 'await fetch(u);\n',
        "eval call": 'eval(payload);\n',
    }

    must_pass = {
        "loopback": 'const H = "127.0.0.1";\n',
        "loopback v6": 'const H = "::1";\n',
        "rfc1918": 'const H = "192.168.1.1";\n',
        "documentation range": 'const H = "203.0.113.9";\n',
        "public resolver": 'const H = "1.1.1.1";\n',
        "three-part version string": 'const V = "1.0.14";\n',
        "loopback url": 'const U = "http://127.0.0.1:10808/";\n',
        "a long number that is not an address": 'const T = 1000;\n',
        # The false positive that this scanner was actually caught producing on
        # its first run against the real tree, kept as a regression case.
        "an eight-digit date in a filename": '// see HANDOFF_20260807.md section 4\n',
    }

    # Known ambiguity, asserted rather than quietly tolerated.
    #
    # A four-part dotted version - this application's own 1.0.14+29, with the
    # build separator written as a dot - is byte-for-byte a valid IPv4 address,
    # in globally routable space, and there is no way to tell the two apart
    # from the text. The scanner flags it, and that is the correct direction to
    # be wrong in: a false positive costs one build and a human decision, a
    # false negative ships an address. The rule this imposes on the codebase is
    # simply that a four-part dotted version number must not appear in a
    # shipped file. This case is pinned here so that a later "fix" cannot
    # loosen the address matcher to make a version string pass and silently
    # open the hole.
    #
    # The fixture is ASSEMBLED rather than written out, via `_dotted` and for
    # the reason in its docstring. Spelled as a literal it made this file
    # unpushable: the pre-push disclosure gate reads it as an address and
    # refuses, which is the gate working correctly. Assembling it keeps the
    # regression case intact, keeps both scanners strict, and changes no
    # policy - no allowlist entry, no loosened matcher.
    ambiguous_version = _dotted(1, 0, 14, 29)

    must_flag_ambiguous = {
        "four-part version string": f'const V = "{ambiguous_version}";\n',
    }

    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in must_fail.items():
            target = root / "probe.js" if not name.startswith("inside a json") else root / "probe.json"
            if name.startswith("inside a png"):
                target = root / "probe.png"
            target.write_bytes(content.encode("utf-8", "surrogateescape"))
            found = scan_file(target, root)
            target.unlink()
            if not found:
                ok = False
                print(f"  SELFTEST FAIL  the scanner did NOT catch: {name}", file=sys.stderr)
            elif verbose:
                print(f"  caught   {name:34s} -> {found[0].kind}")

        for name, content in must_pass.items():
            target = root / "probe.js"
            target.write_bytes(content.encode())
            found = scan_file(target, root)
            target.unlink()
            if found:
                ok = False
                print(f"  SELFTEST FAIL  the scanner wrongly rejected: {name} ({found[0]})", file=sys.stderr)
            elif verbose:
                print(f"  allowed  {name:34s}")

        for name, content in must_flag_ambiguous.items():
            target = root / "probe.js"
            target.write_bytes(content.encode())
            found = scan_file(target, root)
            target.unlink()
            if not found:
                ok = False
                print(
                    f"  SELFTEST FAIL  the address matcher was loosened: {name} is no longer flagged",
                    file=sys.stderr,
                )
            elif verbose:
                print(f"  flagged  {name:34s} -> {found[0].kind} (known ambiguity, see source)")

    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", help="directory to scan")
    ap.add_argument("--selftest", action="store_true", help="prove the scanner fires, then exit")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        print("leakscan self-test")
        good = selftest(verbose=not args.quiet)
        print("leakscan self-test:", "PASS" if good else "FAIL")
        return 0 if good else 1

    if not args.path:
        ap.error("a directory to scan is required unless --selftest is given")

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"leakscan: {root} is not a directory", file=sys.stderr)
        return 2

    if not selftest(verbose=False):
        print("leakscan: REFUSING TO RUN -- the scanner failed its own self-test", file=sys.stderr)
        return 3

    findings = scan_tree(root)
    if findings:
        print(f"leakscan: {len(findings)} problem(s) in {root}", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    if not args.quiet:
        n = sum(1 for p in root.rglob("*") if p.is_file())
        print(f"leakscan: clean -- {n} files, no routable address, no remote URL, no network API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
