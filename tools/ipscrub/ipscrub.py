#!/usr/bin/env python3
"""
ipscrub (wins_vpn port) -- refuse to push infrastructure addresses or key
material to `origin`.

Provenance
----------
Ported from `wins/docs` -> `tools/ipscrub/ipscrub.py` (2026-08-06), which was
proven to flag a novel address it had never been told about, to produce zero
false positives across its negative controls, and to fail closed. The IPv4
detector, its suppression rules and its self-test are carried over intact.

What is DIFFERENT here, and why
-------------------------------
1. SCOPE: `wins/docs` has no remote, so its gate scans the whole repository and
   blocks unconditionally. `wins_vpn` HAS a remote, and its already-pushed
   history is saturated with addresses that predate this gate. A whole-history
   gate here would block every push forever and would be switched off within a
   day. So this gate scans exactly the objects the push would NEWLY upload:

       git rev-list --objects <pushed tip> --not <remote's tip> --remotes=<remote>

   That is the disclosure surface and nothing else. History already on the
   remote is out of scope for a *pre-push* control; it is a server-side problem.

2. IPv6: the docs version is IPv4-only. One AAAA record on any node and it goes
   blind. Added, with the same benign-class exclusions.

3. WireGuard key shapes: added. PrivateKey/PresharedKey material BLOCKS.
   Public keys WARN but do not block -- they are public by construction, and
   what makes them disclosive is being tabulated NEXT TO a node address, which
   is the thing this gate already blocks.

4. A third false-positive shape: a bare library version (`libcublas 13.1.1.3`)
   with no `version:` keyword. The docs version would have flagged it. Rule
   added, bounded exactly like the existing ones.

5. The OID rule now also covers the four-component form (`2.5.29.37`), which
   this repository contains and the docs version would have flagged. The root
   arc <= 2 guard is unchanged, so no address with a first octet of 3 or more
   can be suppressed by it.

6. BINARY BLOBS ON EVIDENCE PATHS NOW REFUSE INSTEAD OF SKIPPING (2026-08-07).
   `scan_objects` sniffed every blob and silently `continue`d on any binary --
   which is how three real `.pcap` captures were pushed to GitHub on
   2026-08-03 through a doubled path, passing a gate that never read one byte
   of them. Skipping is not scanning. A binary this tool CANNOT read, sitting
   on a path that is by convention capture output, is now a blocking finding
   that says so. Non-evidence binaries (icons, archives, `.so`) still skip:
   the refusal is scoped to the paths where captures live, so it cannot turn
   into the kind of noise that gets a gate switched off.

7. Three more false-positive shapes, all measured in this repository on
   2026-08-07 and all bounded the same way the earlier four are (see
   `is_oid_map_key`, `UA_PRODUCT_RE`, and `swiftlang` in `LIBVER_KW_RE`):
   bare X.500 OID map keys in Go/JSON literals, the Apple `swiftlang-N.N.N.N`
   toolchain version, and browser user-agent product versions such as
   `HeadlessChrome/150.0.0.0` -- which look exactly like dotted quads because
   Chrome's UA reduction pins the last three components to `0.0.0`.

8. Dashed-quad hostnames (2026-08-22). `a-b-c-d.sslip.io` is an IPv4 address
   wearing a hostname -- sslip.io / nip.io answer DNS for `a-b-c-d.<domain>`
   with `a.b.c.d` -- and the dotted detector cannot see it because the dots
   are dashes. The dashed shape is normalised to dots and run through the
   SAME parser, infrastructure test and allowlist, gated on hostname position
   (see `DASHED_QUAD_RE`), so a bare `1-2-3-4` in prose stays unflagged.

Where this lives
----------------
The tracked, canonical copy is `tools/ipscrub/` -- this file, the allowlist
next to it, `pre-push`, and `install-hooks.sh`. `.git/hooks/` holds an
INSTALLED copy, put there by `sh tools/ipscrub/install-hooks.sh`, because
`.git/hooks/` is not version controlled and a fresh clone therefore has no
gate until someone runs that one command.

Edit the tracked copy. The installed `pre-push` wrapper deliberately prefers
`$ROOT/tools/ipscrub/ipscrub.py` over the copy beside itself, so a `git pull`
that improves the detector or the allowlist takes effect immediately and the
installed copy is only ever a fallback for branches that predate this
directory. Editing the `.git/hooks/` copy helps you once and nobody else ever.

The allowlist is resolved next to whichever scanner is chosen (see
`--allowlist` default, below), never mixed across the two locations: a
scanner and its allowlist are one unit.

Detection policy
----------------
A finding is any IP literal that is globally routable -- NOT private (RFC1918),
loopback, link-local, unspecified, multicast, reserved, RFC6598 shared space or
documentation space -- and not in the allowlist.

Deliberately NOT flagged, because they are not addresses:
  * version quads       `DriverVer = 03/25/2026,1.3.0.0`, `v1.2.3.4`
  * library versions    `libcublas 13.1.1.3`
  * ASN.1 object ids    `Oid.Value -eq '2.5.29.37'`, `2.23.140.1.1`
  * dates / digests / out-of-range octets

Every suppression is COUNTED and listable with --show-suppressed, so a rule can
never quietly hide an address. Each suppression rule is structurally bounded so
it cannot reach a real node address: the version and library rules require no
letters between the keyword and the quad; the OID rule requires a root arc of 2
or less.

Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
import tempfile

# ==========================================================================
# IPv4 detection  (carried over from wins/docs unchanged unless noted)
# ==========================================================================

# A dotted quad with an optional trailing `.port`. The lookbehind refuses to
# start inside a longer numeric run, so a date like `2026.08.06.1` cannot latch
# on. The optional fifth group exists because tcpdump writes endpoints as
# `host.port`, and captures are where node addresses live.
QUAD_RE = re.compile(
    r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d{1,5}))?(?!\.?\d)"
)

# Version-declaration keywords. Enumerated rather than `\w*ver`, because
# `server = <addr>` must NOT be read as a version.
VERSION_KW_RE = re.compile(
    r"(?i)\b(?:driverver|fileversion|productversion|assemblyversion|"
    r"appversion|osversion|version|vers|ver|revision|rev|build)\b\s*[=:]"
)

# NEW (see module docstring, item 4). Software components whose versions are
# written as a bare dotted quad with no `version:` keyword in sight --
# `libcublas 13.1.1.3`. No `=`/`:` is required, so the enumeration is kept
# tight and deliberately EXCLUDES words this project uses next to real
# addresses: node, host, server, gateway, peer, hub, relay, endpoint, exit.
# `swiftlang` added 2026-08-07: `swiftlang-6.3.3.1.3` is how Apple stamps the
# Swift compiler, 47 occurrences in this tree. `clang` was already here and
# suppressed its sibling `clang-2100.1.1.101`; `swiftlang` contains no `clang`
# substring, so the word boundary never matched and the toolchain version was
# flagged as an address. Bounded identically to every other entry: a line like
# `swiftlang toolchain on <addr>` has LETTERS between the keyword and the quad
# and stays flagged.
LIBVER_KW_RE = re.compile(
    r"(?i)\b(?:lib[a-z][a-z0-9_+-]*|cuda|cudart|cudnn|cublas|cufft|curand|"
    r"cusparse|nccl|tensorrt|nvcc|nvidia|glibc|musl|openssl|boringssl|zlib|"
    r"ffmpeg|llvm|clang|swiftlang|gcc|msvc|dotnet|jdk|jre|gradle|kotlin|"
    r"flutter|dart|python|npm|pnpm|yarn|golang|rustc|cargo|sqlite|ollama|"
    r"toolkit|sdk|firmware|bios|kernel|patchlevel|schema)\b"
)
LETTER_RE = re.compile(r"[A-Za-z]")

# Browser user-agent product versions (NEW 2026-08-07). `HeadlessChrome/150.0.0.0`
# appears 15 times in the harness's `webrtc.json` captures and is a dotted quad
# by accident: Chrome's User-Agent Reduction freezes MINOR.BUILD.PATCH at
# `0.0.0`, leaving `<major>.0.0.0`, which is a perfectly routable-looking
# address.
#
# The trailing `/` is the whole bound, and it is a good one: every UA product
# token carries it (`Chrome/`, `Safari/`, `AppleWebKit/`) and prose sitting
# next to a node address never does. `the Chrome box at <addr>` stays flagged,
# because there is no slash immediately before the quad.
UA_PRODUCT_RE = re.compile(
    r"(?i)\b(?:headlesschrome|chromium|chrome|crios|firefox|fxios|safari|"
    r"applewebkit|webkit|gecko|mozilla|edge|edg|edga|edgios|opr|opera|"
    r"electron|okhttp|curl|wget|python-requests|dalvik|cfnetwork)/$"
)

# Toolchain custody records legitimately carry four-component JDK versions in
# two machine-readable shapes. Keep this exception scoped to the reviewed pins
# file so a similarly shaped endpoint anywhere else remains a finding.
TOOLCHAIN_PINS_PATH_RE = re.compile(r"(?i)(?:^|/)tools/toolchain-pins\.json$")
TOOLCHAIN_PINS_JSON_VERSION_RE = re.compile(r'(?i)"version"\s*:\s*"$')
TOOLCHAIN_PINS_JDK_ARCHIVE_RE = re.compile(
    r'(?i)OpenJDK[^"/]*_hotspot_$'
)
TOOLCHAIN_PINS_JDK_ARCHIVE_TAIL_RE = re.compile(r'_\d+\.tar\.gz"')

# X.509 / ASN.1 object identifiers are dotted decimal too.
OID_CONTEXT_RE = re.compile(
    r"(?i)\b(?:oid|oids|policyidentifier|certificatepolicies|extendedkeyusage|"
    r"eku|asn\.?1|objectidentifier|x\.?509|certificate|certificates|"
    r"subjectaltname|keyusage|basicconstraints)\b"
)
# X.660: an OID's root arc can only be 0, 1 or 2. This is the guard that
# matters -- no address whose first octet is 3 or greater can be suppressed as
# an OID, whatever words share its line.
OID_MAX_ROOT_ARC = 2

# Registered OID arcs (NEW 2026-08-07). The rule above needs certificate prose
# ON THE LINE, and a map literal has none -- `"2.5.4.6": "countryName"` in
# internal/coverlisten/covercert.go is 100 % OID and 0 % prose, which produced
# 12 false positives there and one more in its test.
#
# Written as a list of REGISTERED PREFIXES rather than a looser pattern,
# because a JSON object keyed by address (`{"<node>": "kansas"}`) is a
# perfectly plausible shape in this project and must keep flagging. Root arc
# <= 2 alone would not save it. A missing arc here costs a false positive,
# which is the safe direction; a too-broad arc would cost a false negative,
# which is not, so this list only grows on evidence.
#
# Assembled from tuples at run time, for exactly the reason `_host()` exists
# further down: THIS FILE IS SCANNED BY ITS OWN DETECTOR. Spelled out as string
# literals, the IETF arc is a four-component dotted quad whose first octet is
# routable, and it would sit in TUPLE position rather than map-key position --
# so the very rule defined below would decline to suppress it, `ipscrub scan`
# would report this file, and the pre-push gate would block the push that ships
# its own fix. That is not a thought experiment: it happened while writing this
# change, and the sandbox push that caught it is the reason the tuples are here.
# The same trap swallowed a first attempt at THIS comment, which explained the
# hazard by quoting the literal it was warning about.
def _arc(*parts):
    """Build a registered OID arc prefix without writing a quad literal."""
    return ".".join(str(p) for p in parts) + "."


OID_REGISTERED_ARCS = (
    _arc(0, 9, 2342),   # RFC 4519 pilot attributes -- userID, domainComponent
    _arc(1, 2, 840),    # ISO member-body US -- RSA / PKCS / ANSI
    _arc(1, 3, 6, 1),   # IETF, including the private enterprise number tree
    _arc(2, 5, 4),      # X.520 attribute types -- the covercert.go DN map
    _arc(2, 5, 29),     # X.509 v3 certificate extensions
    _arc(2, 16, 840),   # Joint-ISO-ITU-T country US
    _arc(2, 23, 140),   # CA/Browser Forum certificate policies
)
DOT_RUN_CHARS = frozenset("0123456789.")
# Anchored with `.match(line, pos)`, so no `^`: `^` would bind to the start of
# the line rather than to pos and the rule would never fire.
OID_MAP_KEY_TAIL_RE = re.compile(r"\s*:")

SHARED_ADDRESS_SPACE_V4 = ipaddress.IPv4Network("100.64.0.0/10")

# ==========================================================================
# Dashed-quad hostname detection  (NEW 2026-08-22 -- item 8)
# ==========================================================================
#
# A dashed quad is an IPv4 address wearing a hostname label: sslip.io and
# nip.io answer DNS for `a-b-c-d.<domain>` with `a.b.c.d`, so every octet
# survives in the clear and QUAD_RE above never sees it -- the dots are
# dashes. Normalised to dots and handed to the SAME parser, the SAME
# infrastructure test, the SAME allowlist and the SAME version suppressor, so
# no second set of rules exists to drift: `VERSION=1-2-3-4` suppresses
# exactly as `VERSION=1.2.3.4` does.
#
# Two positional bounds, mirroring how the encoding is actually used:
#   1. a hostname label: the quad is immediately followed by `.` + a letter
#      (`<quad>.sslip.io`, `<quad>.nip.io`, any `<quad>.<domain>`);
#   2. an endpoint target: the quad is preceded by `@`, `=` or the `/` of a
#      scheme, and followed by `:` (a port), `/`, whitespace, a quote or end
#      of line (`ssh root@<quad>`, `https://<quad>/path`, `HUB=<quad>`).
# A bare `1-2-3-4` in prose ("steps 1-2-3-4") matches neither bound and stays
# unflagged, which is the whole point of the bounds: the shape alone is far
# too common to be an address claim.
DASHED_QUAD_RE = re.compile(
    r"(?<![0-9A-Za-z_-])(\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})(?![0-9A-Za-z_-])"
)
DASHED_LABEL_TAIL_RE = re.compile(r"\.[A-Za-z]")


def is_dashed_host_shaped(line, m):
    """True if the dashed quad at `m` is used as a hostname, not prose."""
    after = line[m.end(1):]
    if DASHED_LABEL_TAIL_RE.match(after):
        return True
    if m.start(1) == 0:
        return False
    if line[m.start(1) - 1] not in "@/=":
        return False
    return (not after) or after[0].isspace() or after[0] in ":/'\""


# ==========================================================================
# IPv6 detection  (NEW -- item 2)
# ==========================================================================
#
# Matched as a maximal run of hex groups so that a longer colon-hex string --
# a 32-group TLS fingerprint, say -- is consumed WHOLE and then rejected by the
# parser, rather than a valid-looking 8-group window being carved out of its
# middle. The lookarounds stop the match beginning or ending inside such a run.
#
# `::` is required to appear, OR eight groups, because that is what makes an
# IPv6 address; three-group shapes like `00:31:30` (a timestamp) and six-group
# shapes like a MAC address are not valid IPv6 and are dropped by the parser.
V6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.%])"
    r"([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})"
    r"(?:%[A-Za-z0-9_.-]+)?"
    r"(?![0-9A-Fa-f:])"
)
# Bracketed-with-port `[2001:db8::1]:9110` is covered: the bracket and the port
# colon sit outside the captured group.
#
# Why `::` in C++/Dart source cannot produce a false positive, structurally:
# to be flagged an address must be global unicast, i.e. inside 2000::/3, which
# requires its FIRST group to be four hex digits beginning with 2 or 3. No
# identifier in any language in this repository may begin with a digit, so
# `std::string`, `winrt::Windows`, `abc::def` all normalise into ::/8 .. 1000::/4
# (reserved) or f000::/4 and are dropped. The same argument disposes of colon-hex
# fingerprints written as two-digit bytes: their first group is <= 0xff, which is
# inside ::/8.


def parse_v6(text):
    """Return a canonical IPv6Address for `text`, or None."""
    tok = text.split("%", 1)[0]
    if tok.count(":") < 2:
        return None
    try:
        return ipaddress.IPv6Address(tok)
    except ValueError:
        return None


# ==========================================================================
# WireGuard / AmneziaWG key shapes  (NEW -- item 3)
# ==========================================================================
#
# Curve25519 keys are 32 bytes, written base64 as 43 chars plus one `=`. That
# is byte-for-byte the same shape as an SRI hash (`sha256-<44 chars>`) and as
# a lockfile integrity digest, both of which this repository contains, so the
# match is gated on context and on the absence of a digest prefix.
B64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{43}=)(?![A-Za-z0-9+/=])")

# Blocking: real secrets.
WG_SECRET_CTX_RE = re.compile(
    r"(?i)\b(?:private[_ -]?key|preshared[_ -]?key|psk|secret[_ -]?key)\b\s*[=:]"
)
# Warning only: public keys are public by construction. What makes them
# disclosive is being tabulated next to a node address -- and the address is
# what this gate blocks.
WG_PUBLIC_CTX_RE = re.compile(
    r"(?i)\b(?:public[_ -]?key|pub[_ -]?key|peer|wireguard|amnezia|awg|wg[0-9]?|"
    r"allowed[_ -]?ips|endpoint)\b"
)
# Digest prefixes that produce the identical 44-char shape.
B64_DIGEST_PREFIX_RE = re.compile(
    r"(?i)(?:sha(?:1|224|256|384|512)|md5|blake[23]b?|integrity|checksum|digest|"
    r"hash|sri|etag|h1)\s*[-:=]\s*[\"']?$"
)
# Files whose entire purpose is to carry digests of this shape. `go.sum` earns
# its place: its `h1:` dirhashes are 44-char base64 and its module paths contain
# the word `amnezia`, so every line of it looked like a keyed WireGuard config.
B64_SKIP_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:[^/]*\.lock|[^/]*-lock\.json|[^/]*\.lockfile|go\.sum|"
    r"[^/]*\.sha\d+|[^/]*\.map|[^/]*\.pbxproj|[^/]*\.resolved)$"
)

BINARY_SNIFF_BYTES = 8192
MAX_LINE_ECHO = 118

KIND_V4 = "ipv4"
KIND_V6 = "ipv6"
KIND_WG_SECRET = "wg-secret"
KIND_WG_PUBLIC = "wg-public"
KIND_BINARY_EVIDENCE = "binary-evidence"
BLOCKING_KINDS = {KIND_V4, KIND_V6, KIND_WG_SECRET, KIND_BINARY_EVIDENCE}

# ==========================================================================
# Evidence paths  (NEW 2026-08-07 -- item 6)
# ==========================================================================
#
# The gate reads text. Every binary blob was sniffed and silently skipped, and
# on 2026-08-03 three real `.pcap` captures rode a doubled path
# (`winn_protocol_experimental/winn_protocol_experimental/evidence/...`) into a
# push that this gate approved without reading a byte of them.
#
# A binary the scanner cannot read is not a clean result; it is an unknown. On
# paths that by convention hold capture output, an unknown is refused. Anywhere
# else binaries still skip, because refusing every icon, archive and `.so`
# would make the gate noise and noise is what gets a gate switched off.
#
# The two shapes below are the same two the repository's `.gitignore` now
# carries, deliberately: a path this gate refuses is a path git should already
# have ignored, and when they disagree one of them is wrong.
EVIDENCE_DIR_RE = re.compile(r"(?i)(?:^|/)(?:evidence|[^/]*_evidence_[^/]*)(?:/|$)")
CAPTURE_EXT_RE = re.compile(r"(?i)\.(?:pcap|pcapng|cap|etl)$")


def is_evidence_path(path):
    """True if `path` is where capture output lives, by directory or by suffix."""
    p = (path or "").replace("\\", "/")
    return bool(EVIDENCE_DIR_RE.search(p) or CAPTURE_EXT_RE.search(p))


def binary_evidence_finding(path, nbytes):
    """The refusal a skipped binary on an evidence path becomes."""
    return Finding(
        path, 0, "<unreadable binary, %d byte(s)>" % nbytes,
        "binary blob on an evidence path -- this gate cannot read it, "
        "so it cannot clear it", 0, KIND_BINARY_EVIDENCE)


class Finding:
    __slots__ = ("path", "lineno", "ip", "line", "column", "kind", "binary", "glued")

    def __init__(self, path, lineno, ip, line, column, kind, binary=False):
        self.path = path
        self.lineno = lineno
        self.ip = ip
        self.line = line
        self.column = column
        self.kind = kind
        # `binary` makes the report say "byte +0x1f40" instead of "line 8000",
        # because for a blob the number is an OFFSET and calling it a line
        # would send the reader looking for a line that does not exist.
        self.binary = binary
        self.glued = False

    def excerpt(self):
        s = self.line.strip()
        if len(s) > MAX_LINE_ECHO:
            i = s.find(self.ip)
            start = max(0, i - MAX_LINE_ECHO // 3)
            s = ("..." if start else "") + s[start:start + MAX_LINE_ECHO] + "..."
        return s


def normalize_quad(text):
    """Canonical IPv4Address for `text`, or None.

    Leading zeros are tolerated and normalised (`010.008.000.001` -> `10.8.0.1`).
    Python's parser rejects them outright and silently dropping such a string
    would be a false negative -- the failure mode this detector least wants.
    """
    parts = text.split(".")
    if len(parts) != 4:
        return None
    octets = []
    for p in parts:
        if not p or not p.isdigit() or len(p) > 3:
            return None
        v = int(p, 10)
        if v > 255:
            return None
        octets.append(v)
    return ipaddress.IPv4Address(".".join(str(o) for o in octets))


def is_infrastructure_v4(ip):
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return False
    if ip in SHARED_ADDRESS_SPACE_V4:
        return False
    return True


def is_infrastructure_v6(ip):
    if ip.ipv4_mapped is not None:
        return is_infrastructure_v4(ip.ipv4_mapped)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return False
    if ip.is_site_local:
        return False
    return True


def is_toolchain_pin_version(path, line, match):
    """True for the two reviewed JDK-version fields in toolchain-pins.json."""
    if not TOOLCHAIN_PINS_PATH_RE.search(path or ""):
        return False
    before = line[:match.start()]
    after = line[match.end(1):]
    if TOOLCHAIN_PINS_JSON_VERSION_RE.search(before):
        return True
    return bool(
        TOOLCHAIN_PINS_JDK_ARCHIVE_RE.search(before)
        and TOOLCHAIN_PINS_JDK_ARCHIVE_TAIL_RE.match(after)
    )


def is_version_shaped(line, start):
    """True if the quad at `start` is a version number, not an address.

    Three narrow rules, each bounded so it cannot swallow a real address:

    1. Immediately preceded by a bare `v`/`V`            -> `v1.2.3.4`.
    2. A version keyword with `=` or `:` earlier on the line, with NO letters
       between keyword and quad. Catches `DriverVer = 03/25/2026,1.3.0.0`
       while leaving `Version: node reachable at <addr>` flagged.
    3. (NEW) A library/toolkit name earlier on the line, again with NO letters
       between it and the quad. Catches `libcublas 13.1.1.3` while leaving
       `the CUDA box at <addr>` flagged, because `box at ` has letters.
    4. (NEW 2026-08-07) A browser user-agent product token IMMEDIATELY
       followed by `/` and then the quad -- `HeadlessChrome/150.0.0.0`.
    """
    before = line[:start]
    if re.search(r"(?<![\w.])[vV]$", before):
        return True
    if UA_PRODUCT_RE.search(before):
        return True
    # `wins_vpn.apple_packet_tunnel.v3.1.0.14.29.installed` -- a version inside
    # a dotted identifier, which the docs-repo rule missed because it refused
    # any `.` before the `v`. Allowed here ONLY when the character before that
    # dot is a letter or underscore, i.e. the dot is an identifier separator.
    # `2026.v1.2.3.4` is still flagged, because a digit precedes the dot.
    if re.search(r"(?<=[A-Za-z_])\.[vV]$", before):
        return True
    for kw_re in (VERSION_KW_RE, LIBVER_KW_RE):
        last = None
        for m in kw_re.finditer(before):
            last = m
        if last is not None and not LETTER_RE.search(before[last.end():]):
            return True
    return False


CIDR_SUFFIX_RE = re.compile(r"/(\d{1,3})(?!\d)")

# Below these prefix lengths a literal is arithmetic, not a host: nobody writes
# a machine's address with a /1 or a /3.
ROUTE_PREFIX_LIMIT = {4: 8, 6: 16}


def is_route_prefix(line, end, ip):
    """True if this is the base of a very short CIDR block -- route math.

    Covers the classic full-tunnel split pair `0.0.0.0/1` + `128.0.0.0/1`, its
    IPv6 twin `::/1` + `8000::/1`, and prose that names a block such as
    `2000::/3`. Replaces what would otherwise be a growing list of allowlist
    holes, and generalises to blocks nobody has written down yet.

    Bounded twice so it cannot reach a node address:
      1. The prefix must be shorter than /8 (v4) or /16 (v6).
      2. The address must be EXACTLY the base of that block, i.e. every host
         bit zero. A real node address is not the base of a /3.
    `<node>/32` and `<node>/128` are therefore still flagged, as they must be.
    """
    m = CIDR_SUFFIX_RE.match(line, end)
    if not m:
        return False
    n = int(m.group(1), 10)
    if n >= ROUTE_PREFIX_LIMIT[ip.version]:
        return False
    try:
        net = ipaddress.ip_network("%s/%d" % (ip, n), strict=False)
    except ValueError:
        return False
    return net.network_address == ip


def is_oid_shaped(line, m):
    """True if this is an ASN.1 object identifier rather than an address.

    Guarded twice, and the second guard is the one that matters:

    1. Surrounding prose must name certificates/OIDs.
    2. The first octet must be <= 2, because an OID's root arc can only be
       0, 1 or 2. No address with a first octet of 3 or more can be suppressed
       here, so every node address in this project is structurally out of reach.

    Unlike the docs-repo original this accepts the FOUR-component form as well
    as the five-component one, because `Oid.Value -eq '2.5.29.37'` occurs in
    this repository and the four-component restriction made it a false positive.
    """
    if int(m.group(1).split(".", 1)[0], 10) > OID_MAX_ROOT_ARC:
        return False
    return bool(OID_CONTEXT_RE.search(line))


def _dotted_run(line, pos):
    """Span of the maximal digits-and-dots run containing `pos`.

    QUAD_RE only ever captures four components, so a six-arc CA/Browser Forum
    policy OID such as 2.23.140.1.2.2 arrives here truncated to its first four
    arcs. The arc test has to see the WHOLE token, or a long OID would be
    judged on a prefix that is not the token actually written in the file.
    """
    a = b = pos
    while a > 0 and line[a - 1] in DOT_RUN_CHARS:
        a -= 1
    while b < len(line) and line[b] in DOT_RUN_CHARS:
        b += 1
    return a, b


def is_bare_oid_literal(line, m):
    """True if this dotted-decimal is a bare OID literal rather than an address.

    `is_oid_shaped` requires certificate prose on the line. A Go or JSON map
    literal has none:

        "2.5.4.6":  "countryName",

    That is the shape of every row in `internal/coverlisten/covercert.go`, and
    it is why the scoping pass counted 13 phantom occurrences there. The
    scoping pass was explicit that this file needs a SCANNER fix and not a
    scrub -- the values really are OIDs.

    Three preconditions apply to every case, and none of them is dropped:

      1. Root arc <= 2 (X.660), the same structural guard the prose rule uses.
         No address with a first octet of 3 or more is reachable from here.
      2. WHOLE QUOTED TOKEN. The dotted run must be exactly the contents of a
         quoted string -- opening quote immediately before, the same quote
         immediately after, digits and dots in between and nothing else.
      3. A REGISTERED ARC PREFIX, dot-terminated. This is the guard doing the
         real work, because `{"<node>": "kansas"}` is a shape this project
         could easily write and it must keep flagging. The dot terminator on
         each prefix is load-bearing: a token whose third arc merely STARTS
         with the registered arc's third arc -- `H_UNREG_KEY` in the self-test
         is one digit away from the X.520 attribute arc -- is not under it,
         and must still flag. (Written by reference rather than spelled out:
         this file is scanned by its own detector, and the first draft of this
         very paragraph flagged itself.)

    Given those, one of two positional cases must also hold:

      a. MAP-KEY POSITION -- the closing quote is followed only by optional
         space and a `:`. This is `covercert.go`'s DN map, 12 occurrences.
      b. FIVE OR MORE ARCS, anywhere -- a test assertion, a constant, an
         argument. This bound is airtight rather than merely tight: an IPv4
         literal has EXACTLY four components, so a five-arc token is not an
         address at all. The one shape that could otherwise sneak in is
         tcpdump's `host.port`, and precondition 2 excludes it (a capture
         writes `<addr>.443` unquoted) as do preconditions 1 and 3.

    Case (b) exists because `covercert_test.go` asserts on a policy OID as a
    plain argument -- `mentions(result.Identifying, "<5-arc oid>")` -- which
    case (a) does not reach. Left unhandled it would be one standing false
    positive in a tracked file, and one standing false positive is how a gate
    starts being ignored.
    """
    a, b = _dotted_run(line, m.start())
    if a == 0 or b >= len(line):
        return False
    quote = line[a - 1]
    if quote not in "\"'" or line[b] != quote:
        return False
    tok = line[a:b]
    parts = tok.split(".")
    # Rejects a leading or trailing dot, which would otherwise inflate the arc
    # count by one and let a four-arc token pass the five-arc test.
    if not all(p.isdigit() for p in parts):
        return False
    if int(parts[0], 10) > OID_MAX_ROOT_ARC:
        return False
    if not any(tok.startswith(arc) for arc in OID_REGISTERED_ARCS):
        return False
    return bool(OID_MAP_KEY_TAIL_RE.match(line, b + 1)) or len(parts) >= 5


def scan_text(text, path, allowlist):
    """Return (findings, suppressed) for one document."""
    findings, suppressed = [], []
    skip_b64 = bool(B64_SKIP_PATH_RE.search(path or ""))
    for lineno, line in enumerate(text.splitlines(), 1):
        # --- IPv4 ---
        for m in QUAD_RE.finditer(line):
            raw = m.group(1)
            ip = normalize_quad(raw)
            if ip is None or not is_infrastructure_v4(ip):
                continue
            if allowlist.contains(ip):
                continue
            f = Finding(path, lineno, raw, line, m.start(), KIND_V4)
            if (is_toolchain_pin_version(path, line, m)
                    or is_version_shaped(line, m.start()) or is_oid_shaped(line, m)
                    or is_bare_oid_literal(line, m)
                    or is_route_prefix(line, m.end(1), ip)):
                suppressed.append(f)
                continue
            findings.append(f)

        # --- Dashed-quad hostnames (NEW 2026-08-22) ---
        for m in DASHED_QUAD_RE.finditer(line):
            raw = m.group(1)
            ip = normalize_quad(raw.replace("-", "."))
            if ip is None or not is_infrastructure_v4(ip):
                continue
            if allowlist.contains(ip):
                continue
            if not is_dashed_host_shaped(line, m):
                continue
            f = Finding(path, lineno, raw, line, m.start(1), KIND_V4)
            if is_version_shaped(line, m.start(1)):
                suppressed.append(f)
                continue
            findings.append(f)

        # --- IPv6 ---
        for m in V6_RE.finditer(line):
            raw = m.group(1)
            ip = parse_v6(raw)
            if ip is None or not is_infrastructure_v6(ip):
                continue
            if allowlist.contains(ip):
                continue
            f = Finding(path, lineno, raw, line, m.start(), KIND_V6)
            if is_route_prefix(line, m.end(1), ip):
                suppressed.append(f)
                continue
            findings.append(f)

        # --- WireGuard / Curve25519 key shapes ---
        if skip_b64:
            continue
        for m in B64_KEY_RE.finditer(line):
            before = line[:m.start(1)]
            if B64_DIGEST_PREFIX_RE.search(before):
                suppressed.append(
                    Finding(path, lineno, m.group(1), line, m.start(1), KIND_WG_PUBLIC))
                continue
            if WG_SECRET_CTX_RE.search(line):
                kind = KIND_WG_SECRET
            elif WG_PUBLIC_CTX_RE.search(line):
                kind = KIND_WG_PUBLIC
            else:
                continue
            findings.append(Finding(path, lineno, m.group(1), line, m.start(1), kind))
    return findings, suppressed


def looks_binary(data):
    return b"\0" in data[:BINARY_SNIFF_BYTES]


def decode(data):
    return data.decode("utf-8", errors="replace")


# ==========================================================================
# Raw-byte scanning of binary blobs  (NEW 2026-08-07 -- the residual hole)
# ==========================================================================
#
# The evidence-path rule above refuses a binary because of WHERE it sits. That
# left the complement wide open: a blob that is neither on an evidence path nor
# carrying a capture suffix was still `continue`d unread. A compiled binary, a
# shared object, a tarball, a SQLite database, a `.dill`, an image with EXIF --
# any of them could carry an infrastructure address straight through the gate.
#
# So binaries are now read. Two mechanisms, deliberately unequal in ambition:
#
#   1. TEXT RUNS (primary).  Extract printable runs -- ASCII and UTF-16LE, the
#      latter because Windows binaries and `.etl` store strings that way -- and
#      feed each run through `scan_text`. This reuses every discriminator the
#      text path already has: the allowlist, the version-quad rule, the OID
#      rules, route-prefix suppression, and the WireGuard key context rules.
#      Reuse is the whole point; a second, parallel set of rules would drift.
#
#   2. PACKED VALUES (narrow, on purpose).  See PACKED SCANNING below.
#
# ---------------------------------------------------------------------------
# WHY A RUN IS NOT A LINE  -- the false-positive rule that makes this usable
# ---------------------------------------------------------------------------
# In text, a line is a semantic unit. In a binary, a printable run is an
# arbitrary CONCATENATION of unrelated strings: Go, Swift and MSVC all pack
# their string tables end to end with no separator, so digits from the tail of
# one string join digits from the head of the next and manufacture a dotted
# quad that never existed as a value.
#
# Measured on this repository -- 267 tracked binaries, 368 MB -- a naive
# run-as-line scan produced 106 findings and every single one was false:
#
#     ...marshal.func1.1.1.1        Go closure symbol names (96 of the 106)
#     ...spdy/3spdy/<quad>u=0, i    two string-table entries fused
#     <quad>map[%s]%sMediaStop      a run beginning mid-table
#
# The shape they share is that the address is GLUED to identifier characters.
# A real serialized address is delimited -- `endpoint=<addr>:51820`, a bare
# string of its own in a SQLite cell, a value in an EXIF tag. So a finding from
# a binary run is dropped when a letter, digit or underscore sits immediately
# on either side of it. That rule removed 100 of the 106, and the remainder
# were genuine routable literals inside vendored upstream binaries, which is
# the detector working correctly and is what the allowlist is for.
#
# The cost is a bounded false NEGATIVE: an address welded to a word with no
# delimiter (`wg01.2.3.4`) is missed. No real serializer emits that, and the
# alternative -- 106 false alarms on every push -- is a gate somebody switches
# off, which is worse than the hole.
BIN_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")
BIN_UTF16LE_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
BIN_GLUE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")

# A blob past this size is not scanned byte by byte; it is refused instead.
# Nothing in this repository is close (the largest tracked binary is 38 MB), so
# the cap costs nothing today and fails CLOSED if that ever changes.
MAX_BINARY_SCAN_BYTES = 256 * 1024 * 1024


def _binary_text_runs(data):
    """Yield (byte_offset, text, stride) for printable runs, ASCII then UTF-16LE.

    `stride` is bytes-per-character, so a caller can turn an index within the
    decoded run back into a real file offset. Without it every UTF-16 offset
    reported would be half the true one and would send the reader to the wrong
    part of the file.
    """
    for m in BIN_ASCII_RUN_RE.finditer(data):
        yield m.start(), m.group(0).decode("ascii"), 1
    for m in BIN_UTF16LE_RUN_RE.finditer(data):
        yield m.start(), m.group(0)[::2].decode("ascii"), 2


# A run that is EXACTLY a dotted quad and sits immediately after a run ending
# in a version keyword is a version number, not an address. This is how Windows
# VERSIONINFO stores things: the key (`FileVersion`) and its value (the bare
# version quad) are two separate NUL-terminated strings, so the keyword the
# text-side
# `is_version_shaped` needs is never on the same "line" and that rule cannot
# fire. Measured: this is the whole of the residual false-positive class, two
# hits in installer/windows/dependencies/mullvad-split-tunnel.sys.
#
# Deliberately narrow. The run must be the quad and NOTHING else, so a real
# `<addr>:51820` endpoint or a bare address in a SQLite cell is untouched --
# the latter is a case the self-test pins in the must-flag direction.
BIN_VERSION_KEY_RE = re.compile(
    r"(?i)\b(?:driverver|fileversion|productversion|assemblyversion|appversion|"
    r"osversion|version|vers|ver|revision|rev|build)\s*$")
BIN_BARE_QUAD_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Bytes of padding tolerated between the key run and the value run.
BIN_VERSION_GAP = 8


def _ends_with_version_key(text):
    """True if `text` ends in a version keyword, tolerating one glued prefix char.

    A UTF-16LE run can begin one byte early: an ASCII character followed by the
    string's first NUL looks exactly like a UTF-16 pair, so `...INFO\\0` before
    `FileVersion` decodes as `OFileVersion` and the `\\b` in the keyword pattern
    then has no boundary to anchor to. That is a one-character ambiguity in the
    run boundary, so it is answered by testing the run with its first character
    dropped as well -- not by loosening `\\b`, which would let `conversion`
    pass for `version`.
    """
    if BIN_VERSION_KEY_RE.search(text):
        return True
    return bool(text and BIN_VERSION_KEY_RE.search(text[1:]))


def _is_glued(run, start, end):
    """True if `run[start:end]` is welded to surrounding identifier characters.

    This is what separates a serialized address from one manufactured by two
    unrelated string-table entries meeting. See the block comment above.
    """
    if start > 0 and run[start - 1] in BIN_GLUE_CHARS:
        return True
    if end < len(run) and run[end] in BIN_GLUE_CHARS:
        return True
    return False


# ---------------------------------------------------------------------------
# PACKED SCANNING -- why it is narrow, and why "scan for packed quads" is a trap
# ---------------------------------------------------------------------------
# ANY four consecutive bytes are a syntactically valid IPv4 address, and about
# 78% of them decode to something globally routable. A packed scan over this
# repository's 368 MB of binaries would therefore report roughly 287 MILLION
# "addresses". Sixteen-byte IPv6 is no better in practice: one byte in eight
# lands in 2000::/3 by chance. There is no threshold that rescues this -- the
# signal is not weak, it is absent. A packed value carries no evidence that it
# is an address at all.
#
# So packed scanning is done ONLY where something else supplies that evidence,
# and there turns out to be exactly one place where it does:
#
#   AGAINST A KNOWN NODE MAP (`--node-map`, `$IPSCRUB_NODE_MAP`, or
#   `git config ipscrub.nodeMap`).  If you can say WHICH addresses are yours,
#   searching for their 4- and 16-byte encodings is targeted rather than
#   speculative: a hit is a byte-for-byte match on a value you already named.
#   This is off unless a map is supplied and the file is deliberately NOT in
#   this repository -- it lives in the no-remote archive (`wins/docs`) that
#   already holds the node map. Writing those addresses into a file here in
#   order to detect them here would be the disclosure the gate exists to
#   prevent, so a path inside the repo is refused outright.
#
#   MEASURED 2026-08-07, THE FIRST TIME IT WAS EVER ARMED HERE -- and it does
#   NOT have "zero false positives by construction", which is what the note
#   here used to imply. Exactness is about the VALUE, not about whether the
#   bytes are an address. A 15-address map expands to 27 encodings (each IPv4
#   is also searched byte-reversed): 24 four-byte patterns and 3 sixteen-byte
#   ones. Over the 264 blobs / 367.8 MB actually byte-scanned in this tree the
#   chance-collision arithmetic is
#
#       4-byte:   24 * 367_821_971 / 2^32   = 2.06 expected
#       16-byte:   3 * 367_821_971 / 2^128  = 3e-30 expected
#
#   and the run produced exactly ONE new finding: a 4-byte match at +0x6a4bf in
#   web/assets/demo/winsvpn-ios-demo.mp4. That offset lands inside the `mdat`
#   box -- the compressed video payload, not `moov`/`udta`/`meta` where metadata
#   could live -- so it is a chance collision, precisely as 2.06-expected
#   predicts. It is still reported, and it should be: the gate's job is to hand
#   a human something to confirm, not to decide silently.
#
#   So: a 16-byte hit is as good as proof. A 4-byte hit needs one more step --
#   look at WHERE it lands. Inside compressed or encrypted payload it is noise;
#   in a header, a config blob, a string table or a database page it is real.
#   The same discipline as the rejected heuristic below, applied to the rule
#   that replaced it.
#
# ---------------------------------------------------------------------------
# A HEURISTIC THAT WAS TRIED AND REJECTED -- do not re-add it without numbers
# ---------------------------------------------------------------------------
# The obvious way to make packed scanning work without a node map is to demand
# structural corroboration: match a serialized `sockaddr_in` -- AF_INET (2) as
# a 16-bit family, then a big-endian port, then the four address bytes, with
# BSD/macOS prefixing a length byte (0x10 0x02). Requiring the family bytes AND
# a port drawn from a short meaningful set looks decisive on paper: 2-in-65536
# for the family times 14-in-65536 for the port predicts about 0.001 chance
# matches across all 368 MB of binaries in this repository.
#
# It was implemented and measured. It produced 840 hits across 33 files --
# roughly a million times the predicted rate -- including three PNG/WebP image
# assets. The arithmetic assumed uniformly random bytes, and real binaries are
# nothing of the kind: they are full of alignment padding and zero-filled
# structures, so `\x02\x00` is common rather than rare, and every low port
# worth searching for (22, 53, 80) has a zero high byte, which is the single
# most over-represented byte in any object file. Ports 22, 53 and 80 alone
# accounted for 758 of the 840.
#
# It was removed. Blocking an app icon is precisely the failure that gets a
# gate switched off, and a rule that fires on `assets/icon/app_icon.png` would
# have done it within a day. The lesson is the general one for this file: for
# packed bytes, estimate the false-positive rate by MEASURING it against the
# real corpus, never by assuming a uniform distribution.


class NodeMap:
    """Addresses known to be this project's own, loaded from OUTSIDE the repo.

    Holds only packed encodings -- the literals never need to be printed, and
    a report says "the packed form of a known node address", never the value.
    """

    def __init__(self):
        self.packed = {}          # bytes -> label
        self.naddrs = 0           # distinct addresses, not encodings

    def add(self, token, label):
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            ip = normalize_quad(token)
            if ip is None:
                return False
        if ip.packed not in self.packed:
            self.naddrs += 1
        self.packed[ip.packed] = label
        # Some serializers store v4 in host order; catch the reversal too.
        if ip.version == 4:
            self.packed.setdefault(ip.packed[::-1], label + " (byte-reversed)")
        return True

    def __len__(self):
        return len(self.packed)


def node_map_inside_repo(path, repo):
    """Is this node-map path inside the repository it is about to scan?

    A pure predicate so it can be tested both directions without touching a
    filesystem. It is the one rule the node map has: the file is a list of this
    project's real addresses, so putting it in the repository -- in order to
    detect those addresses in the repository -- would BE the disclosure the gate
    exists to prevent. Refused, not warned about.

    Compared component-wise on normalised absolute paths, so a sibling that
    merely shares a name prefix (`wins_vpn_notes/` next to `wins_vpn/`) is not
    mistaken for something inside the tree.
    """
    if not path or not repo:
        return False
    p = os.path.normpath(os.path.abspath(path)).split(os.sep)
    r = os.path.normpath(os.path.abspath(repo)).split(os.sep)
    return len(p) > len(r) and p[:len(r)] == r


def load_node_map(path, repo=None, source=None):
    """Load a node map, or fail loudly. Never returns a silently-empty map.

    Two failures used to be indistinguishable from "no map configured", and
    both of them looked like success: a path that does not exist, and a path
    inside the repository. Both are now hard errors. A configured-but-unusable
    node map is the exact shape of the bug this whole tool keeps finding -- a
    check that reports OK while doing nothing.
    """
    nm = NodeMap()
    if not path:
        return nm
    where = " (from %s)" % source if source else ""
    if node_map_inside_repo(path, repo):
        raise RuntimeError(
            "node map %s%s is INSIDE the repository at %s.\n"
            "         That file lists this project's own addresses. Writing them\n"
            "         here in order to detect them here is the disclosure this\n"
            "         gate exists to prevent. Move it outside the tree."
            % (path, where, repo))
    if not os.path.exists(path):
        raise RuntimeError(
            "node map %s%s does not exist.\n"
            "         Refusing to continue with the packed scan silently off --\n"
            "         a configured map that cannot be read must not look like a\n"
            "         clean result. Fix the path or unset it." % (path, where))
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            tok = line.split("#", 1)[0].strip()
            if not tok:
                continue
            if not nm.add(tok.split()[0], "node-map line %d" % n):
                sys.stderr.write("ipscrub: node map: ignoring %r\n" % tok)
    if not len(nm):
        raise RuntimeError(
            "node map %s%s contains no usable addresses.\n"
            "         An empty map is not a clean scan, it is no scan." % (path, where))
    return nm


# ---------------------------------------------------------------------------
# Where the node map comes from -- and why not from CI
# ---------------------------------------------------------------------------
# The packed scan is the one check that needs to be TOLD this project's
# addresses. Until 2026-08-07 nothing supplied them anywhere, so the packed path
# was off in every checkout and every job, and said nothing about it: dead code
# reporting success, which is the failure this file exists to catch.
#
# Resolution order, most explicit first. Each source is named in the status line
# so "which map am I running?" is never a guess:
#
#   1. --node-map PATH
#   2. $IPSCRUB_NODE_MAP
#   3. `git config ipscrub.nodeMap`  <-- the one that survives a reboot
#
# (3) is the wiring for the pre-push path. It lives in .git/config, which is not
# version controlled and is never pushed, so the PATH is per-clone local state
# and the FILE stays wherever the operator keeps it -- the no-remote archive.
# One command per clone:
#
#     git config ipscrub.nodeMap /path/outside/this/repo/node-map.txt
#
# WHY NOT A GITHUB ACTIONS SECRET. It was considered and rejected, and the
# reasons are not stylistic:
#
#   * It inverts the threat model. The map is the list of addresses whose
#     disclosure to GitHub this gate prevents. Storing it as an Actions secret
#     hands that exact list to GitHub to hold. There is no version of that which
#     is a smaller disclosure than the one being defended against.
#   * CI runs AFTER the push. By the time a workflow starts, the objects are
#     already on the remote. A packed scan there could only report a disclosure
#     that has already happened -- it is forensics, not a gate. The pre-push
#     hook is the only place where the answer still changes the outcome.
#   * Any collaborator who can land a workflow change can read a secret. This
#     remote has a dozen branches and the repository's visibility, forks,
#     collaborators and deploy keys have not been checked by anyone -- see the
#     owner item about the settings page nobody has opened.
#
# What it would take to run the packed scan off this machine, honestly stated:
# a runner on operator-controlled hardware (self-hosted, or a local batch job)
# reading the map from local disk, with no third party ever holding the file.
# Nothing in the current setup provides that, and no substitute was invented.


def resolve_node_map(args, repo):
    """(NodeMap, status_line). Raises RuntimeError on a configured-but-bad map."""
    path, source = getattr(args, "node_map", None), "--node-map"
    if not path:
        path, source = os.environ.get("IPSCRUB_NODE_MAP") or None, "$IPSCRUB_NODE_MAP"
    if not path and repo:
        out = subprocess.run(["git", "-C", repo, "config", "--get", "ipscrub.nodeMap"],
                             capture_output=True, text=True, check=False)
        if out.returncode == 0 and out.stdout.strip():
            path, source = out.stdout.strip(), "git config ipscrub.nodeMap"

    if not path:
        if getattr(args, "require_node_map", False) or \
                os.environ.get("IPSCRUB_REQUIRE_NODE_MAP") == "1":
            raise RuntimeError(
                "--require-node-map was given but no node map is configured.\n"
                "         Set one of: --node-map PATH, $IPSCRUB_NODE_MAP, or\n"
                "             git config ipscrub.nodeMap /path/outside/this/repo\n"
                "         Refusing to report a result the packed scan did not "
                "contribute to.")
        return NodeMap(), (
            "packed-value scan OFF -- no node map configured, so an address "
            "present in a\n         binary ONLY as raw 4/16 bytes is NOT checked. "
            "Text runs still are.\n         Wire it once per clone:  git config "
            "ipscrub.nodeMap <path OUTSIDE this repo>")

    nm = load_node_map(path, repo, source)
    # COUNTS only. The values are the thing being protected; a status line that
    # printed them would be the disclosure, in the log of every push. The two
    # numbers differ because each IPv4 address is also searched for byte-
    # reversed, so encodings > addresses is expected, not a bug.
    return nm, ("packed-value scan ON -- %d address(es), %d encoding(s), from %s "
                "(values never printed)" % (nm.naddrs, len(nm), source))


def announce_packed(status):
    sys.stderr.write("ipscrub: %s\n" % status)


def _scan_packed(data, path, nodemap):
    """Exact packed-value hits only. See PACKED SCANNING, above."""
    findings = []

    # Node-map hits are NOT allowlist-checked. The allowlist means "reviewed
    # and safe to publish"; the node map means "this project's own address".
    # If a value is ever in both, the node map is the one that is right --
    # allowlisting your own node is the mistake the allowlist header forbids.
    if nodemap and len(nodemap):
        for packed, label in nodemap.packed.items():
            start = data.find(packed)
            # A 16-byte match is proof. A 4-byte one is targeted but not proof:
            # see the chance arithmetic under PACKED SCANNING. Say so where the
            # reader actually meets it, so nobody has to rediscover it -- and
            # still block, because confirming is a human step, not a silent one.
            corroborate = ("" if len(packed) == 16 else
                           " -- CONFIRM: a 4-byte match also arises by chance "
                           "about once per 180 MB scanned per address, so check "
                           "where it lands (compressed/encrypted payload = "
                           "noise; header, config, string table or DB page = "
                           "real)")
            while start >= 0:
                findings.append(Finding(
                    path, start, "<packed node address: %s>" % label,
                    "packed %d-byte form of a known node address at +0x%x%s"
                    % (len(packed), start, corroborate), 0,
                    KIND_V4 if len(packed) == 4 else KIND_V6, True))
                start = data.find(packed, start + 1)

    return findings


def scan_binary(data, path, allowlist, nodemap=None):
    """Scan a blob the text path would have skipped. Returns (findings, suppressed)."""
    if len(data) > MAX_BINARY_SCAN_BYTES:
        return [Finding(path, 0, "<oversized binary, %d byte(s)>" % len(data),
                        "binary blob too large to scan (cap %d bytes) -- refused "
                        "rather than assumed clean" % MAX_BINARY_SCAN_BYTES,
                        0, KIND_BINARY_EVIDENCE, True)], []

    findings, suppressed = [], []
    prev_text, prev_end, prev_stride = "", -1, 0
    for offset, run, stride in _binary_text_runs(data):
        # The ASCII pass and the UTF-16 pass each walk the blob from the start,
        # so "the previous run" is only meaningful within one pass. Reset at
        # the boundary rather than let the last ASCII run pose as the neighbour
        # of the first UTF-16 one.
        if stride != prev_stride:
            prev_text, prev_end, prev_stride = "", -1, stride
        # Is this run a version VALUE whose KEY was the run just before it?
        version_value = (
            BIN_BARE_QUAD_RE.match(run) is not None
            and 0 <= offset - prev_end <= BIN_VERSION_GAP
            and _ends_with_version_key(prev_text))
        prev_text, prev_end = run, offset + len(run) * stride
        if version_value:
            continue

        f, s = scan_text(run, path, allowlist)
        for hit in f + s:
            # `column` is the offset of the match within the run, so it locates
            # THIS occurrence -- searching by value would collapse repeats onto
            # the first one and mislocate every later hit.
            start = hit.column
            end = start + len(hit.ip)
            hit.lineno = offset + start * stride
            hit.binary = True
            hit.glued = _is_glued(run, start, end)
        # A glued hit is dropped outright, not merely "suppressed": listing 96
        # Go symbol names as suppressed noise on every run trains people to
        # stop reading the report at all.
        findings.extend(h for h in f if not h.glued)
        suppressed.extend(h for h in s if not h.glued)

    findings.extend(_scan_packed(data, path, nodemap))
    return findings, suppressed


# ==========================================================================
# Allowlist
# ==========================================================================

class Allowlist:
    """Reviewed addresses and CIDR blocks judged safe to leave in the clear.

    CIDR support is new here: `wins_vpn` builds firewall rules from published
    provider ingress ranges, and enumerating them one address at a time would
    be both unreadable and wrong.
    """

    def __init__(self):
        self.hosts = set()
        self.nets = []

    def add(self, token):
        if "/" in token:
            try:
                self.nets.append(ipaddress.ip_network(token, strict=False))
                return True
            except ValueError:
                return False
        ip = normalize_quad(token)
        if ip is None:
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                return False
        self.hosts.add(str(ip))
        return True

    def contains(self, ip):
        if str(ip) in self.hosts:
            return True
        for n in self.nets:
            if ip.version == n.version and ip in n:
                return True
        return False

    def __len__(self):
        return len(self.hosts) + len(self.nets)


def load_allowlist(path):
    allow = Allowlist()
    if not path or not os.path.exists(path):
        return allow
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            tok = line.split("#", 1)[0].strip()
            if not tok:
                continue
            if not allow.add(tok.split()[0]):
                sys.stderr.write("ipscrub: allowlist: ignoring %r\n" % tok)
    return allow


# ==========================================================================
# Git plumbing
# ==========================================================================

def git(repo, *args):
    out = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, check=False)
    if out.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (
            " ".join(args), out.stderr.decode("utf-8", "replace").strip()))
    return out.stdout


def repo_root(start):
    out = subprocess.run(["git", "-C", start, "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise SystemExit("ipscrub: %s is not inside a git repository" % start)
    return out.stdout.strip()


def tracked_files(repo):
    raw = git(repo, "ls-files", "-z").decode("utf-8", "replace")
    return [f for f in raw.split("\0") if f]


def scan_worktree(repo, allowlist, nodemap=None):
    findings, suppressed = [], []
    for rel in tracked_files(repo):
        p = os.path.join(repo, rel)
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if looks_binary(data):
            if is_evidence_path(rel):
                # Already refused on the strongest ground there is -- where it
                # sits. Reading its bytes too would only add detail to a
                # verdict that cannot change.
                findings.append(binary_evidence_finding(rel, len(data)))
            else:
                f, s = scan_binary(data, rel, allowlist, nodemap)
                findings.extend(f)
                suppressed.extend(s)
            continue
        f, s = scan_text(decode(data), rel, allowlist)
        findings.extend(f)
        suppressed.extend(s)
    return findings, suppressed


def scan_objects(repo, positive, negative, allowlist, nodemap=None):
    """Scan every unique blob reachable from `positive` but not `negative`.

    Objects, not final trees: a redaction commit layered on top leaves the
    original blob reachable from the tip being pushed, and it would still be
    uploaded. It must not satisfy this gate.
    """
    args = ["rev-list", "--objects"] + list(positive)
    if negative:
        args += ["--not"] + list(negative)
    raw = git(repo, *args).decode("utf-8", "replace")

    blobs = {}
    for line in raw.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue  # commit / object with no path
        blobs.setdefault(parts[0], parts[1])
    if not blobs:
        return [], [], 0

    order = list(blobs)
    check = subprocess.run(
        ["git", "-C", repo, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input="\n".join(order).encode(), capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")
    wanted = [ln.split()[0] for ln in check.splitlines()
              if len(ln.split()) >= 2 and ln.split()[1] == "blob"]
    if not wanted:
        return [], [], 0

    stream = subprocess.run(["git", "-C", repo, "cat-file", "--batch"],
                            input="\n".join(wanted).encode(),
                            capture_output=True, check=True).stdout

    findings, suppressed = [], []
    pos, n = 0, 0
    while pos < len(stream):
        nl = stream.find(b"\n", pos)
        if nl < 0:
            break
        header = stream[pos:nl].decode("utf-8", "replace").split()
        if len(header) < 3:
            break
        sha, size = header[0], int(header[2])
        body = stream[nl + 1: nl + 1 + size]
        pos = nl + 1 + size + 1
        n += 1
        if looks_binary(body):
            # NOT a silent skip any more. See "Evidence paths", above, and
            # "Raw-byte scanning of binary blobs" for the complement: a blob
            # off an evidence path is now READ, not waved through.
            path = blobs.get(sha, sha)
            if is_evidence_path(path):
                findings.append(binary_evidence_finding(path, size))
            else:
                f, s = scan_binary(body, path, allowlist, nodemap)
                findings.extend(f)
                suppressed.extend(s)
            continue
        f, s = scan_text(decode(body), blobs.get(sha, sha), allowlist)
        findings.extend(f)
        suppressed.extend(s)
    return findings, suppressed, n


# ==========================================================================
# Reporting
# ==========================================================================

BAR = "=" * 72
KIND_LABEL = {
    KIND_V4: "IPv4 infrastructure address",
    KIND_V6: "IPv6 infrastructure address",
    KIND_WG_SECRET: "WireGuard private/preshared key",
    KIND_WG_PUBLIC: "WireGuard public key",
    KIND_BINARY_EVIDENCE: "Unscannable binary on an evidence path",
}


def report(findings, suppressed, stream, show_suppressed, header, hint):
    by_file = {}
    for f in findings:
        by_file.setdefault(f.path, []).append(f)
    distinct = sorted({f.ip for f in findings})
    stream.write("\n%s\n%s\n%s\n" % (BAR, header, BAR))
    stream.write("%d occurrence(s), %d distinct value(s), %d file(s).\n" %
                 (len(findings), len(distinct), len(by_file)))
    counts = {}
    for f in findings:
        counts[f.kind] = counts.get(f.kind, 0) + 1
    for k in (KIND_V4, KIND_V6, KIND_WG_SECRET, KIND_WG_PUBLIC,
              KIND_BINARY_EVIDENCE):
        if counts.get(k):
            stream.write("    %-32s %d\n" % (KIND_LABEL[k] + ":", counts[k]))
    stream.write("\n")
    for path in sorted(by_file):
        rows = by_file[path]
        stream.write("  %s  (%d hit(s))\n" % (path, len(rows)))
        for r in rows[:3]:
            where = ("byte +0x%-4x" % r.lineno) if r.binary else ("line %-6d" % r.lineno)
            stream.write("      %s %s\n" % (where, r.excerpt()))
        if len(rows) > 3:
            stream.write("      ... %d more in this file\n" % (len(rows) - 3))
    if suppressed:
        stream.write("\n  (%d non-address literal(s) suppressed: version quads / "
                     "library versions / ASN.1 OIDs / digest hashes%s)\n" %
                     (len(suppressed), "" if show_suppressed else
                      "; --show-suppressed to list"))
        if show_suppressed:
            for r in suppressed:
                stream.write("      %s:%d  %s  <- %s\n" %
                             (r.path, r.lineno, r.ip, r.excerpt()))
    if hint:
        stream.write("\n%s\n" % hint)
    stream.write("%s\n" % BAR)


HINT = (
    "  How to proceed:\n"
    "    * See everything the push would upload:\n"
    "        python3 tools/ipscrub/ipscrub.py prepush-preview --ref <branch>\n"
    "    * Replace real addresses with the project placeholders\n"
    "      (<KANSAS_IP>, <NODE_ES_IP>, <OPERATOR_WAN>, <STAGING_HUB_SSLTIP_HOST>),\n"
    "      then push again.\n"
    "    * A redaction commit layered on top does NOT help: the original blob\n"
    "      is still reachable from the tip you are pushing and still uploads.\n"
    "    * If a value is genuinely publishable (a provider's published range, a\n"
    "      public resolver), add it to tools/ipscrub/ipscrub-allowlist.txt WITH\n"
    "      A REASON -- that is the TRACKED copy, and editing the .git/hooks/\n"
    "      copy instead would help you once and nobody else ever.\n"
    "      Never allowlist one of this project's own node addresses.\n"
    "    * For an 'Unscannable binary on an evidence path' finding there is no\n"
    "      scrub: a .pcap carries its addresses in IP headers with checksums\n"
    "      over them, so rewriting it manufactures a new file rather than\n"
    "      redacting one. Take the bundle OUT of the commit instead -- record\n"
    "      its sha256 manifest, move the bytes byte-exact into the no-remote\n"
    "      archive repo, and cite it by manifest hash. There is no allowlist\n"
    "      entry for this finding class, on purpose."
)


# ==========================================================================
# Commands
# ==========================================================================

ZERO_RE = re.compile(r"^0+$")


def _split_findings(findings):
    blocking = [f for f in findings if f.kind in BLOCKING_KINDS]
    warnings = [f for f in findings if f.kind not in BLOCKING_KINDS]
    return blocking, warnings


def _dedupe(findings):
    combined = {}
    for f in findings:
        combined.setdefault((f.path, f.lineno, f.column, f.ip), f)
    return list(combined.values())


def _negative_refs(repo, remote):
    """Everything the remote is already known to have.

    Uses remote-tracking refs, which are only as fresh as the last fetch. That
    is the conservative direction: a stale ref means we scan MORE than we had
    to, never less.
    """
    neg = ["--remotes=%s" % remote] if remote else ["--remotes"]
    return neg


def cmd_prepush(args):
    """git pre-push gate. Non-zero exit aborts the push."""
    repo = repo_root(args.repo or ".")
    allowlist = load_allowlist(args.allowlist)
    remote = args.remote_name or "origin"

    if sys.stdin.isatty():
        lines = []
    else:
        lines = [ln for ln in sys.stdin.read().splitlines() if ln.strip()]

    positive, negative = [], []
    for ln in lines:
        parts = ln.split()
        if len(parts) < 4:
            continue
        local_sha, remote_sha = parts[1], parts[3]
        if ZERO_RE.match(local_sha):
            continue  # branch deletion: uploads nothing
        positive.append(local_sha)
        if not ZERO_RE.match(remote_sha):
            negative.append(remote_sha)

    if not positive and lines:
        print("ipscrub: pre-push OK -- deletions only, nothing is uploaded.")
        return 0

    if not positive:
        # FAIL CLOSED, but usefully. Empty stdin has two causes that look
        # identical from here: git found nothing to push (it still runs the
        # hook, then prints "Everything up-to-date"), or the ref list was
        # unreadable. Blanket-refusing turns every harmless no-op push into an
        # error, and a gate that errors on no-ops is a gate someone deletes.
        #
        # So resolve the uncertainty by assuming the WORST case instead of
        # guessing the best: scan every local ref that is not already on the
        # remote -- a superset of anything any single push could upload. Clean
        # means no push from this checkout could disclose anything; dirty
        # blocks. That is conservative in the direction that matters.
        sys.stderr.write(
            "ipscrub: no ref list on stdin -- scanning EVERY local ref not yet on\n"
            "         '%s' instead, which is a superset of any single push.\n" % remote)
        positive = ["--all"]

    nodemap, packed_status = resolve_node_map(args, repo)
    announce_packed(packed_status)
    negative += _negative_refs(repo, remote)
    findings, suppressed, nblobs = scan_objects(repo, positive, negative, allowlist,
                                                nodemap)
    findings = _dedupe(findings)
    blocking, warnings = _split_findings(findings)

    if warnings:
        sys.stderr.write(
            "\nipscrub: NOTE -- %d WireGuard public key(s) in %d file(s) would be\n"
            "uploaded. Public keys are not secrets; they become disclosive when\n"
            "tabulated next to a node address, and addresses are blocked below.\n"
            "Not blocking on this.\n" % (len(warnings), len({w.path for w in warnings})))
        for w in warnings[:5]:
            sys.stderr.write("    %s:%d\n" % (w.path, w.lineno))
        if len(warnings) > 5:
            sys.stderr.write("    ... %d more\n" % (len(warnings) - 5))

    if not blocking:
        print("ipscrub: pre-push OK -- %d newly-uploaded blob(s) scanned, "
              "no infrastructure addresses or key material." % nblobs)
        return 0

    report(blocking, suppressed, sys.stderr, args.show_suppressed,
           "PUSH BLOCKED -- ipscrub found infrastructure addresses in what this "
           "push would\n                UPLOAD (%d new blob(s) scanned)" % nblobs,
           HINT)
    sys.stderr.write(
        "\nThese are objects the remote does NOT already have. Blocked.\n"
        "To override you must knowingly set IPSCRUB_ALLOW_PUSH=1, which is a\n"
        "decision to publish these values on GitHub.\n")
    return 1


def cmd_prepush_preview(args):
    """Same computation as the gate, driven from a ref instead of git's stdin."""
    repo = repo_root(args.repo or ".")
    allowlist = load_allowlist(args.allowlist)
    remote = args.remote_name or "origin"
    ref = args.ref or "HEAD"
    sha = git(repo, "rev-parse", ref).decode().strip()
    nodemap, packed_status = resolve_node_map(args, repo)
    announce_packed(packed_status)
    negative = _negative_refs(repo, remote)
    findings, suppressed, nblobs = scan_objects(repo, [sha], negative, allowlist,
                                                nodemap)
    findings = _dedupe(findings)
    blocking, warnings = _split_findings(findings)
    print("ipscrub: preview of `git push %s %s` -- %d blob(s) new to the remote"
          % (remote, ref, nblobs))
    if warnings:
        print("         %d WireGuard public key occurrence(s) (warn only)" % len(warnings))
    if not blocking:
        print("ipscrub: clean -- this push would upload no infrastructure addresses.")
        return 0
    report(blocking, suppressed, sys.stdout, args.show_suppressed,
           "ipscrub: ADDRESSES THIS PUSH WOULD UPLOAD", HINT)
    return 1


def cmd_scan(args):
    repo = repo_root(args.repo or ".")
    allowlist = load_allowlist(args.allowlist)
    nodemap, packed_status = resolve_node_map(args, repo)
    announce_packed(packed_status)
    findings, suppressed = scan_worktree(repo, allowlist, nodemap)
    findings = _dedupe(findings)
    blocking, warnings = _split_findings(findings)
    if warnings:
        print("ipscrub: %d WireGuard public key occurrence(s) (warn only)" % len(warnings))
    if not blocking:
        print("ipscrub: clean -- %d tracked file(s), no unscrubbed addresses.%s"
              % (len(tracked_files(repo)),
                 " (%d suppressed)" % len(suppressed) if suppressed else ""))
        return 0
    report(blocking, suppressed, sys.stdout, args.show_suppressed,
           "ipscrub: UNSCRUBBED INFRASTRUCTURE ADDRESSES IN TRACKED FILES", HINT)
    return 1


def cmd_scan_paths(args):
    """Scan explicit files on disk. Used to verify a scrub."""
    allowlist = load_allowlist(args.allowlist)
    try:
        repo = repo_root(args.repo or ".")
    except SystemExit:
        repo = None          # scan-paths is the one command that need not be in a repo
    nodemap, packed_status = resolve_node_map(args, repo)
    announce_packed(packed_status)
    findings, suppressed = [], []
    for p in args.paths:
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError as e:
            sys.stderr.write("ipscrub: %s: %s\n" % (p, e))
            return 2
        if looks_binary(data):
            if is_evidence_path(p):
                findings.append(binary_evidence_finding(p, len(data)))
            else:
                f, s = scan_binary(data, p, allowlist, nodemap)
                findings.extend(f)
                suppressed.extend(s)
            continue
        f, s = scan_text(decode(data), p, allowlist)
        findings.extend(f)
        suppressed.extend(s)
    blocking, warnings = _split_findings(_dedupe(findings))
    if warnings:
        print("ipscrub: %d WireGuard public key occurrence(s) (warn only)" % len(warnings))
    if not blocking:
        print("ipscrub: clean -- %d path(s), no infrastructure addresses.%s"
              % (len(args.paths),
                 " (%d suppressed)" % len(suppressed) if suppressed else ""))
        return 0
    report(blocking, suppressed, sys.stdout, args.show_suppressed,
           "ipscrub: ADDRESSES IN THE GIVEN PATHS", None)
    return 1


def cmd_node_map_status(args):
    """Is the packed scan armed in this checkout, and from where?

    Exists so the answer is a command instead of an inference. The packed path
    spent its whole life off in every checkout while every scan printed
    'clean'; the fix for that is not only announcing it during a scan but
    making it directly askable, including from install-hooks.sh.
    """
    try:
        repo = repo_root(args.repo or ".")
    except SystemExit:
        repo = None
    nm, status = resolve_node_map(args, repo)
    print("ipscrub: %s" % status)
    return 0 if len(nm) else 1


def cmd_scan_history(args):
    repo = repo_root(args.repo or ".")
    allowlist = load_allowlist(args.allowlist)
    nodemap, packed_status = resolve_node_map(args, repo)
    announce_packed(packed_status)
    findings, suppressed, nblobs = scan_objects(
        repo, args.revs or ["--all"], args.not_revs or [], allowlist, nodemap)
    blocking, warnings = _split_findings(_dedupe(findings))
    if warnings:
        print("ipscrub: %d WireGuard public key occurrence(s) (warn only)" % len(warnings))
    if not blocking:
        print("ipscrub: clean -- %d blob(s), no infrastructure addresses." % nblobs)
        return 0
    report(blocking, suppressed, sys.stdout, args.show_suppressed,
           "ipscrub: ADDRESSES IN %d BLOB(S)" % nblobs, None)
    return 1


# ==========================================================================
# Self test
# ==========================================================================

def _host(*octets):
    """Assemble a stand-in address at run time.

    Written as tuples, not literals, for a specific reason: this file is
    scanned by the detector like any other. A routable literal here -- even an
    invented one -- would be a finding in every future scan, and a gate that
    cries wolf about its own test data is a gate that gets switched off.
    """
    return ".".join(str(o) for o in octets)


def _v6(*groups):
    return ":".join(groups)


# Stand-ins. None of these belong to this project.
H_HUB = _host(77, 88, 99, 111)
H_NODE = _host(55, 66, 77, 88)
H_WAN = _host(33, 44, 55, 66)
H_WORKER = _host(22, 33, 44, 55)
H_EXIT = _host(44, 55, 66, 77)
H_POD = _host(88, 99, 111, 122)
H_CTRL = _host(11, 22, 33, 44)
H_PADDED_A = _host("010", "008", "000", "001")   # normalises to private
H_PADDED_B = _host("052", "110", "002", "153")   # normalises to routable
H_OIDROOT = _host(2, 23, 140, 1)                 # OID root arc, first octet <= 2
H_OID4 = _host(2, 5, 29, 37)                     # four-component OID

# --- the three shapes added 2026-08-07, all measured in this repository -----
# Assembled, never written as literals, for the reason `_host` documents.
H_X520_C = _host(2, 5, 4, 6)                     # X.520 countryName, a DN-map key
H_CABF_EV = H_OIDROOT + ".2.2"                   # six-arc CA/B Forum policy OID
H_CABF_EV5 = H_OIDROOT + ".1"                    # five-arc EV policy OID
H_UNREG_5 = _host(2, 5, 40, 6) + ".1"            # five arcs, but no registered arc
# Root arc <= 2 and one digit away from the X.520 arc `2.5.4.` -- but `2.5.40`
# is not under it, because the registered prefixes are dot-terminated. The
# first attempt at this discriminator used the canonical example quad, which
# turned out to be ALLOWLISTED, so the case could never have flagged and the
# rule it was meant to bound went unbounded. Checked against the allowlist.
H_UNREG_KEY = _host(2, 5, 40, 6)
SWIFTLANG = "swiftlang-%s.3" % _host(6, 3, 3, 1)  # Apple Swift toolchain stamp
UA_CHROME = "HeadlessChrome/%s" % _host(150, 0, 0, 0)  # Chrome UA reduction

# Paths for the evidence-path predicate, which is checked separately below
# because it is about WHERE a blob sits, not what a line says.
# (expected, path, why)
EVIDENCE_PATH_CASES = [
    (True, "winn_protocol_experimental/winn_protocol_experimental/evidence/"
           "leak-v2-acceptance-20260724/client-captures/failed-batch-4/"
           "v4-graceful-0ac1a5e5bfb1/client.pcap",
     "the doubled path that actually pushed three pcaps to GitHub"),
    (True, "winn_protocol_experimental/evidence/leak-v2/sockets.txt",
     "the primary evidence tree"),
    (True, "winn_protocol_experimental/.e8_linux_evidence_20260802/e8_verbose.bin",
     "sibling evidence drop, the shape .gitignore now also covers"),
    (True, "captures/probe.pcapng", "a capture by suffix, outside any evidence dir"),
    (True, "a/b/EVIDENCE/c.bin", "directory match is case-insensitive"),
    (False, "android/app/src/main/res/mipmap-hdpi/ic_launcher.png",
     "an app icon is a binary, and must still skip silently"),
    (False, "android/app/src/debug/jniLibs/arm64-v8a/libwinnengine.so",
     "a build artifact must still skip -- refusing it would make the gate noise"),
    (False, "winn_protocol_experimental/spikes/ios_maximum_privacy/evidenceverify/x.go",
     "`evidenceverify` is source; the rule matches the DIRECTORY `evidence`"),
    (False, "docs/handoff/EVIDENCE_NOTES.md",
     "a filename containing the word is not an evidence directory"),
]

V6_HUB = _v6("2a01", "4f8", "c17", "1234", "", "1")
V6_NODE = _v6("2606", "50c0", "8000", "", "153")
V6_ULA = _v6("fd00", "", "1")
V6_LL = _v6("fe80", "", "1c2b", "3d4e", "5f60", "7a8b")
V6_DOC = _v6("2001", "db8", "", "1")
V6_CF = _v6("2606", "4700", "4700", "", "1111")
V6_GOOG = _v6("2001", "4860", "4860", "", "8888")
V6_FULL = _v6("2a02", "26f0", "1700", "0011", "0000", "0000", "0000", "0abc")

WG_PUB = ("A" * 21 + "b7Kd9QzXm2VpLr4TgH6" + "sN3")[:43] + "="
WG_PUB2 = ("Zq" + "8" * 20 + "cV1nR5tYuI0pAsDfGhJ" + "kL")[:43] + "="
assert len(WG_PUB) == 44 and len(WG_PUB2) == 44, (len(WG_PUB), len(WG_PUB2))


# --- binary blobs, added 2026-08-07 with the raw-byte scanner ---------------
# Assembled from the same stand-ins for the same reason `_host` documents: a
# routable literal in this file would be a finding in every future scan.
H_BIN = _host(66, 77, 88, 99)        # carried inside a binary as ASCII
H_BIN_W = _host(99, 88, 77, 66)      # carried as UTF-16LE, Windows style
H_BIN_PACKED = _host(44, 33, 22, 11)  # only ever present in packed form
H_BIN_VER = _host(1, 3, 0, 0)        # a VERSIONINFO value, not an address

# --- the dashed-quad hostname shape, added 2026-08-22 ------------------------
# Assembled with `.replace`, never written as literals: a dashed literal here
# would be a finding in every future scan of this file, for the same reason
# `_host` documents.
H_DASH = _host(66, 77, 88, 99).replace(".", "-")        # routable, unflagged elsewhere
H_PRIV_DASH = _host(192, 168, 50, 1).replace(".", "-")  # decodes PRIVATE
H_ALLOW_DASH = _host(1, 1, 1, 1).replace(".", "-")      # decodes to an allowlisted resolver


def _utf16(s):
    return s.encode("ascii").decode("ascii").encode("utf-16-le")


def _packed(addr):
    return ipaddress.IPv4Address(addr).packed


# (expect_flag, blob, why)
BINARY_CASES = [
    # --- MUST flag: an address a binary really is carrying -------------------
    (True, b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 24 +
     ("default_endpoint=%s:51820" % H_BIN).encode() + b"\x00" * 32,
     "shared object with an endpoint string -- the residual hole itself"),
    (True, b"SQLite format 3\x00" + b"\x00" * 60 + H_BIN.encode() + b"\x00" * 20,
     "bare address alone in a SQLite cell, delimited by NULs"),
    (True, b"MZ\x90\x00" + b"\x00" * 40 + _utf16("Endpoint = %s:51820" % H_BIN_W) +
     b"\x00" * 16,
     "UTF-16LE string in a Windows binary"),
    (True, b"\x00" * 8 + ("[%s]:9110" % V6_NODE).encode() + b"\x00" * 8,
     "bracketed IPv6 endpoint inside a blob"),
    (True, b"Exif\x00\x00" + b"\x00" * 30 + ("GPSHost=%s" % H_BIN).encode() +
     b"\x00" * 10,
     "an image's EXIF tag is just another string run"),

    # --- MUST NOT flag: the manufactured shapes, measured on this repo -------
    (False, b"\x00" * 16 + ("crypto/tls.(*SessionState).Bytes.marshal.func%s"
                            % _host(1, 1, 1, 1)).encode() + b"\x00" * 16,
     "Go closure symbol name -- 96 of the 106 false hits measured here"),
    (False, b"\x00" * 16 + ("spdy/3spdy/%su=0, iu=1, i" % H_BIN).encode() +
     b"\x00" * 16,
     "two string-table entries fused into a quad that never existed"),
    (False, b"\x00" * 16 + ("%smap[%%s]%%sMediaStop" % H_BIN).encode() + b"\x00" * 16,
     "run beginning mid-table, quad welded to the next entry"),
    (False, b"VS_VERSION_INFO\x00" + _utf16("FileVersion") + b"\x00\x00" +
     _utf16(H_BIN_VER) + b"\x00\x00",
     "Windows VERSIONINFO: the key is a SEPARATE string from its value"),
    (False, b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8,
     "an app icon must still pass -- blocking one gets the gate switched off"),

    # --- MUST NOT flag: packed bytes with no node map ------------------------
    # This pins the rejected sockaddr heuristic. It is a REGRESSION GUARD: if
    # somebody re-adds a structural packed rule, this case fails and tells them
    # to go read why it was removed before they ship 840 false hits again.
    (False, b"\x02\x00" + b"\xca\x6c" + _packed(H_BIN_PACKED) + b"\x00" * 32,
     "packed sockaddr_in shape alone is NOT evidence -- see PACKED SCANNING"),
    # 2026-08-07, second pass: the guard above was verified to fire by actually
    # re-adding the rejected rule in a scratch copy -- and that exercise showed
    # it only covers ONE of the three serialisations. It is written Linux-style,
    # AF_INET as a little-endian 16-bit family. A re-adder who matched the
    # BSD/macOS `\x10\x02` length+family prefix, or a big-endian `\x00\x02`,
    # would sail past it and ship the same 840 false hits. Both shapes pinned.
    (False, b"\x10\x02" + b"\xca\x6c" + _packed(H_BIN_PACKED) + b"\x00" * 32,
     "BSD/macOS sockaddr_in (len byte + family) is not evidence either"),
    (False, b"\x00\x02" + b"\x00\x35" + _packed(H_BIN_PACKED) + b"\x00" * 32,
     "big-endian AF_INET + port 53 -- the exact shape that produced 758 of 840"),
    (False, _packed(H_BIN_PACKED) * 64,
     "raw packed bytes without a node map must never flag"),

    # --- the xray triage, pinned so it cannot silently un-decide -------------
    # These are the two distinct values behind the 6 findings the binary scan
    # reported against the vendored Xray-core blobs on 2026-08-07, in the exact
    # Go string-table runs they were measured in. They are c.root-servers.net,
    # they are upstream's own constants, and they are now allowlisted with the
    # evidence written into the allowlist entry.
    #
    # Written as literals here on purpose. That is what the resolver cases in
    # SELFTEST_CASES do, and it is safe for the same reason: an allowlisted
    # value cannot make this file a finding. It also COUPLES the two -- delete
    # the allowlist entry and these cases fail, so the decision cannot rot into
    # a value nobody can account for.
    (False, b"\x00" * 8 + b"xray.mph.cache%s(DNS idx:%d)192.33.4.12:53"
            b"Logger startedLogger closing" + b"\x00" * 8,
     "c.root-servers.net in upstream Xray-core's app/dns.checkRoutes run"),
    (False, b"\x00" * 8 + b"default route for  IP(s) for domain "
            b"[2001:500:2::c]:53. Try to unwrap it" + b"\x00" * 8,
     "the same probe's IPv6 root-server literal, bracketed with a port"),

    # ...and the discriminators. The allowlist entries are HOST entries, not a
    # widened rule: the identical run shape carrying anything else must still
    # block. Without these two the triage above would be indistinguishable from
    # having quietly stopped scanning that shape.
    (True, b"\x00" * 8 + ("xray.mph.cache%%s(DNS idx:%%d)%s:53"
                          "Logger startedLogger closing" % H_BIN).encode() + b"\x00" * 8,
     "same run shape, an address that is NOT the root server -> still flags"),
    (True, b"\x00" * 8 + ("default route for  IP(s) for domain [%s]:53. "
                          "Try to unwrap it" % V6_NODE).encode() + b"\x00" * 8,
     "same IPv6 run shape, a node address instead -> still flags"),
]

# Where a node map may live. (expected_inside, path, repo, why)
#
# The one rule the node map has, tested as a pure predicate so both directions
# are cheap: the file lists this project's real addresses, so a copy inside the
# repository -- placed there in order to detect those addresses in the
# repository -- would BE the disclosure the gate exists to prevent.
NODE_MAP_PATH_CASES = [
    (True, "/r/tools/ipscrub/node-map.txt", "/r",
     "the tempting place to put it is the one place it must never go"),
    (True, "/r/.git/node-map.txt", "/r",
     "inside .git is still inside the repo -- untracked is not the same as outside"),
    (False, "/home/u/Documents/wins/docs/node-map.txt", "/home/u/Documents/wins/source/wins_vpn",
     "the no-remote archive, which is where it actually lives"),
    (False, "/parent/wins_vpn_notes/node-map.txt", "/parent/wins_vpn",
     "a SIBLING sharing a name prefix is not inside -- compared by component"),
    (False, "/r/../outside/node-map.txt", "/r",
     "`..` is normalised before comparing, so traversal cannot fake containment"),
    (False, "/r", "/r",
     "the repo root itself is not a file inside the repo"),
]

# (text, should_flag, why)
SELFTEST_CASES = [
    # --- MUST flag: routable IPv4, in the forms the corpus uses --------------
    ("Hub: primary `%s`" % H_HUB, True, "address in prose"),
    ("**On the hub (root@%s) - deployment happened here**" % H_HUB, True, "after root@"),
    ("%s was dropped at the provider edge" % H_NODE, True, "address at line start"),
    ("probe `%s:9110` from two networks" % H_NODE, True, "address with port"),
    ("00:31:30.02 ens6 In IP %s.50210 > %s.80: Flags [S]" % (H_HUB, H_NODE),
     True, "tcpdump host.port form, both endpoints"),
    ("From the laptop's WAN address `%s`." % H_WAN, True, "trailing sentence period"),
    ("ssh -i ~/.ssh/k root@%s" % H_WORKER, True, "ssh target"),
    ("| `exit-node` | UpCloud | %s |" % H_EXIT, True, "markdown table cell"),
    ("connect to host %s port 10788" % H_POD, True, "pod address"),
    ("endpoint=%s:51820 \\" % H_CTRL, True, "shell assignment"),
    ("allow from %s/32" % H_NODE, True, "CIDR host route must still flag"),
    ("%s and %s" % (H_PADDED_A, H_PADDED_B), True, "leading zeros normalise"),
    ('"endpoint":"%s:9110"' % H_NODE, True, "JSON fixture endpoint"),

    # --- MUST flag: routable IPv6 (NEW) --------------------------------------
    ("AAAA record for the hub is %s" % V6_HUB, True, "IPv6 in prose"),
    ("Endpoint = [%s]:51820" % V6_NODE, True, "bracketed IPv6 with port"),
    ("ssh root@%s" % V6_HUB, True, "IPv6 ssh target"),
    ("| madrid | IONOS | %s |" % V6_NODE, True, "IPv6 in a markdown table"),
    ("route add %s/128 dev wg0" % V6_HUB, True, "IPv6 host route"),
    ("uncompressed %s in a capture" % V6_FULL, True, "full eight-group IPv6"),
    ("IP6 %s.51820 > %s.9110: UDP" % (V6_HUB, V6_NODE), True,
     "tcpdump IPv6 host.port form"),

    # --- MUST flag: WireGuard secrets (NEW) ----------------------------------
    ("PrivateKey = %s" % WG_PUB, True, "wg PrivateKey"),
    ("PresharedKey = %s" % WG_PUB2, True, "wg PresharedKey"),

    # --- MUST NOT flag: resolvers (allowlisted) ------------------------------
    ("nameserver 1.1.1.1", False, "Cloudflare resolver"),
    ("nameserver 1.0.0.1", False, "Cloudflare secondary"),
    ("dig @8.8.8.8 example.org", False, "Google resolver"),
    ("fallback 8.8.4.4", False, "Google secondary"),
    ("DNS=9.9.9.9 149.112.112.112", False, "Quad9 pair"),
    ("resolver %s" % V6_CF, False, "Cloudflare IPv6 resolver"),
    ("resolver %s" % V6_GOOG, False, "Google IPv6 resolver"),

    # --- MUST NOT flag: route math -------------------------------------------
    ("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1", False, "full-tunnel split-route pair"),
    ("AllowedIPs = ::/1, 8000::/1", False, "IPv6 full-tunnel split pair"),
    ("global unicast is 2000::/3", False, "IPv6 block named in prose"),
    ("64.0.0.0/2 is arithmetic, not a host", False, "short v4 prefix base"),

    # --- and the discriminators that keep the route-prefix rule safe ----------
    ("allow from %s/8" % H_NODE, True, "/8 is not short enough to be route math"),
    ("route %s/2 via wg0" % H_NODE, True,
     "short prefix but NOT the block base -> still flagged"),
    ("peer %s/128 dev wg0" % V6_HUB, True, "IPv6 host route still flagged"),

    # --- MUST NOT flag: not addresses at all ---------------------------------
    ("DriverVer = 03/25/2026,1.3.0.0", False, "INF version quad"),
    ("Installed v1.2.3.4 of the bundle", False, "bare v-prefixed version"),
    ("FileVersion: 10.0.22621.1", False, "5-component version"),
    ("version = 4.8.1.1", False, "keyword + digits only between"),
    ("rev: 2.0.0.1", False, "rev keyword"),
    ("ships its own CUDA 13 (`libcublas 13.1.1.3`, `libcudart 13.0.96`)", False,
     "bare library version, no version keyword"),
    ('guard installed == "wins_vpn.apple_packet_tunnel.v3.1.0.14.29.installed"',
     False, "version inside a dotted identifier"),
    ("2026.v1.2.3.4 is a date, not an identifier", False,
     "digit before the dot -- the .v rule must not apply"),
    ("github.com/amnezia-vpn/amneziawg-go v0.2.19 h1:%s" % WG_PUB, False,
     "go.sum dirhash, same 44-char shape, wg context word on the line"),
    ("bundled libggml 0.9.1.2 and libcudart 13.0.96", False, "two library versions"),
    ("Recorded 2026.08.06 in the log", False, "dotted date"),
    ("Session 20260806 at 00:40:29.711422", False, "compact date + timestamp"),
    ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
     False, "hex digest"),
    ("999.999.999.999 is not an address", False, "octets out of range"),
    ("build: 1.2.3.4.5", False, "five-component version"),
    ("ratio 1.5 vs 2.5", False, "plain decimals"),
    ("token 1.2.3.4.5.6 here", False, "six components match nothing"),
    ("aa:bb:cc:dd:ee:ff is a MAC address", False, "MAC is not valid IPv6"),
    ("SHA256 fingerprint AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:"
     "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89", False,
     "colon-hex fingerprint consumed whole, rejected"),
    ("started at 00:31:30.02 and ended 00:40:29", False, "timestamps"),
    ("using std::string and winrt::Windows::Foundation", False, "C++ namespaces"),

    # --- MUST NOT flag: non-global address space -----------------------------
    ("bind 127.0.0.1:8080", False, "loopback"),
    ("peer 10.8.1.6 allowed-ips 10.8.0.0/16", False, "RFC1918 /8"),
    ("gateway 192.168.50.1", False, "RFC1918 /16"),
    ("docker0 172.17.0.0/16", False, "RFC1918 /12"),
    ("listen 0.0.0.0:443", False, "unspecified"),
    ("APIPA 169.254.44.38", False, "link-local"),
    ("netmask 255.255.255.0 broadcast 255.255.255.255", False, "mask + broadcast"),
    ("example net 203.0.113.9 and 192.0.2.0/24", False, "TEST-NET documentation"),
    ("also 198.51.100.7 in the runbook", False, "TEST-NET-2 documentation"),
    ("CGNAT 100.64.0.1", False, "RFC6598 shared space"),
    ("mDNS 224.0.0.251", False, "multicast"),
    ("IP 10.8.1.6.51820 > 10.8.1.1.51820: UDP", False, "private endpoints with ports"),
    ("ULA peer %s" % V6_ULA, False, "IPv6 ULA"),
    ("link-local %s" % V6_LL, False, "IPv6 link-local"),
    ("docs example %s" % V6_DOC, False, "IPv6 documentation range"),
    ("bind [::1]:9110", False, "IPv6 loopback"),
    ("listen [::]:443", False, "IPv6 unspecified"),

    # --- MUST NOT flag: ASN.1 object identifiers ------------------------------
    ("EV policy OID `%s.1`, and SANs for three domains" % H_OIDROOT, False,
     "CA/Browser Forum EV policy arc, five components"),
    ("Where-Object { $_.Oid.Value -eq '%s' }" % H_OID4, False,
     "four-component OID -- the shape the docs version missed"),
    ("extendedKeyUsage 1.3.6.1.5.5.7.3.1", False, "EKU serverAuth OID"),

    # --- MUST NOT flag: digest base64 that looks exactly like a wg key --------
    ("integrity=\"sha256-%s\"" % WG_PUB, False, "SRI hash, same 44-char shape"),
    ("script-src 'self' 'sha256-%s'" % WG_PUB2, False, "CSP hash"),
    ("%s" % WG_PUB, False, "bare base64 with no key context is not a finding"),

    # --- the discriminators that keep the suppression rules safe --------------
    ("Version: node reachable at %s" % H_NODE, True,
     "version keyword present but LETTERS intervene -> still flagged"),
    ("server = %s" % H_HUB, True, "'server' must not be read as a 'ver' keyword"),
    ("the CUDA box at %s" % H_NODE, True,
     "library keyword present but LETTERS intervene -> still flagged"),
    ("libvirt guest reached %s" % H_HUB, True,
     "lib* keyword present but LETTERS intervene -> still flagged"),
    ("node %s is the Madrid exit" % H_NODE, True,
     "'node' is deliberately NOT a library keyword in this project"),
    ("TLS certificate seen in capture: IP %s.443 > 10.8.1.6.5122" % H_HUB, True,
     "'certificate' cannot suppress a first-octet > 2 address"),
    ("IP %s.443 > %s.9110: Flags [S]" % (H_OIDROOT, H_NODE), True,
     "OID-shaped octets in a capture, no OID context -> still flagged"),
    ("| madrid | %s | %s |" % (H_NODE, WG_PUB), True,
     "the address+key table: the address is what blocks"),

    # --- MUST NOT flag: the three shapes measured on 2026-08-07 --------------
    # 1. Bare X.500 OID map keys. 13 occurrences in internal/coverlisten/
    #    covercert.go and its test; the scoping pass ruled these need a
    #    SCANNER fix, not a scrub, because they really are OIDs.
    ('\t"%s":                    "countryName",' % H_X520_C, False,
     "X.520 DN map key in a Go literal -- no cert prose anywhere on the line"),
    ('  "%s": "extKeyUsage",' % H_OID4, False,
     "X.509 extension arc as a JSON map key"),
    ('"%s": "Organization Validation",' % H_CABF_EV, False,
     "six-arc CA/B Forum policy OID as a map key, truncated by QUAD_RE to four"),
    ('\tif !mentions(result.Identifying, "%s") {' % H_CABF_EV5, False,
     "five-arc OID as a bare argument -- covercert_test.go's actual shape"),
    # 2. The Apple Swift toolchain stamp. 47 occurrences.
    ("Toolchain observed: Apple Swift 6.3.3 (`%s`)." % SWIFTLANG, False,
     "swiftlang-N.N.N.N -- `clang` was covered, its sibling was not"),
    # 3. Browser user-agent product versions. 15 occurrences in webrtc.json.
    ('"userAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
     '(KHTML, like Gecko) %s Safari/537.36"' % UA_CHROME, False,
     "HeadlessChrome/N.0.0.0 -- Chrome UA reduction pins the last three to 0"),

    # --- and the discriminators that keep those three rules safe -------------
    ('"%s": "kansas"' % H_NODE, True,
     "an ADDRESS in map-key position: root arc > 2, so the OID rule cannot reach it"),
    ('"%s": "the exit node"' % H_UNREG_KEY, True,
     "root arc <= 2, quoted map key, one digit off a registered arc -> flagged"),
    ('"%s:9110": "endpoint"' % H_X520_C, True,
     "port inside the quotes is not map-key position -> still flagged"),
    ("%s," % H_X520_C, True,
     "the same OID unquoted and not a key -> still flagged, the rule is positional"),
    ('assertSeen("%s")' % H_UNREG_5, True,
     "five arcs and quoted, but under no registered arc -> still flagged"),
    ("IP %s.443 > %s.9110: Flags [S]" % (H_OIDROOT, H_NODE), True,
     "tcpdump host.port: five-arc run, but UNQUOTED -> still flagged"),
    ("swiftlang builds run on the box at %s" % H_NODE, True,
     "swiftlang keyword present but LETTERS intervene -> still flagged"),
    ("the Chrome box at %s" % H_NODE, True,
     "browser keyword present but no `/` before the quad -> still flagged"),
    ("Chrome/%s" % H_NODE, False,
     "and this is the shape the `/` bound deliberately does suppress"),

    # --- MUST flag / MUST NOT flag: dashed-quad hostnames (2026-08-22) -------
    ("curl -s https://%s.sslip.io/nodes" % H_DASH, True,
     "dashed-quad sslip.io URL -- an IPv4 address wearing a hostname"),
    ("ssh root@%s" % H_DASH, True, "bare dashed-quad ssh target"),
    ("scp root@%s:/etc/wg0.conf ." % H_DASH, True, "bare dashed-quad scp target"),
    ("WINS_HUB_HOST=%s" % H_DASH, True, "bare dashed quad in an assignment"),
    ("steps %s to publish" % H_DASH, False,
     "a bare dashed quad in prose is not a hostname"),
    ("gateway is %s.example.com" % H_PRIV_DASH, False,
     "a dashed-quad hostname that decodes PRIVATE is not flagged"),
    ("resolver %s.example.com" % H_ALLOW_DASH, False,
     "a dashed label decoding to an allowlisted value is not flagged"),
    ("window 2026-08-22-10 closes", False,
     "out-of-range octets are not an address, dashed or dotted"),
    ("web-1-2-3-4.example.com is ours", False,
     "a quad welded into a longer label is not the bare encoding"),

    # --- dashed version assignments: dotted-twin parity (2026-08-22 A1) -------
    ("VERSION=%s" % H_DASH, False,
     "a dashed version-keyword assignment suppresses like its dotted twin"),
    ("VER=%s" % H_DASH, False, "a dashed VER= quad is a version, not a host"),
    ("BUILD=%s" % H_DASH, False, "a dashed BUILD= quad is a version, not a host"),
    ("libcublas %s" % H_DASH, False,
     "a dashed library-version quad suppresses like its dotted twin"),
]


# Path-scoped JDK pin cases. The same quad must keep flagging outside the
# reviewed toolchain schema and in endpoint-like fields inside it.
TOOLCHAIN_PIN_VERSION_CASES = [
    ("tools/toolchain-pins.json", '{"version": "%s"}' % H_NODE, False,
     "reviewed JSON JDK version field"),
    ("tools/toolchain-pins.json",
     '{"darwin_arm64": "OpenJDK17U-jdk_aarch64_mac_hotspot_%s_1.tar.gz"}' % H_NODE,
     False, "reviewed OpenJDK archive filename"),
    ("tools/toolchain-pins.json", '{"endpoint": "%s"}' % H_NODE, True,
     "endpoint field in pins file must still flag"),
    ("other/toolchain.json", '{"version": "%s"}' % H_NODE, True,
     "version field outside reviewed pins path must still flag"),
]


def cmd_selftest(args):
    allowlist = load_allowlist(args.allowlist)
    if not len(allowlist):
        print("ipscrub: selftest needs the allowlist (--allowlist)", file=sys.stderr)
        return 2

    npass = nfail = 0
    failures = []
    print("%s\nipscrub detector self-test (both directions)\n%s" % (BAR, BAR))
    for text, expect_flag, why in SELFTEST_CASES:
        findings, _ = scan_text(text, "<selftest>", allowlist)
        got = bool([f for f in findings if f.kind in BLOCKING_KINDS])
        ok = (got == expect_flag)
        npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
        if not ok:
            failures.append((text, expect_flag, got, why))
        print("  %s  %-6s %-62s  %s" % ("PASS" if ok else "FAIL",
                                        "FLAG" if expect_flag else "clean",
                                        (text[:60] + "..") if len(text) > 62 else text,
                                        why))

    print("\n%s\ntoolchain-pin versions: path and schema must both match\n%s" % (BAR, BAR))
    for path, text, expect_flag, why in TOOLCHAIN_PIN_VERSION_CASES:
        findings, _ = scan_text(text, path, allowlist)
        got = bool([f for f in findings if f.kind in BLOCKING_KINDS])
        ok = (got == expect_flag)
        npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
        if not ok:
            failures.append((text, expect_flag, got, why))
        print("  %s  %-6s %-62s  %s" % ("PASS" if ok else "FAIL",
                                        "FLAG" if expect_flag else "clean",
                                        path, why))

    # A NOVEL address the detector has never been told about must still flag.
    # This is the property the whole design rests on: match by class, not list.
    print("\n%s\nnovel-address check: 40 addresses never seen by this tool\n%s" % (BAR, BAR))
    novel_fail = 0
    import random
    rnd = random.Random(20260807)
    for _ in range(40):
        a = rnd.randint(3, 223)
        if a in (10, 100, 127, 169, 172, 192, 198, 203, 224):
            a = 51
        cand = _host(a, rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(1, 254))
        ip = normalize_quad(cand)
        if not is_infrastructure_v4(ip) or allowlist.contains(ip):
            continue
        got, _ = scan_text("newly provisioned node at %s" % cand, "<novel>", allowlist)
        if got:
            npass += 1
        else:
            nfail += 1
            novel_fail += 1
            failures.append((cand, True, False, "novel address not detected"))
    print("  %s  %d novel addresses, %d missed" %
          ("PASS" if novel_fail == 0 else "FAIL", 40, novel_fail))

    # The binary blind spot, checked as a property of the PATH -- because that
    # is the only thing the gate knows about a blob it cannot read. Both
    # directions matter equally here: a rule that refuses everything binary
    # would be switched off within a day, and one that refuses nothing is the
    # gate we already had on 2026-08-03.
    print("\n%s\nevidence-path refusal: binaries the gate must not skip\n%s"
          % (BAR, BAR))
    for expect, path, why in EVIDENCE_PATH_CASES:
        got = is_evidence_path(path)
        ok = (got == expect)
        npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
        if not ok:
            failures.append((path, expect, got, why))
        shown = path if len(path) <= 62 else "..." + path[-59:]
        print("  %s  %-6s %-62s  %s" % ("PASS" if ok else "FAIL",
                                        "REFUSE" if expect else "skip",
                                        shown, why))

    # The residual hole: a binary that is NEITHER on an evidence path NOR
    # carrying a capture suffix. Before 2026-08-07 every one of these was
    # `continue`d unread. Both directions again, and the must-NOT-flag half is
    # the load-bearing one -- it is measured against the real shapes this
    # repository's 267 tracked binaries actually contain.
    print("\n%s\nraw-byte binary scan: blobs off any evidence path\n%s" % (BAR, BAR))
    for expect, blob, why in BINARY_CASES:
        f, _ = scan_binary(blob, "vendor/thing.bin", allowlist, None)
        got = bool([x for x in f if x.kind in BLOCKING_KINDS])
        ok = (got == expect)
        npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
        if not ok:
            failures.append((repr(blob[:48]), expect, got, why))
        print("  %s  %-6s %-62s  %s" % ("PASS" if ok else "FAIL",
                                        "FLAG" if expect else "clean",
                                        (why[:60] + "..") if len(why) > 62 else why,
                                        ""))

    # A node map turns the packed scan on, and the SAME bytes that must stay
    # clean without one must flag with one. Without this pair the packed path
    # could be dead code and nothing would say so.
    nm = NodeMap()
    nm.add(H_BIN_PACKED, "selftest node")
    packed_blob = b"\x00" * 32 + _packed(H_BIN_PACKED) + b"\x00" * 32

    # 2026-08-07, second pass: the v6 half of the packed path had never been
    # exercised, in the self-test or anywhere else -- the map that armed it for
    # the first time happens to contain both families, and a 16-byte encoding
    # is the ONLY packed hit that is proof rather than a lead. Paired the same
    # way, so a v6 regression cannot hide behind the v4 case passing.
    nm6 = NodeMap()
    nm6.add(V6_NODE, "selftest node v6")
    packed6 = b"\x00" * 32 + ipaddress.IPv6Address(V6_NODE).packed + b"\x00" * 32

    for width, blob, mapping_on in (("4-byte ", packed_blob, nm),
                                    ("16-byte", packed6, nm6)):
        for label, mapping, expect in (("without node map", None, False),
                                       ("with node map", mapping_on, True)):
            f, _ = scan_binary(blob, "vendor/thing.bin", allowlist, mapping)
            got = bool([x for x in f if x.kind in BLOCKING_KINDS])
            ok = (got == expect)
            npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
            if not ok:
                failures.append(("packed %s blob %s" % (width, label), expect, got,
                                 "node-map packed scan"))
            print("  %s  %-6s packed %s address, %-40s" %
                  ("PASS" if ok else "FAIL", "FLAG" if expect else "clean",
                   width, label))

    # Where the node map is allowed to live. Pure predicate, both directions.
    print("\n%s\nnode-map containment: the file must live OUTSIDE the repo\n%s"
          % (BAR, BAR))
    for expect, path, repo, why in NODE_MAP_PATH_CASES:
        got = node_map_inside_repo(path, repo)
        ok = (got == expect)
        npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
        if not ok:
            failures.append((path, expect, got, why))
        print("  %s  %-6s %-40s  %s" % ("PASS" if ok else "FAIL",
                                        "REFUSE" if expect else "allow",
                                        path, why))

    # The packed scan must never be quietly off. Until 2026-08-07 it was off in
    # every checkout and every scan still said "clean" -- so these four checks
    # are about the STATE being visible and a configured-but-broken map being
    # an error, not about detection.
    #
    # The ambient environment is neutralised first: an operator who has actually
    # wired a node map must not get self-test failures because of it, and the
    # checks are about resolution, not about this machine.
    print("\n%s\npacked-scan state: off must be LOUD, misconfigured must FAIL\n%s"
          % (BAR, BAR))

    class _Args(object):
        node_map = None
        require_node_map = False

    saved = {k: os.environ.pop(k, None)
             for k in ("IPSCRUB_NODE_MAP", "IPSCRUB_REQUIRE_NODE_MAP")}
    try:
        state_cases = []

        a = _Args()
        nm2, status = resolve_node_map(a, None)
        state_cases.append(("no node map announces OFF, and is empty",
                            "OFF" in status and len(nm2) == 0))

        a = _Args()
        a.require_node_map = True
        try:
            resolve_node_map(a, None)
            state_cases.append(("--require-node-map with none configured must FAIL", False))
        except RuntimeError:
            state_cases.append(("--require-node-map with none configured must FAIL", True))

        a = _Args()
        a.node_map = os.path.join("/r", "tools", "ipscrub", "node-map.txt")
        try:
            resolve_node_map(a, "/r")
            state_cases.append(("a node map INSIDE the repo must be refused", False))
        except RuntimeError:
            state_cases.append(("a node map INSIDE the repo must be refused", True))

        a = _Args()
        a.node_map = os.path.join(tempfile.gettempdir(),
                                  "ipscrub-selftest-absent-%d" % os.getpid())
        try:
            resolve_node_map(a, None)
            state_cases.append(("a configured map that does not exist must FAIL", False))
        except RuntimeError:
            state_cases.append(("a configured map that does not exist must FAIL", True))
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    for why, ok in state_cases:
        npass, nfail = (npass + 1, nfail) if ok else (npass, nfail + 1)
        if not ok:
            failures.append((why, True, False, "packed-scan state"))
        print("  %s  %s" % ("PASS" if ok else "FAIL", why))

    print("\n%s\n%d passed, %d failed\n%s" % (BAR, npass, nfail, BAR))
    for text, exp, got, why in failures:
        print("FAILED: %r expected=%s got=%s (%s)" % (text, exp, got, why))
    return 1 if nfail else 0


# ==========================================================================

def main(argv=None):
    p = argparse.ArgumentParser(prog="ipscrub")
    p.add_argument("--allowlist", help="path to the allowlist")
    p.add_argument("--node-map", help=(
        "path to a file of THIS PROJECT'S OWN addresses, used to search binary "
        "blobs for their packed 4/16-byte encodings. Keep it OUTSIDE this "
        "repository (the no-remote archive holds one already) -- a path inside "
        "the repo is REFUSED. Falls back to $IPSCRUB_NODE_MAP, then to "
        "`git config ipscrub.nodeMap`."))
    p.add_argument("--require-node-map", action="store_true", help=(
        "fail instead of running with the packed scan off. Use this wherever a "
        "green result is supposed to MEAN the packed scan ran; without it, no "
        "node map is a quiet partial scan. Also settable as "
        "$IPSCRUB_REQUIRE_NODE_MAP=1."))
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--repo", help="repository path (default: cwd)")
        sp.add_argument("--show-suppressed", action="store_true")
        return sp

    pp = common(sub.add_parser("prepush", help="fail-closed pre-push gate (reads git's stdin)"))
    pp.add_argument("--remote-name", help="remote being pushed to (default: origin)")
    pp.set_defaults(fn=cmd_prepush)

    pv = common(sub.add_parser("prepush-preview", help="what would `git push <ref>` upload?"))
    pv.add_argument("--ref", help="ref to preview (default: HEAD)")
    pv.add_argument("--remote-name", help="remote (default: origin)")
    pv.set_defaults(fn=cmd_prepush_preview)

    common(sub.add_parser("scan", help="scan tracked files in the working tree")).set_defaults(fn=cmd_scan)

    sp = common(sub.add_parser("scan-paths", help="scan explicit files on disk"))
    sp.add_argument("paths", nargs="+")
    sp.set_defaults(fn=cmd_scan_paths)

    sh = common(sub.add_parser("scan-history", help="scan blobs reachable from revs"))
    sh.add_argument("revs", nargs="*")
    sh.add_argument("--not-revs", nargs="*", help="exclude objects reachable from these")
    sh.set_defaults(fn=cmd_scan_history)

    nm = sub.add_parser("node-map-status",
                        help="is the packed scan armed here, and from which source?")
    nm.add_argument("--repo", help="repository path (default: cwd)")
    nm.set_defaults(fn=cmd_node_map_status)

    st = sub.add_parser("selftest", help="run the both-ways detector tests")
    st.set_defaults(fn=cmd_selftest)

    args = p.parse_args(argv)
    # The node map is resolved per-command instead of here, because the third
    # source -- `git config ipscrub.nodeMap` -- needs the repository, which only
    # the command knows. See resolve_node_map().
    if not args.allowlist:
        args.allowlist = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "ipscrub-allowlist.txt")
    try:
        return args.fn(args)
    except RuntimeError as e:
        sys.stderr.write("ipscrub: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
