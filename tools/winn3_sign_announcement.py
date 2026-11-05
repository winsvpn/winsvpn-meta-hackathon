#!/usr/bin/env python3
"""Offline signing ceremony for the global announcement.

WHY THIS FILE EXISTS. The hub holds NO announcement signing key (Fable 5.1
ruling, 2026-09-29, IA-CP-06). `/admin/*` is one fleet-wide shared token, and a
leaked token must not be able to write an authenticated message to every
installed app. So announcements are signed OFF the hub, exactly like
descriptors (tools/winn3_sign_descriptor.py), and the hub only verifies the
uploaded envelope against the a1..a3 PUBLIC keys and a strictly increasing
sequence. This is a separate file from the descriptor tool on purpose: that
tool's blast-radius warnings (its payload carries an admission secret) do not
apply here and must not be diluted by mixing the two.

WHAT IT SIGNS, byte for byte the construction both verifiers use:
  message = b"winsvpn-announcement/v1" || 0x00 || payload
  payload = UTF-8 JSON {"iat","kid","seq","text"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False
  hub    -- server/wins_control_plane_setup_ONETOUCH.sh,
            verify_announcement_signature / store_verified_announcement
  client -- lib/announcement_signature.dart, announcementSigningBytes
The hub stores the payload bytes verbatim and the client verifies the bytes it
decodes; neither re-serialises, so this serialisation is the only one there is.

THE PRIVATE KEY is passed BY PATH and never read, printed, logged or copied by
this script: openssl(1) opens it. There is deliberately NO key-generation mode.
Generate keys by hand, offline:
    umask 077 && openssl genpkey -algorithm ED25519 -out a1.pem

Output of `sign`: one JSON object {"payload": <b64>, "sig": <b64>} on stdout,
the same shape the hub serves as `announcement_signed`. Save it and give its
path to `wins-admin` menu 10, or post the two fields yourself:
    curl -sS -X POST "$HUB_BASE/admin/announce" -H "x-admin-token: $WINS_ADMIN_TOKEN" \
      -F "announcement_payload_b64=..." -F "announcement_sig_b64=..."

Exit codes: 0 signed, 2 refused (bad input / seq did not increase), 3 openssl
or environment failure.
"""
import argparse
import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

# Copies of hub constants; server/test_winn3_sign_announcement_tool.py checks
# them against the live hub module so the two cannot drift.
DOMAIN = b"winsvpn-announcement/v1"
KEY_SLOTS = ("a1", "a2", "a3")
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_PAYLOAD_BYTES = 8192
MAX_TEXT_CHARS = 900
MAX_SEQ = 2 ** 53 - 1

HUB_PUBKEY_ENV = "ANNOUNCE_PUBKEY_{SLOT}"
CLIENT_PUBKEY_DEFINE = "WINS_ANNOUNCE_PUBKEY_{SLOT}"


def die(message, code=2):
    sys.stderr.write(f"REFUSED: {message}\n")
    raise SystemExit(code)


def _openssl_command():
    configured = os.environ.get("WINS_RELEASE_OPENSSL")
    if not configured:
        return "openssl"
    if not os.path.isabs(configured):
        die("WINS_RELEASE_OPENSSL must be an absolute path.", 3)
    try:
        info = os.lstat(configured)
    except OSError as exc:
        die(f"WINS_RELEASE_OPENSSL is unavailable: {exc}", 3)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        die("WINS_RELEASE_OPENSSL must name one regular, non-symlink file.", 3)
    if not os.access(configured, os.X_OK):
        die("WINS_RELEASE_OPENSSL is not executable.", 3)
    return configured


def _run_openssl(argv):
    try:
        completed = subprocess.run(
            [_openssl_command(), *argv],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except FileNotFoundError:
        die("openssl(1) is not on PATH. The hub verifies with openssl.", 3)
    except subprocess.TimeoutExpired:
        die("openssl timed out.", 3)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        die(f"openssl {argv[0]} failed: {detail or 'no diagnostic'}", 3)
    return completed.stdout


def public_key_raw(key_path):
    """Raw 32-byte Ed25519 public half of the key at `key_path` (read by openssl)."""
    if not os.path.exists(key_path):
        die(f"private key not found at {key_path}", 2)
    der = _run_openssl(["pkey", "-in", key_path, "-pubout", "-outform", "DER"])
    if not der.startswith(ED25519_SPKI_PREFIX) or len(der) != 44:
        die("that key is not Ed25519; the client verifies Ed25519 only.", 2)
    return der[-ED25519_PUBLIC_KEY_BYTES:]


def _write_private(path, blob):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(blob)


def sign_message(key_path, message):
    # Ed25519 is one-shot: openssl needs a seekable -in, not a pipe.
    with tempfile.TemporaryDirectory(prefix="announce-sign-") as work:
        message_path = os.path.join(work, "announcement.bin")
        _write_private(message_path, message)
        signature = _run_openssl(
            ["pkeyutl", "-sign", "-rawin", "-inkey", key_path, "-in", message_path])
    if len(signature) != ED25519_SIGNATURE_BYTES:
        die(f"openssl returned a {len(signature)}-byte signature; Ed25519 is 64.", 3)
    return signature


def verify_message(public_raw, message, signature):
    """Verify with the PUBLIC half, the way the hub does."""
    with tempfile.TemporaryDirectory(prefix="announce-verify-") as work:
        key_path = os.path.join(work, "announce.der")
        msg_path = os.path.join(work, "announce.bin")
        sig_path = os.path.join(work, "announce.sig")
        _write_private(key_path, ED25519_SPKI_PREFIX + public_raw)
        _write_private(msg_path, message)
        _write_private(sig_path, signature)
        completed = subprocess.run(
            [_openssl_command(), "pkeyutl", "-verify", "-rawin", "-pubin",
             "-inkey", key_path, "-keyform", "DER",
             "-sigfile", sig_path, "-in", msg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    return completed.returncode == 0


def payload_bytes_for(kid, seq, iat, text):
    return json.dumps(
        {"kid": kid, "seq": seq, "iat": iat, "text": text},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _read_text(args):
    if (args.text is None) == (args.text_file is None):
        die("give exactly one of --text or --text-file", 2)
    if args.text is not None:
        return args.text
    try:
        with open(args.text_file, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        die(f"cannot read --text-file: {exc.__class__.__name__}", 2)
    # One trailing newline is an editor artefact, not part of the message.
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    return text


def cmd_pubkey(args):
    slot = args.kid.strip().lower()
    if slot not in KEY_SLOTS:
        die(f"--kid must be one of {', '.join(KEY_SLOTS)}", 2)
    encoded = base64.b64encode(public_key_raw(args.key)).decode()
    if args.bare:
        print(encoded)
        return 0
    upper = slot.upper()
    print("# Base64 of the RAW 32-byte Ed25519 public half. The private key was")
    print("# read only by openssl and is not printed, copied or logged.")
    print("# 1. HUB (wins-hub.service EnvironmentFile, no WINS_ prefix):")
    print(f"{HUB_PUBKEY_ENV.format(SLOT=upper)}={encoded}")
    print("# 2. CLIENT (--dart-define on every build, WITH the WINS_ prefix):")
    print(f"--dart-define={CLIENT_PUBKEY_DEFINE.format(SLOT=upper)}={encoded}")
    return 0


def cmd_sign(args):
    slot = args.kid.strip().lower()
    if slot not in KEY_SLOTS:
        die(f"--kid must be one of {', '.join(KEY_SLOTS)}", 2)
    text = _read_text(args)
    if not text.strip():
        die("announcement text is blank; the client refuses empty text", 2)
    if len(text) > MAX_TEXT_CHARS:
        die(f"announcement text is {len(text)} characters, over the "
            f"{MAX_TEXT_CHARS}-character cap the client renders and the hub enforces", 2)
    if not 1 <= args.seq <= MAX_SEQ:
        die(f"--seq must be 1..{MAX_SEQ}", 2)
    if args.prev_seq is not None and args.seq <= args.prev_seq:
        die(f"seq must STRICTLY INCREASE: --seq {args.seq} is not greater than "
            f"--prev-seq {args.prev_seq}. The hub refuses it too. Nothing was signed", 2)
    iat = int(time.time()) if args.iat is None else args.iat
    if iat < 0:
        die("--iat must be non-negative", 2)
    payload = payload_bytes_for(slot, args.seq, iat, text)
    if len(payload) > MAX_PAYLOAD_BYTES:
        die(f"payload is {len(payload)} bytes, over the {MAX_PAYLOAD_BYTES}-byte ceiling", 2)
    public_raw = public_key_raw(args.key)
    message = DOMAIN + b"\x00" + payload
    signature = sign_message(args.key, message)
    if not verify_message(public_raw, message, signature):
        die("self-verification FAILED; nothing was emitted.", 3)
    print(json.dumps({
        "payload": base64.b64encode(payload).decode(),
        "sig": base64.b64encode(signature).decode(),
    }, sort_keys=True))
    sys.stderr.write(
        f"signed announcement kid={slot} seq={args.seq} iat={iat} "
        f"payload={len(payload)} bytes; public key "
        f"{HUB_PUBKEY_ENV.format(SLOT=slot.upper())}="
        f"{base64.b64encode(public_raw).decode()}\n")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="winn3_sign_announcement.py",
        description=(
            "Sign the global announcement offline. The hub holds no signing "
            "key by design. The private key is passed BY PATH and is never "
            "read, printed or copied by this script."),
        epilog=(
            "There is no key-generation mode on purpose:\n"
            "    umask 077 && openssl genpkey -algorithm ED25519 -out a1.pem"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    pub = sub.add_parser("pubkey", help="print the base64 raw public half of a key")
    pub.add_argument("--key", required=True, metavar="PATH")
    pub.add_argument("--kid", default="a1", metavar="SLOT", help="a1, a2 or a3")
    pub.add_argument("--bare", action="store_true")
    pub.set_defaults(func=cmd_pubkey)
    sign = sub.add_parser("sign", help="sign an announcement")
    sign.add_argument("--key", required=True, metavar="PATH",
                      help="Ed25519 private key (PEM). Read by openssl only.")
    sign.add_argument("--text", help="announcement text")
    sign.add_argument("--text-file", metavar="PATH",
                      help="UTF-8 file holding the text (one trailing newline dropped)")
    sign.add_argument("--seq", type=int, required=True,
                      help="sequence; must exceed the hub's stored seq")
    sign.add_argument("--prev-seq", type=int, default=None, metavar="N",
                      help="the seq the hub currently serves, checked locally")
    sign.add_argument("--kid", default="a1", help="signing slot (default a1)")
    sign.add_argument("--iat", type=int, default=None,
                      help="issued-at unix seconds (default: now)")
    sign.set_defaults(func=cmd_sign)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
