#!/usr/bin/env python3
"""Turn a one-time prepaid mint response into an encrypted delivery file.

Round R2. Input: the JSON body returned ONCE by POST /admin/redemption/batch
(file path, or "-" for stdin so the plaintext never touches disk). Output:

  OUTPUT                 CSV encrypted with `age` to the approved recipient(s)
                         (plaintext CSV only with --plaintext, mode 0600)
  OUTPUT.manifest.json   no codes: batch, channel, serials, canary pull list,
                         row count and the SHA-256 of the plaintext CSV

CSV columns: serial,activation_code,duration,redeem_url,batch_id,channel

Canaries are dropped from the delivery file. With --printer-canaries (printer
channel only) they are kept so a leaked print file trips the hub's canary
alarm, and their serials go to the manifest's pull list: those printed cards
must be destroyed before sale.

This tool makes no network call and holds no credential. Amazon's real
upload format is unknown until the account holder obtains it, so the CSV is a
generic interchange file, not an Amazon feed. R2-EN: operator messages below
are new English strings.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CHANNELS = {"direct", "printer", "amazon", "reseller", "giveaway", "support"}
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_CODES = 20000
FIELDS = ["serial", "activation_code", "duration", "redeem_url", "batch_id", "channel"]
DEFAULT_REDEEM_URL = "https://winsvpn.org/#get"
CODE_RE = re.compile(r"(?:[0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{3}")
BATCH_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
DURATION_RE = re.compile(r"[1-9][0-9]{0,3}[dmy]|lifetime|life")
AGE_RECIPIENT_RE = re.compile(r"age1[0-9a-z]{58}")


class ExportError(Exception):
    pass


def crockford_check_ok(code: str) -> bool:
    symbols = code.replace("-", "")
    value = 0
    for ch in symbols[:-1]:
        value = value * 32 + ALPHABET.index(ch)
    check = value % 37
    return check < 32 and ALPHABET[check] == symbols[-1]


def load_mint(source: str) -> dict:
    if source == "-":
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    else:
        with open(source, "rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ExportError("Input exceeds the 8 MiB limit.")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ExportError("Input is not JSON.") from exc
    if not isinstance(data, dict):
        raise ExportError("Expected the mint response object.")
    return data


def build_rows(data: dict, redeem_url: str, printer_canaries: bool) -> tuple:
    batch = data.get("batch_id")
    channel = data.get("channel")
    duration = data.get("duration")
    if not isinstance(batch, str) or not BATCH_RE.fullmatch(batch):
        raise ExportError("Invalid batch_id.")
    if channel not in CHANNELS:
        raise ExportError("Missing or unknown channel; mint with the R2 hub.")
    if not isinstance(duration, str) or not DURATION_RE.fullmatch(duration):
        raise ExportError("Invalid duration.")
    if printer_canaries and channel != "printer":
        raise ExportError("--printer-canaries is only for printer batches.")
    codes = data.get("codes")
    if not isinstance(codes, list) or not 1 <= len(codes) <= MAX_CODES:
        raise ExportError("The mint response must hold 1 to 20000 codes.")
    serial_prefix = batch.upper() + "-"
    seen_codes, seen_serials = set(), set()
    rows, pull_list, serials = [], [], []
    for item in codes:
        if not isinstance(item, dict) or set(item) != {"code", "canary", "serial"}:
            raise ExportError("Each code needs exactly code, canary and serial.")
        code, canary, serial = item["code"], item["canary"], item["serial"]
        if not isinstance(code, str) or not CODE_RE.fullmatch(code) or not crockford_check_ok(code):
            raise ExportError("A code failed its shape or check-symbol test.")
        if not isinstance(canary, bool):
            raise ExportError("canary must be true or false.")
        if (not isinstance(serial, str) or not serial.startswith(serial_prefix)
                or not re.fullmatch(r"[0-9]{5}", serial[len(serial_prefix):])):
            raise ExportError("A serial does not belong to this batch.")
        if code in seen_codes or serial in seen_serials:
            raise ExportError("Duplicate code or serial.")
        seen_codes.add(code)
        seen_serials.add(serial)
        if canary and not printer_canaries:
            continue
        if canary:
            pull_list.append(serial)
        serials.append(serial)
        rows.append([serial, code, duration, redeem_url, batch, channel])
    if not rows:
        raise ExportError("No sale codes left after removing canaries.")
    return batch, channel, duration, rows, serials, pull_list


def render_csv(rows: list) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(FIELDS)
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def _exclusive_open(path: Path) -> int:
    if path.is_symlink():
        raise ExportError(f"Refusing to write through a symlink: {path.name}")
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as exc:
        raise ExportError(f"Refusing to overwrite an existing file: {path.name}") from exc


def _fsync_directory(directory: Path) -> None:
    # The new name must survive a crash too: these files are the only plaintext
    # copy of codes the hub stores as keyed hashes.
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path: Path, payload: bytes) -> None:
    fd = _exclusive_open(path)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def encrypt_with_age(plaintext: bytes, destination: Path, recipients: list, recipients_file: str,
                     age_binary: str) -> None:
    binary = shutil.which(age_binary) if os.sep not in age_binary else age_binary
    if not binary:
        raise ExportError("The age binary was not found; install age or pass --age.")
    command = [binary]
    for recipient in recipients:
        command += ["-r", recipient]
    if recipients_file:
        command += ["-R", recipients_file]
    # Plaintext goes in on stdin and ciphertext comes back on stdout, so the
    # only file ever written is the encrypted one, through an exclusive open.
    try:
        completed = subprocess.run(command, input=plaintext, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExportError("age did not run to completion.") from exc
    if completed.returncode != 0 or not completed.stdout.startswith(b"age-encryption.org/v1"):
        raise ExportError("age failed; no delivery file was written.")
    write_exclusive(destination, completed.stdout)


def export(source: str, output: Path, *, recipients: list, recipients_file: str, plaintext: bool,
           printer_canaries: bool, redeem_url: str, age_binary: str = "age") -> dict:
    if not plaintext and not recipients and not recipients_file:
        raise ExportError("Give --recipient or --recipients-file, or --plaintext for a local test file.")
    for recipient in recipients:
        if not AGE_RECIPIENT_RE.fullmatch(recipient):
            raise ExportError("A --recipient is not an age X25519 public key (age1...).")
    if not redeem_url.startswith("https://"):
        raise ExportError("--redeem-url must be an https URL.")
    manifest_path = output.with_name(output.name + ".manifest.json")
    if manifest_path.exists() or manifest_path.is_symlink():
        raise ExportError(f"Refusing to overwrite an existing file: {manifest_path.name}")
    batch, channel, duration, rows, serials, pull_list = build_rows(
        load_mint(source), redeem_url, printer_canaries)
    payload = render_csv(rows)
    if plaintext:
        write_exclusive(output, payload)
    else:
        encrypt_with_age(payload, output, recipients, recipients_file, age_binary)
    manifest = {
        "batch_id": batch,
        "channel": channel,
        "duration": duration,
        "rows": len(rows),
        "serials": serials,
        "canary_pull_list": pull_list,
        "plaintext_csv_sha256": hashlib.sha256(payload).hexdigest(),
        "encrypted": not plaintext,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        write_exclusive(manifest_path, (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mint_json", help="mint response file, or - for stdin")
    parser.add_argument("output", type=Path, help="delivery file to create (never overwritten)")
    parser.add_argument("--recipient", action="append", default=[], help="age X25519 public key (repeatable)")
    parser.add_argument("--recipients-file", default="", help="age recipients file")
    parser.add_argument("--plaintext", action="store_true", help="write an unencrypted CSV (local tests only)")
    parser.add_argument("--printer-canaries", action="store_true",
                        help="printer batches: keep canaries and list their serials to pull")
    parser.add_argument("--redeem-url", default=DEFAULT_REDEEM_URL)
    parser.add_argument("--age", default="age", help="age binary")
    args = parser.parse_args(argv)
    try:
        manifest = export(args.mint_json, args.output, recipients=args.recipient,
                          recipients_file=args.recipients_file, plaintext=args.plaintext,
                          printer_canaries=args.printer_canaries, redeem_url=args.redeem_url,
                          age_binary=args.age)
    except (OSError, ExportError) as exc:
        # Never echo input content: it holds live codes.
        print(f"Export failed: {exc if isinstance(exc, ExportError) else type(exc).__name__}. "
              "No delivery file was kept.", file=sys.stderr)
        return 1
    pulled = len(manifest["canary_pull_list"])
    print(f"Wrote {manifest['rows']} rows for batch {manifest['batch_id']} "
          f"({'encrypted' if manifest['encrypted'] else 'PLAINTEXT'})"
          + (f"; destroy {pulled} canary cards listed in the manifest before sale" if pulled else "")
          + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())
