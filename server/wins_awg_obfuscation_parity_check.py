#!/usr/bin/env python3
"""Fail if what the hub SERVES disagrees with what a node is RUNNING.

This is the check whose absence let two defects live side by side for weeks:

  * the hub's ``parse_obfuscation`` silently rewrote any unreadable profile to
    the legacy 11/22/33/44 set on the serving path, and
  * the core-hop installer hardcoded that same legacy set instead of reading
    the provisioned ``/etc/winsvpn/awg-obfuscation.env``.

Both are the same class: a component that independently re-derives a value
instead of reading the one authoritative source, then disagrees with it in
silence. AmneziaWG parameters are **not negotiated**, so a disagreement is not
a weaker tunnel -- the client's packets stop matching what the node expects and
the tunnel simply cannot handshake. It presents to the user as "the VPN is
broken" with nothing anywhere saying why. That is what this guard exists to
turn into a loud, early failure.

Two things this deliberately does NOT do:

1. **It never compares a file against itself.** The served side and the running
   side must come from genuinely different components, and the tool refuses to
   run if they resolve to the same path. A check that reads awg0.conf twice
   proves nothing; that is how both defects survived review.
2. **It never prints the parameter values.** H1..H4 and S1..S4 exist precisely
   so that they are not publicly known, and stdout gets pasted into tickets and
   piped into logs. Disagreements are reported by *key name*, which is all an
   operator needs in order to know where to look.

Usage
-----
Serving side is the hub, running side is the node (the real production shape;
run it on the hub with the node's interface config copied in read-only)::

    wins_awg_obfuscation_parity_check.py \\
        --hub-db /root/vpn_auth/vpn_users.db --slug <node-slug> \\
        --hub-main /root/vpn_auth/main.py \\
        --running-conf ./awg0.conf-from-that-node

Serving side is a captured client config response (run from a client's
vantage point, which is what actually reaches users)::

    wins_awg_obfuscation_parity_check.py \\
        --served-json ./config-response.json \\
        --running-conf /etc/amnezia/amneziawg/awg0.conf

Optionally add the provisioned single source as a third side::

    ... --profile /etc/winsvpn/awg-obfuscation.env

Static invariant over any number of installer copies -- every site that
defaults AWG_H1..AWG_H4 must be preceded by sourcing the profile, so a third
copy cannot drift back to hardcoded legacy values::

    wins_awg_obfuscation_parity_check.py --installer-drift \\
        server/wins_core_server_setup_ONETOUCH.sh \\
        server/wins_data_plane_setup_ONETOUCH.sh \\
        tools/home_server/wins_core_server_setup_ONETOUCH.sh

Prove the guard fires before trusting it::

    wins_awg_obfuscation_parity_check.py --self-test

Exit codes: 0 agree / invariant holds, 1 disagreement, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import re
import sqlite3
import sys
import tempfile
from typing import Optional

# The eleven parameters that make up one AmneziaWG obfuscation profile, in the
# order the hub's DEFAULT_OBFUSCATION declares them. Each is (config-file key,
# awg-obfuscation.env variable). The JSON key served to clients is the
# config-file key verbatim.
PARAMETERS = (
    ("Jc", "AWG_JC"),
    ("Jmin", "AWG_JMIN"),
    ("Jmax", "AWG_JMAX"),
    ("S1", "AWG_S1"),
    ("S2", "AWG_S2"),
    ("S3", "AWG_S3"),
    ("S4", "AWG_S4"),
    ("H1", "AWG_H1"),
    ("H2", "AWG_H2"),
    ("H3", "AWG_H3"),
    ("H4", "AWG_H4"),
)
CONF_KEYS = tuple(key for key, _ in PARAMETERS)
ENV_FOR_CONF = dict(PARAMETERS)

# How far back from an `AWG_H1="${AWG_H1:-11}"` default site --installer-drift
# will look for the profile being sourced. The fixed blocks put the source
# about ten lines above; the window is generous enough to survive a comment
# being reworded and tight enough that an unrelated source elsewhere in a
# 6000-line installer cannot be mistaken for this one.
PROFILE_SOURCE_LOOKBACK_LINES = 40

# Matches both spellings in the tree: the core installers assign straight back
# into AWG_H1, the data-plane installer and wins-node-register assign into
# AWG_H1_DEFAULT. Both are header-default sites and both must read the profile
# first, so both are checked.
HEADER_DEFAULT_SITE = re.compile(r'^\s*AWG_H1(?:_DEFAULT)?\s*=\s*"?\$\{AWG_H1:-')
PROFILE_SOURCE_SITE = re.compile(
    r'^\s*(?:\.|source)\s+"?(?:\$\{AWG_OBFUSCATION_PROFILE[^}]*\}|/etc/winsvpn/awg-obfuscation\.env)'
)


class InputError(Exception):
    """A source could not be read or understood. Not a disagreement."""


# --------------------------------------------------------------------------
# Readers -- one per component that holds these values.
# --------------------------------------------------------------------------

def read_running_conf(path: str) -> dict:
    """RUNNING side: an AmneziaWG interface config (awg0.conf, core0.conf, ...).

    Only the [Interface] section is considered; a [Peer] block never carries
    these keys and matching there would be a false read.
    """
    values: dict = {}
    section = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    section = stripped.lower()
                    continue
                if section and section != "[interface]":
                    continue
                if "=" not in stripped or stripped.startswith("#"):
                    continue
                key, _, raw = stripped.partition("=")
                key = key.strip()
                if key in CONF_KEYS:
                    values[key] = raw.strip()
    except OSError as exc:
        raise InputError(f"cannot read running config {path}: {exc.strerror}") from exc
    return values


def read_profile_env(path: str) -> dict:
    """The provisioned single source: /etc/winsvpn/awg-obfuscation.env.

    Parsed, never sourced. This file is root-owned mode 0600, but a guard that
    executes its input is a guard that can be turned into a shell.
    """
    raw: dict = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                raw[key.strip()] = value.strip().strip('"').strip("'")
    except OSError as exc:
        raise InputError(f"cannot read profile {path}: {exc.strerror}") from exc
    return {
        conf_key: raw[env_key]
        for conf_key, env_key in PARAMETERS
        if env_key in raw
    }


def read_served_json(path: str) -> dict:
    """SERVING side: a captured hub response, or a bare obfuscation object.

    Accepts the whole /api/v1/config-shaped payload and digs out the
    obfuscation block wherever the response schema puts it, so an operator can
    save the response verbatim instead of hand-editing it -- hand-editing the
    evidence is how you end up comparing something against itself.
    """
    try:
        if path == "-":
            document = json.load(sys.stdin)
        else:
            with open(path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
    except OSError as exc:
        raise InputError(f"cannot read served JSON {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise InputError(f"served JSON {path} is not valid JSON: {exc}") from exc

    for candidate in _candidate_obfuscation_blocks(document):
        if isinstance(candidate, dict) and any(k in candidate for k in CONF_KEYS):
            return {k: candidate[k] for k in CONF_KEYS if k in candidate}
    raise InputError(f"served JSON {path} carries no obfuscation block")


def _candidate_obfuscation_blocks(document):
    if isinstance(document, dict):
        if any(k in document for k in CONF_KEYS):
            yield document
        for key in ("obfuscation", "vpn_config", "vpnconfig", "config", "data"):
            nested = document.get(key)
            if isinstance(nested, dict):
                yield from _candidate_obfuscation_blocks(nested)


def load_hub_parser(path: str):
    """Load the hub's OWN parse_obfuscation out of the deployed/embedded source.

    Extracted and exec'd rather than reimplemented. A guard that reimplements
    the parser is another independent re-derivation -- the exact defect class
    it is supposed to catch -- and it would agree with itself forever while the
    real serving path did something else.

    Accepts either a Python module (``/root/vpn_auth/main.py``) or the
    installer shell script that embeds it.

    Returns ``(parse_obfuscation, is_fail_closed_variant)``. The pre-fix parser
    is still loadable on purpose: pointing this at a deployed hub that has not
    been updated should report the silent-substitution behaviour, not refuse to
    look.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            source = handle.read()
    except OSError as exc:
        raise InputError(f"cannot read hub source {path}: {exc.strerror}") from exc

    try:
        tree = ast.parse(source)
    except SyntaxError:
        source = _extract_embedded_main(source, path)
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise InputError(f"hub source {path} does not parse as Python: {exc}") from exc

    wanted_defs = {
        "ObfuscationProfileError",
        "coerce_obfuscation_value",
        "parse_obfuscation",
    }
    wanted_assigns = {"DEFAULT_OBFUSCATION", "AWG_OBFUSCATION_MAX"}
    body: list = []
    found: set = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in wanted_defs:
            node.decorator_list = []
            body.append(node)
            found.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted_assigns:
                    body.append(node)
                    found.add(target.id)

    if "parse_obfuscation" not in found or "DEFAULT_OBFUSCATION" not in found:
        raise InputError(
            f"hub source {path} carries no parse_obfuscation/DEFAULT_OBFUSCATION pair"
        )

    namespace: dict = {
        "json": json,
        "re": re,
        "Optional": Optional,
        "Any": object,
        "logger": logging.getLogger("awg-parity-check.hub"),
    }
    exec(compile(ast.Module(body=body, type_ignores=[]), f"<hub:{path}>", "exec"), namespace)
    return namespace["parse_obfuscation"], "ObfuscationProfileError" in found


def _extract_embedded_main(source: str, path: str) -> str:
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if "main.py" in line and line.rstrip().endswith("<<'PYEOF'"):
            start = index + 1
            break
    if start is None:
        raise InputError(f"{path} is neither Python nor a script embedding main.py")
    for index in range(start, len(lines)):
        if lines[index].strip() == "PYEOF":
            return "\n".join(lines[start:index])
    raise InputError(f"{path} embeds main.py but never closes the heredoc")


def read_hub_db(db_path: str, slug: str, parse_obfuscation) -> dict:
    """SERVING side: what the hub will hand to the next client of this node.

    Opened read-only through a file: URI. This tool is pointed at live control
    planes; it must not be able to write to one even by accident.
    """
    if not os.path.exists(db_path):
        raise InputError(f"cannot read hub database {db_path}: no such file")
    uri = "file:" + os.path.abspath(db_path).replace("?", "%3f").replace("#", "%23") + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise InputError(f"cannot open hub database read-only: {exc}") from exc
    try:
        row = connection.execute(
            "SELECT obfuscation_json FROM nodes WHERE slug = ?", (slug,)
        ).fetchone()
    except sqlite3.Error as exc:
        raise InputError(f"cannot read nodes.obfuscation_json: {exc}") from exc
    finally:
        connection.close()
    if row is None:
        raise InputError("hub database has no node with that slug")
    try:
        served = parse_obfuscation(row[0])
    except Exception as exc:  # the hub's own error type, whatever it is called
        raise InputError(
            f"the hub REFUSES to serve this node: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(served, dict):
        raise InputError("the hub's parse_obfuscation did not return a mapping")
    return {k: served[k] for k in CONF_KEYS if k in served}


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def normalize(values: dict) -> dict:
    """Compare numerically, so 011 and 11 and '11' are one value, not three."""
    normalized: dict = {}
    for key, raw in values.items():
        if isinstance(raw, bool):
            normalized[key] = ("invalid", "bool")
            continue
        if isinstance(raw, int):
            normalized[key] = ("int", raw)
            continue
        if isinstance(raw, float):
            normalized[key] = ("int", int(raw)) if raw.is_integer() else ("invalid", "fractional")
            continue
        text = str(raw).strip()
        normalized[key] = ("int", int(text)) if re.fullmatch(r"[0-9]+", text) else ("invalid", text and "non-numeric" or "empty")
    return normalized


def compare(sides: list) -> list:
    """Return a list of human-readable findings. Empty list means agreement.

    ``sides`` is [(label, path, values), ...]. Every side is compared against
    the first, which is by construction the serving side.
    """
    findings: list = []
    normalized = [(label, path, normalize(values)) for label, path, values in sides]

    for label, path, values in normalized:
        invalid = sorted(k for k, v in values.items() if v[0] == "invalid")
        if invalid:
            findings.append(f"{label} has unusable values for: {', '.join(invalid)}")
        missing = [k for k in CONF_KEYS if k not in values]
        if missing:
            findings.append(f"{label} is missing: {', '.join(missing)}")

    reference_label, _, reference = normalized[0]
    for label, _, values in normalized[1:]:
        disagreeing = sorted(
            key
            for key in CONF_KEYS
            if key in reference and key in values and reference[key] != values[key]
        )
        if disagreeing:
            findings.append(
                f"{label} disagrees with {reference_label} on: {', '.join(disagreeing)}"
            )
    return findings


def run_comparison(sides: list, quiet: bool = False) -> int:
    findings = compare(sides)
    if not quiet:
        for label, path, _ in sides:
            print(f"  {label:<28} <- {path}")
    if findings:
        if not quiet:
            print("")
            for finding in findings:
                print(f"DISAGREEMENT: {finding}")
            print("")
            print(
                "AmneziaWG parameters are not negotiated. Clients served the first\n"
                "side cannot handshake with a peer running the others. Values are\n"
                "deliberately not printed; compare the two sources named above."
            )
        return 1
    if not quiet:
        print("\nOK: every side reports the same eleven parameters.")
    return 0


# --------------------------------------------------------------------------
# Static invariant across installer copies
# --------------------------------------------------------------------------

def check_installer_drift(paths: list, quiet: bool = False) -> int:
    """Every AWG_H1 default site must be preceded by sourcing the profile.

    Expressed as an invariant over N files rather than a diff between two, so
    a third copy appearing anywhere is checked automatically instead of
    silently drifting back to hardcoded 11/22/33/44.
    """
    violations: list = []
    sites_checked = 0
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError as exc:
            raise InputError(f"cannot read {path}: {exc.strerror}") from exc
        for index, line in enumerate(lines):
            if not HEADER_DEFAULT_SITE.match(line):
                continue
            sites_checked += 1
            window_start = max(0, index - PROFILE_SOURCE_LOOKBACK_LINES)
            if not any(
                PROFILE_SOURCE_SITE.match(lines[back])
                for back in range(window_start, index)
            ):
                violations.append(f"{path}:{index + 1}")
    if not quiet:
        print(f"  checked {sites_checked} AWG_H1 default site(s) across {len(paths)} file(s)")
    if violations:
        if not quiet:
            for violation in violations:
                print(f"DISAGREEMENT: hardcoded header defaults with no profile sourced above: {violation}")
        return 1
    if sites_checked == 0:
        if not quiet:
            print("DISAGREEMENT: no AWG_H1 default site found; the check matched nothing")
        return 1
    if not quiet:
        print("OK: every header-default site reads the provisioned profile first.")
    return 0


# --------------------------------------------------------------------------
# Self-test -- proof the guard fires
# --------------------------------------------------------------------------

LEGACY = {"Jc": 2, "Jmin": 10, "Jmax": 30, "S1": 16, "S2": 80, "S3": 16, "S4": 0,
          "H1": 11, "H2": 22, "H3": 33, "H4": 44}
STRONG = {"Jc": 5, "Jmin": 61, "Jmax": 843, "S1": 48, "S2": 91, "S3": 16, "S4": 0,
          "H1": 1717986918, "H2": 2863311530, "H3": 3435973836, "H4": 4008636142}


def _conf_text(values: dict, address: str = "10.8.1.1/16") -> str:
    body = "\n".join(f"{k} = {values[k]}" for k in CONF_KEYS if k in values)
    return (
        f"[Interface]\nAddress = {address}\nListenPort = 9110\nPrivateKey = REDACTED\n"
        f"{body}\nMTU = 1280\n\n[Peer]\nPublicKey = REDACTED\nAllowedIPs = 0.0.0.0/0\n"
    )


def _profile_text(values: dict) -> str:
    return "# Generated once per node -- do not edit by hand.\n" + "\n".join(
        f"{ENV_FOR_CONF[k]}={values[k]}" for k in CONF_KEYS if k in values
    ) + "\n"


def self_test() -> int:
    passed = 0
    failed: list = []

    def case(name: str, expected: int, sides: list):
        nonlocal passed
        actual = run_comparison(sides, quiet=True)
        if actual == expected:
            passed += 1
            print(f"  ok    {name} (exit {actual})")
        else:
            failed.append(name)
            print(f"  FAIL  {name} (expected exit {expected}, got {actual})")

    with tempfile.TemporaryDirectory() as work:
        legacy_conf = os.path.join(work, "awg0-legacy.conf")
        strong_conf = os.path.join(work, "awg0-strong.conf")
        partial_conf = os.path.join(work, "awg0-partial.conf")
        peer_only_conf = os.path.join(work, "awg0-peer-only.conf")
        strong_profile = os.path.join(work, "awg-obfuscation.env")
        with open(legacy_conf, "w") as fh:
            fh.write(_conf_text(LEGACY))
        with open(strong_conf, "w") as fh:
            fh.write(_conf_text(STRONG))
        with open(partial_conf, "w") as fh:
            fh.write(_conf_text({k: v for k, v in STRONG.items() if k != "H3"}))
        with open(peer_only_conf, "w") as fh:
            fh.write("[Peer]\nPublicKey = REDACTED\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\n")
        with open(strong_profile, "w") as fh:
            fh.write(_profile_text(STRONG))

        print("value-parity cases:")
        case("legacy served == legacy running", 0, [
            ("hub (serving)", "fixture", dict(LEGACY)),
            ("node awg0.conf (running)", legacy_conf, read_running_conf(legacy_conf)),
        ])
        case("strong served == strong running", 0, [
            ("hub (serving)", "fixture", dict(STRONG)),
            ("node awg0.conf (running)", strong_conf, read_running_conf(strong_conf)),
        ])
        # DEFECT 1 exactly: the hub's bare `try` fell back to the legacy set
        # while the node ran strong parameters.
        case("DEFECT 1: hub serves legacy, node runs strong", 1, [
            ("hub (serving)", "fixture", dict(LEGACY)),
            ("node awg0.conf (running)", strong_conf, read_running_conf(strong_conf)),
        ])
        # DEFECT 2 exactly: the core-hop installer hardcoded the legacy set
        # while the provisioned profile carried strong parameters.
        case("DEFECT 2: core hop renders legacy, profile is strong", 1, [
            ("provisioned profile (source)", strong_profile, read_profile_env(strong_profile)),
            ("core hop conf (running)", legacy_conf, read_running_conf(legacy_conf)),
        ])
        case("single header differs", 1, [
            ("hub (serving)", "fixture", dict(STRONG, H2=STRONG["H2"] + 1)),
            ("node awg0.conf (running)", strong_conf, read_running_conf(strong_conf)),
        ])
        case("running config missing a header", 1, [
            ("hub (serving)", "fixture", dict(STRONG)),
            ("node awg0.conf (running)", partial_conf, read_running_conf(partial_conf)),
        ])
        case("[Peer] keys are not read as [Interface]", 1, [
            ("hub (serving)", "fixture", dict(LEGACY)),
            ("node awg0.conf (running)", peer_only_conf, read_running_conf(peer_only_conf)),
        ])
        case("three-way agreement holds", 0, [
            ("hub (serving)", "fixture", dict(STRONG)),
            ("provisioned profile (source)", strong_profile, read_profile_env(strong_profile)),
            ("node awg0.conf (running)", strong_conf, read_running_conf(strong_conf)),
        ])
        case("three-way, profile agrees but node drifted", 1, [
            ("hub (serving)", "fixture", dict(STRONG)),
            ("provisioned profile (source)", strong_profile, read_profile_env(strong_profile)),
            ("node awg0.conf (running)", legacy_conf, read_running_conf(legacy_conf)),
        ])
        case("string and int forms of the same number agree", 0, [
            ("hub (serving)", "fixture", {k: str(v) for k, v in STRONG.items()}),
            ("node awg0.conf (running)", strong_conf, read_running_conf(strong_conf)),
        ])

        print("\ninstaller-invariant cases:")
        fixed = os.path.join(work, "fixed_installer.sh")
        with open(fixed, "w") as fh:
            fh.write(
                'AWG_OBFUSCATION_PROFILE="${AWG_OBFUSCATION_PROFILE:-/etc/winsvpn/awg-obfuscation.env}"\n'
                'if [[ -f "${AWG_OBFUSCATION_PROFILE}" ]]; then\n'
                '  . "${AWG_OBFUSCATION_PROFILE}"\n'
                'fi\n'
                'AWG_JC="${AWG_JC:-2}"\n'
                'AWG_H1="${AWG_H1:-11}"\n'
                'AWG_H2="${AWG_H2:-22}"\n'
            )
        fixed_default_form = os.path.join(work, "fixed_default_form.sh")
        with open(fixed_default_form, "w") as fh:
            fh.write(
                'if [ -f /etc/winsvpn/awg-obfuscation.env ]; then\n'
                '  . /etc/winsvpn/awg-obfuscation.env\n'
                'fi\n'
                'AWG_H1_DEFAULT="${AWG_H1:-11}"\n'
            )
        broken_default_form = os.path.join(work, "broken_default_form.sh")
        with open(broken_default_form, "w") as fh:
            fh.write('AWG_H1_DEFAULT="${AWG_H1:-11}"\n')
        broken = os.path.join(work, "broken_installer.sh")
        with open(broken, "w") as fh:
            fh.write('AWG_JC="${AWG_JC:-2}"\nAWG_H1="${AWG_H1:-11}"\nAWG_H2="${AWG_H2:-22}"\n')
        far = os.path.join(work, "too_far_installer.sh")
        with open(far, "w") as fh:
            fh.write(
                '. "${AWG_OBFUSCATION_PROFILE}"\n'
                + "# filler\n" * (PROFILE_SOURCE_LOOKBACK_LINES + 5)
                + 'AWG_H1="${AWG_H1:-11}"\n'
            )
        empty = os.path.join(work, "no_sites.sh")
        with open(empty, "w") as fh:
            fh.write("echo nothing to see here\n")

        for name, expected, files in (
            ("fixed installer passes", 0, [fixed]),
            ("AWG_H1_DEFAULT spelling is checked too", 0, [fixed_default_form]),
            ("hardcoded AWG_H1_DEFAULT fails", 1, [broken_default_form]),
            ("hardcoded installer fails", 1, [broken]),
            ("one good + one bad copy fails", 1, [fixed, broken]),
            ("source too far above the site fails", 1, [far]),
            ("matching nothing is a failure, not a pass", 1, [empty]),
        ):
            actual = check_installer_drift(files, quiet=True)
            if actual == expected:
                passed += 1
                print(f"  ok    {name} (exit {actual})")
            else:
                failed.append(name)
                print(f"  FAIL  {name} (expected exit {expected}, got {actual})")

    print("")
    if failed:
        print(f"SELF-TEST FAILED: {len(failed)} case(s): {', '.join(failed)}")
        return 1
    print(f"SELF-TEST PASSED: {passed}/{passed} cases, and every negative case fired.")
    return 0


# --------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if the hub's served AWG obfuscation disagrees with a node's running one.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--served-json", metavar="PATH",
                        help="serving side: captured hub config response, or '-' for stdin")
    parser.add_argument("--hub-db", metavar="PATH",
                        help="serving side: hub SQLite database (opened read-only)")
    parser.add_argument("--slug", metavar="SLUG", help="node slug, required with --hub-db")
    parser.add_argument("--hub-main", metavar="PATH", default="/root/vpn_auth/main.py",
                        help="hub source to load parse_obfuscation from (default: %(default)s)")
    parser.add_argument("--running-conf", metavar="PATH",
                        help="running side: an AmneziaWG interface config on the node")
    parser.add_argument("--profile", metavar="PATH",
                        help="optional third side: the provisioned awg-obfuscation.env")
    parser.add_argument("--installer-drift", metavar="FILE", nargs="+",
                        help="static invariant: every AWG_H1 default site sources the profile")
    parser.add_argument("--self-test", action="store_true",
                        help="run built-in fixtures proving the guard fires")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.installer_drift:
        try:
            return check_installer_drift(args.installer_drift)
        except InputError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    if not args.running_conf:
        parser.error("--running-conf is required (the running side of the comparison)")
    if bool(args.served_json) == bool(args.hub_db):
        parser.error("give exactly one serving side: --served-json or --hub-db")
    if args.hub_db and not args.slug:
        parser.error("--hub-db requires --slug")

    # The rule this guard exists to enforce, applied to the guard itself: a
    # comparison of a file against itself is not a comparison.
    running_real = os.path.realpath(args.running_conf)
    for other in (args.served_json, args.profile):
        if other and other != "-" and os.path.realpath(other) == running_real:
            parser.error(
                "the serving/profile side and the running side are the same file; "
                "this check must compare two different components"
            )

    try:
        sides: list = []
        if args.hub_db:
            parse_obfuscation, fail_closed = load_hub_parser(args.hub_main)
            if not fail_closed:
                print(
                    "WARNING: this hub's parse_obfuscation is the pre-fix variant -- it\n"
                    "         silently substitutes the legacy set on any unreadable\n"
                    "         profile, so 'agreement' below may be a coincidence.\n"
                )
            sides.append(("hub db (serving)", args.hub_db,
                          read_hub_db(args.hub_db, args.slug, parse_obfuscation)))
        else:
            sides.append(("served config (serving)", args.served_json,
                          read_served_json(args.served_json)))
        if args.profile:
            sides.append(("provisioned profile (source)", args.profile,
                          read_profile_env(args.profile)))
        sides.append(("interface conf (running)", args.running_conf,
                      read_running_conf(args.running_conf)))
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return run_comparison(sides)


if __name__ == "__main__":
    sys.exit(main())
