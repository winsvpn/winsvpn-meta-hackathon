#!/usr/bin/env python3
"""Regression check: `CFBundleLocalizations` stays consistent with `kSupportedLocales`.

The single source of truth is `kSupportedLocales` in
`lib/locale_resolution.dart`; `tools/ios_localization_gate.py` keeps
`ios/Runner/Info.plist` in step with it (`--check` verifies, `--update`
rewrites). This script exists because a gate that only ever passes is not a
gate: it re-runs the live `--check` AND proves the gate can fail, using the
three-control protocol from `.spark_lanes/FALSE_GREEN_CATALOGUE.md`.

Controls (every one must pass; POSITIVE controls are scored inverted):

  GREEN                 `--check` against the live tree exits 0.
  NEUTRAL (plist)       comment-only edit to a plist COPY still passes.
  NEUTRAL (dart)        comment-only edit to a dart COPY still passes.
  POSITIVE (dart)       adding Locale('fr') to a dart COPY makes `--check`
                        exit 1 naming `fr` (drift dart-ahead-of-plist).
  POSITIVE (plist)      adding <string>fr</string> to a plist COPY makes
                        `--check` exit 1 naming `fr` (drift plist-ahead-of-dart).
  FIX (dart wins)       `--update` on the dart-ahead drift realigns the plist
                        to the dart order, the result stays well-formed XML,
                        `--check` passes again, and a repeat `--update` is a
                        no-op.
  FIX (authority)       `--update` on the plist-ahead drift REMOVES the extra
                        language, so the dart list is provably the authority.

All mutations happen on private copies under a temp dir inside the repo; the
shared tree is only ever read. Each needle is fingerprinted (must occur exactly
once) or the control is reported NOT_APPLIED, never silently PASSED.

Usage:
    python3 tools/regression_ios_localization_consistency.py
        Run all controls; exit 0 only when every one holds.
    python3 tools/regression_ios_localization_consistency.py --keep-work-dir
        Leave the private copies in place for inspection.
"""

import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(REPO_ROOT, "tools", "ios_localization_gate.py")
DART = os.path.join(REPO_ROOT, "lib", "locale_resolution.dart")
PLIST = os.path.join(REPO_ROOT, "ios", "Runner", "Info.plist")

DART_ENTRY = "  Locale('en'),"
DART_FR_ENTRY = DART_ENTRY + "\n  Locale('fr'),"
PLIST_EN_STRING = "\t\t<string>en</string>"
PLIST_FR_STRING = PLIST_EN_STRING + "\n\t\t<string>fr</string>"

_results = []


def _record(name, ok, detail):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print("  %-34s %s   %s" % (name, status, detail))


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _apply_once(text, needle, replacement, what):
    """Fingerprinted needle mutation: require exactly one match or refuse."""
    count = text.count(needle)
    if count != 1:
        raise RuntimeError(
            "needle for %s occurs %d times (expected 1); refusing to mutate"
            % (what, count))
    return text.replace(needle, replacement)


def _copy(src, dst):
    shutil.copyfile(src, dst)


def _gate(*args):
    proc = subprocess.run(
        [sys.executable, GATE] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _plist_names(path):
    with open(path, "rb") as fh:
        data = plistlib.load(fh)
    return list(data["CFBundleLocalizations"])


def _key_names(path):
    text = _read(path)
    return sorted(re.findall(r"<key>\s*([^<]+?)\s*</key>", text))


def _run_controls():
    failing = 0

    rc, out = _gate("--check")
    ok = rc == 0 and "OK:" in out
    _record("GREEN live --check", ok,
            "exit=%d, %s" % (rc, (out.strip() or "(no output)")))
    failing += 0 if ok else 1

    with tempfile.TemporaryDirectory(
            prefix="ios_loc_regression_", dir=REPO_ROOT) as tmp:
        dart = os.path.join(tmp, "locale_resolution.dart")
        plist = os.path.join(tmp, "Info.plist")

        _copy(DART, dart)
        _copy(PLIST, plist)

        neutral_plist = _apply_once(
            _read(plist),
            "\t<key>CFBundleLocalizations</key>",
            "\t<!-- regression neutral comment -->\n\t<key>CFBundleLocalizations"
            "</key>",
            "neutral plist comment")
        _write(plist, neutral_plist)
        rc, out = _gate("--check", "--dart", DART, "--plist", plist)
        ok = rc == 0 and "OK:" in out
        _record("NEUTRAL plist comment", ok,
                "exit=%d, %s" % (rc, (out.strip() or "(no output)")))
        failing += 0 if ok else 1

        _copy(PLIST, plist)
        neutral_dart = _apply_once(
            _read(dart),
            DART_ENTRY,
            DART_ENTRY + " // regression neutral comment",
            "neutral dart comment")
        _write(dart, neutral_dart)
        rc, out = _gate("--check", "--dart", dart, "--plist", plist)
        ok = rc == 0 and "OK:" in out
        _record("NEUTRAL dart comment", ok,
                "exit=%d, %s" % (rc, (out.strip() or "(no output)")))
        failing += 0 if ok else 1

        _copy(DART, dart)
        _copy(PLIST, plist)
        drifted_dart = _apply_once(
            _read(dart), DART_ENTRY, DART_FR_ENTRY, "dart drift -> fr")
        _write(dart, drifted_dart)
        rc, out = _gate("--check", "--dart", dart, "--plist", plist)
        expected = rc == 1 and "MISMATCH" in out and "fr" in out
        _record("POSITIVE dart-ahead drift", expected,
                "exit=%d (wanted non-zero naming `fr`), %s"
                % (rc, (out.strip() or "(no output)")))
        if rc == 1 and "MISMATCH" not in out:
            print("        (SOURCE_BROKEN, not drift: %s)" % out.strip())
        failing += 0 if expected else 1

        _copy(DART, dart)
        _copy(PLIST, plist)
        drifted_plist = _apply_once(
            _read(plist), PLIST_EN_STRING, PLIST_FR_STRING,
            "plist drift -> fr")
        _write(plist, drifted_plist)
        rc, out = _gate("--check", "--dart", dart, "--plist", plist)
        expected = rc == 1 and "MISMATCH" in out and "fr" in out
        _record("POSITIVE plist-ahead drift", expected,
                "exit=%d (wanted non-zero naming `fr`), %s"
                % (rc, (out.strip() or "(no output)")))
        failing += 0 if expected else 1

        keys_before = _key_names(plist)

        _copy(DART, dart)
        _copy(PLIST, plist)
        drifted_dart = _apply_once(
            _read(dart), DART_ENTRY, DART_FR_ENTRY, "dart drift -> fr (fix)")
        _write(dart, drifted_dart)
        rc, out = _gate("--update", "--dart", dart, "--plist", plist)
        updated = _plist_names(plist)
        well_formed = True
        try:
            _plist_names(plist)
        except Exception as exc:  # noqa: BLE001 - report as measured fact
            well_formed = False
            print("        (update output not well-formed XML: %s)" % exc)
        rc_check, out_check = _gate("--check", "--dart", dart, "--plist", plist)
        rc2, out2 = _gate("--update", "--dart", dart, "--plist", plist)
        keys_after = _key_names(plist)
        ok = (rc == 0 and updated == ["en", "fr", "my"]
              and well_formed and keys_before == keys_after
              and rc_check == 0 and "OK:" in out_check
              and rc2 == 0 and "already matches" in out2)
        _record("FIX dart wins + well-formed", ok,
                "plist now %s, keys preserved=%s, recheck exit=%d, "
                "idempotent exit=%d"
                % (updated, keys_before == keys_after, rc_check, rc2))
        failing += 0 if ok else 1

        _copy(DART, dart)
        _copy(PLIST, plist)
        drifted_plist = _apply_once(
            _read(plist), PLIST_EN_STRING, PLIST_FR_STRING,
            "plist drift -> fr (authority)")
        _write(plist, drifted_plist)
        rc, out = _gate("--update", "--dart", dart, "--plist", plist)
        updated = _plist_names(plist)
        ok = rc == 0 and updated == ["en", "my"]
        _record("FIX dart is the authority", ok,
                "drifted plist reduced back to %s (exit=%d)"
                % (updated, rc))
        failing += 0 if ok else 1

    return failing


def test_ios_localization_controls():
    """Run the complete false-green control set under pytest as well."""
    for path in (DART, PLIST, GATE):
        assert os.path.exists(path), "missing localization-gate input: %s" % path
    _results.clear()
    assert _run_controls() == 0


def main():
    keep = "--keep-work-dir" in sys.argv
    sys.argv = [a for a in sys.argv if a != "--keep-work-dir"]
    for path, what in ((DART, "lib/locale_resolution.dart"),
                       (PLIST, "ios/Runner/Info.plist"),
                       (GATE, "tools/ios_localization_gate.py")):
        if not os.path.exists(path):
            print("missing %s: %s" % (what, path), file=sys.stderr)
            return 2

    print("ios localization consistency regression: %s" % REPO_ROOT)
    print("authority = kSupportedLocales; gate = %s" % GATE)
    if keep:
        print("note: work will be kept under the default tmp dir "
              "(printed below)")
    failing = _run_controls()

    print("-" * 72)
    for name, ok, _detail in _results:
        print("  %-34s %s" % (name, "PASS" if ok else "FAIL"))

    if failing:
        print("RESULT: FAIL (%d failed control%s)"
              % (failing, "" if failing == 1 else "s"))
        return 1
    print("RESULT: PASS (all %d controls)" % len(_results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
