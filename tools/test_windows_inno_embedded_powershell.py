#!/usr/bin/env python3
"""The PowerShell scripts winsvpn.iss writes at install time must parse.

`WritePrerequisiteVerifierScript` and `WriteBrowserBridgeIdentityScript` build a
.ps1 from Pascal string literals and run it elevated. A script that does not
parse makes powershell.exe exit 1 before any check runs. The prerequisite
verifier shipped that way from 2026-08-27 (ee48a2f) to 1.0.17: the OpenView
InvokeMember call lacked its closing parenthesis, every install stopped in
PrepareToInstall with "The embedded prerequisite has the wrong Authenticode
signer, version, or architecture, or verification tooling failed. Exit code: 1",
and no build gate ran the script.

This test rebuilds each script exactly as Inno Setup would (Pascal '' is one
quote, #13#10 is CRLF, adjacent literals concatenate) and checks bracket
balance outside PowerShell strings. When pwsh is installed it also parses each
script with the real PowerShell parser.

Run: python3 -B tools/test_windows_inno_embedded_powershell.py
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ISS = ROOT / "installer/windows/winsvpn.iss"
GENERATORS = ("WritePrerequisiteVerifierScript", "WriteBrowserBridgeIdentityScript")


def embedded_script(iss_text: str, function: str) -> str:
    start = iss_text.index(f"function {function}")
    call = iss_text.index("SaveStringToFile(ScriptPath,", start) + len("SaveStringToFile(ScriptPath,")
    end = iss_text.index("False);", call)
    body = iss_text[call:end]
    out: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "'":
            j = i + 1
            buf: list[str] = []
            while True:
                if body[j] == "'" and body[j + 1:j + 2] == "'":
                    buf.append("'")
                    j += 2
                    continue
                if body[j] == "'":
                    break
                buf.append(body[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        elif body.startswith("#13#10", i):
            out.append("\r\n")
            i += 6
        else:
            i += 1
    return "".join(out)


def bracket_faults(script: str) -> list[str]:
    """Unbalanced (), [] or {} outside PowerShell quoted strings and comments."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    faults: list[str] = []
    line = 1
    i = 0
    n = len(script)
    while i < n:
        c = script[i]
        if c == "\n":
            line += 1
        elif c == "'":
            j = i + 1
            while j < n:
                if script[j] == "'" and script[j + 1:j + 2] == "'":
                    j += 2
                    continue
                if script[j] == "'":
                    break
                j += 1
            line += script.count("\n", i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and script[j] != '"':
                j += 2 if script[j] == "`" else 1
            line += script.count("\n", i, j)
            i = j
        elif c == "#" and (i == 0 or script[i - 1] in " \t\n"):
            end = script.find("\n", i)
            i = n if end < 0 else end
            continue
        elif c in "([{":
            stack.append((c, line))
        elif c in ")]}":
            if not stack or stack[-1][0] != pairs[c]:
                faults.append(f"line {line}: unexpected {c!r}")
            else:
                stack.pop()
        i += 1
    faults.extend(f"line {opened}: {char!r} never closed" for char, opened in stack)
    return faults


class InnoEmbeddedPowerShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.iss = ISS.read_text(encoding="utf-8")

    def test_every_embedded_script_is_bracket_balanced(self) -> None:
        for function in GENERATORS:
            with self.subTest(function=function):
                script = embedded_script(self.iss, function)
                self.assertIn("exit 0", script)
                self.assertEqual(bracket_faults(script), [])

    def test_the_shipped_missing_parenthesis_is_caught(self) -> None:
        self.assertIn("=''''ProductVersion''''''))' + #13#10", self.iss)
        broken = self.iss.replace(
            "=''''ProductVersion''''''))' + #13#10",
            "=''''ProductVersion'''''')' + #13#10",
            1,
        )
        script = embedded_script(broken, "WritePrerequisiteVerifierScript")
        self.assertTrue(bracket_faults(script))

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh is not installed")
    def test_every_embedded_script_parses_in_powershell(self) -> None:
        checker = (
            "$errs=$null; $tok=$null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            "$env:WINS_ISS_PS1, [ref]$tok, [ref]$errs); "
            "if ($errs.Count) { $errs | ForEach-Object { $_.ToString() }; exit 1 }; exit 0"
        )
        with tempfile.TemporaryDirectory(prefix="winsvpn-iss-ps-") as raw:
            for function in GENERATORS:
                with self.subTest(function=function):
                    path = pathlib.Path(raw) / f"{function}.ps1"
                    path.write_bytes(embedded_script(self.iss, function).encode("utf-8"))
                    result = subprocess.run(
                        [shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-Command", checker],
                        env={**os.environ, "WINS_ISS_PS1": str(path)},
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
