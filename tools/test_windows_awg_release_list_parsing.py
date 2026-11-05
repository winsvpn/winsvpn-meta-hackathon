#!/usr/bin/env python3
"""Release-list parsing contract for tools/build_windows_amneziawg_client.ps1.

Windows PowerShell 5.1 ConvertFrom-Json writes a top-level JSON array as one
object. The builder must enumerate it into releases on 5.1 and on pwsh 7, so
the stable-release check sees releases, not one nested array.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT_PATH = ROOT / "tools/build_windows_amneziawg_client.ps1"
CLIENT = CLIENT_PATH.read_text(encoding="utf-8")

OFFICIAL_RELEASE_ID = 374470280
OFFICIAL_ASSET_ID = 523857174
OFFICIAL_MSI_BYTES = 3_641_344
OFFICIAL_MSI_SHA256 = (
    "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b"
)
OFFICIAL_MSI_NAME = "amneziawg-amd64-3.1.0.msi"
OFFICIAL_MSI_URL = (
    "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/download/"
    f"3.1.0/{OFFICIAL_MSI_NAME}"
)

# Runs the builder's real Get-VerifiedOfficialReleaseAsset, lifted from its
# AST, with the builder's own pin assignments. Only the download is stubbed.
HARNESS = r"""
param([string]$Client, [string]$Fixtures, [string]$Mode)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Client, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
$definitions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-VerifiedOfficialReleaseAsset'
}, $true))
if ($definitions.Count -ne 1) { throw 'Expected one Get-VerifiedOfficialReleaseAsset' }
Set-Item -Path 'Function:\script:Get-VerifiedOfficialReleaseAsset' `
    -Value $definitions[0].Body.GetScriptBlock()
$TargetArchitecture = 'amd64'
foreach ($variableName in @(
    'upstreamMsiVersion', 'upstreamReleaseId', 'upstreamAssetId',
    'upstreamMsiName', 'upstreamReleaseApiUrl', 'upstreamReleaseListApiUrl',
    'upstreamMsiUrl', 'architecturePins', 'upstreamMsiSha256', 'upstreamMsiBytes'
)) {
    $target = '$' + $variableName
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $target
    }, $true))
    if ($assignments.Count -ne 1) { throw "Expected one assignment for $target" }
    Set-Variable -Scope Script -Name $variableName `
        -Value (& ([scriptblock]::Create($assignments[0].Right.Extent.Text)))
}
if ($Mode -ceq 'simulate-ps51') {
    # Windows PowerShell 5.1 behaviour: a JSON array arrives as one object.
    function script:ConvertFrom-Json {
        param([Parameter(Mandatory = $true, ValueFromPipeline = $true)][AllowEmptyString()][string]$InputObject)
        process {
            Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate
        }
    }
} elseif ($Mode -cne 'native') {
    throw "Unknown mode $Mode"
}
$script:CurrentList = $null
function script:Invoke-PinnedHttpsDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Curl
    )
    if ($Uri -ceq $upstreamReleaseApiUrl) {
        Copy-Item -LiteralPath (Join-Path $Fixtures 'release.json') -Destination $OutFile
    } elseif ($Uri -ceq $upstreamReleaseListApiUrl) {
        Copy-Item -LiteralPath (Join-Path $Fixtures $script:CurrentList) -Destination $OutFile
    } else {
        throw "Unexpected download $Uri"
    }
}
"HOST $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion) MODE $Mode"
foreach ($list in @(Get-ChildItem -LiteralPath $Fixtures -Filter 'list-*.json' | Sort-Object Name)) {
    $script:CurrentList = $list.Name
    $work = Join-Path $Fixtures ('work-' + [IO.Path]::GetFileNameWithoutExtension($list.Name))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $result = Get-VerifiedOfficialReleaseAsset -WorkingRoot $work -Curl 'unused'
        "CASE $($list.Name) OK release=$($result.release_id) asset=$($result.asset_id) size=$($result.asset_size) verified=$($result.release_metadata_verified)"
    } catch {
        "CASE $($list.Name) THROW $($_.Exception.Message)"
    }
}
"DONE"
"""


def _release(tag: str, *, draft: bool = False, prerelease: bool = False) -> dict:
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease}


OFFICIAL_RELEASE = {
    "id": OFFICIAL_RELEASE_ID,
    "tag_name": "3.1.0",
    "draft": False,
    "prerelease": False,
    "assets": [
        {
            "id": OFFICIAL_ASSET_ID,
            "name": OFFICIAL_MSI_NAME,
            "size": OFFICIAL_MSI_BYTES,
            "digest": f"sha256:{OFFICIAL_MSI_SHA256}",
            "browser_download_url": OFFICIAL_MSI_URL,
        }
    ],
}

# name -> (release list, expected outcome). "OK" or a THROW substring.
CASES = {
    "list-1-single.json": ([_release("3.1.0")], "OK"),
    "list-2-multi.json": (
        [
            _release("3.2.0", prerelease=True),
            _release("3.3.0", draft=True),
            _release("3.1.0"),
            _release("3.0.0"),
            _release("2.0.1"),
            _release("1.0.0"),
            _release("nightly"),
        ],
        "OK",
    ),
    "list-3-empty.json": (
        [],
        "The official Windows client has no discoverable stable release.",
    ),
    "list-4-single-newer.json": (
        [_release("3.2.0")],
        "A newer official stable AmneziaWG Windows release exists: 3.2.0. "
        "Review and freeze its exact inputs before building.",
    ),
    "list-5-multi-newer.json": (
        [_release("3.1.0"), _release("3.10.0"), _release("3.2.0")],
        "A newer official stable AmneziaWG Windows release exists: 3.10.0. "
        "Review and freeze its exact inputs before building.",
    ),
    "list-6-only-prereleases.json": (
        [_release("3.2.0", prerelease=True), _release("3.3.0", draft=True)],
        "The official Windows client has no discoverable stable release.",
    ),
}
EXPECTED_OK = (
    f"OK release={OFFICIAL_RELEASE_ID} asset={OFFICIAL_ASSET_ID} "
    f"size={OFFICIAL_MSI_BYTES} verified=True"
)


def powershell_hosts() -> list[tuple[str, str]]:
    """Every available host, with 'pwsh' (6+) or 'powershell' (Windows 5.1)."""
    hosts = []
    for name in ("pwsh", "powershell"):
        path = shutil.which(name)
        if path is not None:
            hosts.append((name, path))
    return hosts


def run_harness(host: str, mode: str) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="winsvpn-awg-release-list-") as raw:
        root = pathlib.Path(raw)
        fixtures = root / "fixtures"
        fixtures.mkdir()
        (fixtures / "release.json").write_text(
            json.dumps(OFFICIAL_RELEASE), encoding="utf-8"
        )
        for name, (releases, _) in CASES.items():
            (fixtures / name).write_text(json.dumps(releases), encoding="utf-8")
        harness = root / "harness.ps1"
        harness.write_text(HARNESS, encoding="utf-8")
        completed = subprocess.run(
            [
                host,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(harness),
                "-Client",
                str(CLIENT_PATH),
                "-Fixtures",
                str(fixtures),
                "-Mode",
                mode,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or "DONE" not in completed.stdout:
        raise AssertionError(f"harness failed ({completed.returncode}): {output}")
    results = {}
    for line in completed.stdout.splitlines():
        match = re.match(r"^CASE (\S+) (.*)$", line.strip())
        if match:
            results[match.group(1)] = match.group(2)
    return results


class WindowsAwgReleaseListParsingTests(unittest.TestCase):
    def test_release_list_is_enumerated_before_the_stable_filter(self) -> None:
        # The 5.1 defect: @() around the pipeline wraps the one array object.
        self.assertNotRegex(
            CLIENT,
            r"\$releaseList\s*=\s*@\(\s*Get-Content[^)]*\|\s*ConvertFrom-Json\s*\)",
        )
        self.assertIn(
            "        $releaseList = Get-Content -Raw -LiteralPath $releaseListPath |\n"
            "            ConvertFrom-Json\n"
            "        $releaseList = @($releaseList)\n",
            CLIENT,
        )

    def test_one_and_many_release_lists_on_every_available_host(self) -> None:
        hosts = powershell_hosts()
        if not hosts:
            self.skipTest("no PowerShell host is available")
        for name, path in hosts:
            modes = ["native"]
            probe = subprocess.run(
                [path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                 "$PSVersionTable.PSVersion.Major"],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            version = probe.stdout.strip()
            if probe.returncode != 0 or not version.isdigit():
                raise AssertionError(
                    f"{name} did not start ({probe.returncode}): "
                    f"{probe.stdout}{probe.stderr}"
                )
            major = int(version)
            if major >= 6:
                # pwsh 6+ enumerates natively; also replay 5.1 array output.
                modes.append("simulate-ps51")
            for mode in modes:
                with self.subTest(host=name, version=major, mode=mode):
                    results = run_harness(path, mode)
                    self.assertEqual(sorted(results), sorted(CASES))
                    for case, (_, expected) in CASES.items():
                        if expected == "OK":
                            self.assertEqual(results[case], EXPECTED_OK, case)
                        else:
                            self.assertEqual(
                                results[case], f"THROW {expected}", case
                            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
