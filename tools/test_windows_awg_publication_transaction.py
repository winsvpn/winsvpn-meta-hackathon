#!/usr/bin/env python3
"""Crash-recovery tests for the five-file Windows AWG generation transaction."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "tools/build_windows_amneziawg_client.ps1"
TEXT = PRODUCER.read_text(encoding="utf-8")


class WindowsAwgPublicationTransactionTests(unittest.TestCase):
    def test_transaction_contract_and_commit_marker_order_are_explicit(self) -> None:
        for marker in (
            "winsvpn.windows-awg-publication.v2",
            "provenance_is_commit_marker = $true",
            "function Publish-AwgGenerationTransaction",
            "function Restore-AwgTransaction",
            "function Move-AwgTransactionPath",
            "function Flush-DurableFile",
            "function Assert-NoReparseAncestors",
            "[IO.FileShare]::None",
            "-FailAfterRename $FailAfterRename",
            "[switch]$SimulateCrash",
        ):
            self.assertIn(marker, TEXT)
        entries = TEXT[TEXT.index("$transactionEntries = @(") :]
        ordered = (
            "$upstreamMsiFull",
            "$awgToolFull",
            "$wintunFull",
            "$outputFull",
            "$provenanceFull",
        )
        offsets = [entries.index(value) for value in ordered]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("generation provenance commit marker", entries)

    def test_exact_frozen_signer_thumbprints_and_roles_are_bound(self) -> None:
        privacy = "141D90A1BA8F61863FBEDDF7DD1D66C1D1E0B128"
        wireguard = "DF98E075A012ED8C86FBCF14854B8F9555CB3D45"
        self.assertGreaterEqual(TEXT.count(privacy), 1)
        self.assertGreaterEqual(TEXT.count(wireguard), 1)
        for marker in (
            "-ExpectedThumbprint $privacyTechnologiesSignerThumbprint",
            "-ExpectedThumbprint $payload.Thumbprint",
            "expected_privacy_technologies_signer_thumbprint",
            "expected_wireguard_signer_thumbprint",
            "official_windows_client_distribution_container",
            "official_awg_userspace_configuration_tool",
            "official_wireguard_tunnel_adapter_library",
            "winsvpn_rebuilt_unsigned_product_maintenance_helper",
            "verified_upstream_gui_helper_not_published",
            "generation_commit_marker_and_provenance",
            "unsigned_canonical_input_release_copy_only",
        ):
            self.assertIn(marker, TEXT)

    def test_release_asset_sizes_hashes_and_ids_are_in_provenance(self) -> None:
        for marker in (
            "upstream_release_id = $upstreamReleaseId",
            "upstream_asset_id = $upstreamAssetId",
            "upstream_asset_size = $upstreamMsiBytes",
            "upstream_asset_sha256 = $upstreamMsiSha256",
            "upstream_msi_size = $upstreamMsiBytes",
            "upstream_awg_exe_size = $upstreamAwgExeBytes",
            "upstream_msi_helper_size = $upstreamMsiHelperBytes",
            "upstream_wintun_dll_size = $upstreamWintunDllBytes",
            "unsigned_artifact_size = $expectedProductHelperBytes",
        ):
            self.assertIn(marker, TEXT)

    def test_reparse_file_and_ancestor_are_rejected_on_macos(self) -> None:
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("pwsh is unavailable for reparse behavior tests")
        with tempfile.TemporaryDirectory(
            prefix="winsvpn-awg-reparse-", dir="/private/tmp"
        ) as raw:
            root = pathlib.Path(raw)
            real = root / "real"
            real.mkdir()
            (real / "payload.bin").write_bytes(b"payload")
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            escaped_producer = str(PRODUCER).replace("'", "''")
            escaped_link = str(link).replace("'", "''")
            command = rf"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{escaped_producer}', [ref]$tokens, [ref]$errors)
foreach ($functionName in @('Assert-RegularPath', 'Assert-NoReparseAncestors')) {{
    $match = @($ast.FindAll({{
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }}, $true))[0]
    Invoke-Expression $match.Extent.Text
}}
$regularRejected = $false
try {{
    Assert-RegularPath -Path '{escaped_link}' -Label 'symlink' -Directory
}} catch {{
    $regularRejected = $true
}}
$ancestorRejected = $false
try {{
    Assert-NoReparseAncestors -Path '{escaped_link}/payload.bin' -Label 'ancestor'
}} catch {{
    $ancestorRejected = $true
}}
if (-not $regularRejected -or -not $ancestorRejected) {{
    throw 'Reparse file or ancestor was accepted.'
}}
"""
            completed = subprocess.run(
                [pwsh, "-NoLogo", "-NoProfile", "-Command", command],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_every_forward_and_recovery_rename_boundary(self) -> None:
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("pwsh is unavailable for transaction behavior tests")
        escaped = str(PRODUCER).replace("'", "''")
        command = rf"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{escaped}', [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ throw 'Producer parse failed.' }}
$functionNames = @(
    'Get-Sha256',
    'Assert-Sha256',
    'Assert-FileSize',
    'Assert-RegularPath',
    'Assert-NoReparseAncestors',
    'Flush-DurableFile',
    'Write-Utf8Durably',
    'Assert-SamePublicationDirectory',
    'Move-AwgTransactionPath',
    'Read-ValidatedAwgTransactionJournal',
    'Restore-AwgTransaction',
    'Publish-AwgGenerationTransaction'
)
foreach ($functionName in $functionNames) {{
    $matches = @($ast.FindAll({{
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }}, $true))
    if ($matches.Count -ne 1) {{ throw "Missing function $functionName." }}
    Invoke-Expression $matches[0].Extent.Text
}}

function New-Fixture {{
    param([string]$Root)
    [void][IO.Directory]::CreateDirectory($Root)
    $destinationRoot = Join-Path $Root 'published'
    [void][IO.Directory]::CreateDirectory($destinationRoot)
    $sourceRoot = Join-Path $Root 'sources'
    [void][IO.Directory]::CreateDirectory($sourceRoot)
    $entries = @()
    for ($index = 0; $index -lt 5; $index++) {{
        $source = Join-Path $sourceRoot ("$index.new")
        $destination = Join-Path $destinationRoot ("$index.bin")
        [IO.File]::WriteAllText($source, "new-$index")
        [IO.File]::WriteAllText($destination, "old-$index")
        $entries += [ordered]@{{
            Source = $source
            Destination = $destination
            Sha256 = Get-Sha256 -Path $source
            Bytes = (Get-Item -LiteralPath $source).Length
            Label = "fixture-$index"
        }}
    }}
    return $entries
}}

function Assert-OldGeneration {{
    param([object[]]$Entries)
    for ($index = 0; $index -lt $Entries.Count; $index++) {{
        if ([IO.File]::ReadAllText([string]$Entries[$index].Destination) -cne
            "old-$index") {{
            throw "Destination $index was not restored to the old generation."
        }}
    }}
}}

$suiteRoot = Join-Path '/private/tmp' (
    'winsvpn-awg-transaction-test-' + [guid]::NewGuid().ToString('N'))
try {{
    for ($boundary = 1; $boundary -le 10; $boundary++) {{
        $root = Join-Path $suiteRoot ("forward-$boundary")
        $entries = @(New-Fixture -Root $root)
        $journal = Join-Path (Split-Path -Parent $entries[0].Destination) `
            '.winsvpn-awg31-publication.json'
        $transactionRoot = Join-Path $root ('transaction-' + ('a' * 32))
        $failed = $false
        try {{
            Publish-AwgGenerationTransaction -Entries $entries `
                -JournalPath ([string]$journal) -TransactionRoot $transactionRoot `
                -TransactionId ('a' * 32) -FailAfterRename $boundary `
                -SimulateCrash
        }} catch {{
            $failed = $true
        }}
        if (-not $failed -or -not (Test-Path -LiteralPath $journal)) {{
            throw "Forward boundary $boundary was not durably recoverable."
        }}
        Restore-AwgTransaction -JournalPath ([string]$journal) `
            -AllowedDestinations @($entries | ForEach-Object {{ $_.Destination }}) `
            -AllowedTransactionParent $root
        Assert-OldGeneration -Entries $entries
    }}

    for ($boundary = 1; $boundary -le 10; $boundary++) {{
        $root = Join-Path $suiteRoot ("recovery-$boundary")
        $entries = @(New-Fixture -Root $root)
        $journal = Join-Path (Split-Path -Parent $entries[0].Destination) `
            '.winsvpn-awg31-publication.json'
        $transactionRoot = Join-Path $root ('transaction-' + ('b' * 32))
        try {{
            Publish-AwgGenerationTransaction -Entries $entries `
                -JournalPath ([string]$journal) -TransactionRoot $transactionRoot `
                -TransactionId ('b' * 32) -FailAfterRename 10 -SimulateCrash
        }} catch {{}}
        $failed = $false
        try {{
            Restore-AwgTransaction -JournalPath ([string]$journal) `
                -AllowedDestinations @($entries | ForEach-Object {{ $_.Destination }}) `
                -AllowedTransactionParent $root `
                -FailAfterRename $boundary
        }} catch {{
            $failed = $true
        }}
        if (-not $failed -or -not (Test-Path -LiteralPath $journal)) {{
            throw "Recovery boundary $boundary was not restartable."
        }}
        Restore-AwgTransaction -JournalPath ([string]$journal) `
            -AllowedDestinations @($entries | ForEach-Object {{ $_.Destination }}) `
            -AllowedTransactionParent $root
        Assert-OldGeneration -Entries $entries
    }}
}} finally {{
    Remove-Item -LiteralPath $suiteRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}}
"""
        completed = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
