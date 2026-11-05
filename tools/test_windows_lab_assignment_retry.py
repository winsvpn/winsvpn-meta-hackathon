from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKER = ROOT / "tools" / "windows_lab_interactive_worker.ps1"


def powershell_executable() -> str | None:
    names = (
        ("powershell.exe", "pwsh")
        if os.name == "nt"
        else ("pwsh", "powershell.exe")
    )
    for name in names:
        value = shutil.which(name)
        if value:
            return value
    bundled = (
        pathlib.Path.home()
        / "Library"
        / "Application Support"
        / "WinsVPN"
        / "toolchains"
        / "powershell-7.6.4"
        / "pwsh"
    )
    return str(bundled) if bundled.is_file() else None


class WindowsLabAssignmentRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKER.read_text(encoding="utf-8")
        cls.functions = cls.text[
            cls.text.index("function Get-WinsVpnResponseHeaderValue") :
            cls.text.index("function Add-LocalClientKeys")
        ]
        cls.json_writers = cls.text[
            cls.text.index("function Write-NewJson") :
            cls.text.index("function Assert-Valid")
        ]

    def test_retry_contract_is_exact_bounded_and_body_stable(self) -> None:
        retry = self.functions
        self.assertIn("'double_vpn_assignment_preparing'", retry)
        self.assertIn(
            "'Double VPN Core assignment is still being prepared. Please try again.'",
            retry,
        )
        self.assertIn("$maximumElapsedMilliseconds = 120000L", retry)
        self.assertIn("$requestTimeoutSeconds = 7", retry)
        self.assertIn("$deadlineSafetyMilliseconds = 250L", retry)
        self.assertIn("[Diagnostics.Stopwatch]::StartNew()", retry)
        self.assertIn("-Body $bodyBytes", retry)
        self.assertEqual(retry.count("$bodyBytes ="), 1)
        self.assertIn("return 1000L", retry)
        self.assertIn("[Math]::Min(10000L", retry)
        self.assertIn("[Math]::Max(250L", retry)
        self.assertIn("if (-not $preparing) { break }", retry)
        self.assertIn(
            "[System.Collections.Specialized.NameValueCollection]", retry
        )
        self.assertIn("$Headers.GetValues($Name)", retry)
        self.assertIn("$Headers.TryGetValues($Name, [ref]$values)", retry)
        self.assertIn("[Net.Http.HttpClient]", retry)
        self.assertIn("Add-Type -AssemblyName System.Net.Http", retry)
        self.assertIn(
            "[Net.Http.HttpCompletionOption]::ResponseContentRead", retry
        )
        self.assertIn(
            "$client.MaxResponseContentBufferSize = 1048576L", retry
        )
        self.assertIn("$handler.AllowAutoRedirect = $false", retry)
        self.assertIn("$safeHeaders = [ordered]@{}", retry)
        self.assertNotIn("Headers = $response.Headers", retry)
        self.assertNotIn("ConvertFrom-WinsVpnVerifyWebFailure", retry)
        self.assertIn(
            "Live /verify response downgraded or omitted the requested Double VPN route.",
            retry,
        )

    def test_retry_behavior_with_mocked_http_responses(self) -> None:
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        command = (
            "$ErrorActionPreference='Stop'\n"
            + "function Get-StringSha256 { param([string]$Value) "
            + "$a=[Security.Cryptography.SHA256]::Create();try{"
            + "([BitConverter]::ToString($a.ComputeHash("
            + "[Text.UTF8Encoding]::new($false).GetBytes($Value))))"
            + ".Replace('-','').ToLowerInvariant()}finally{$a.Dispose()}}\n"
            + "$PrivateRoot='/tmp/private';$RunId='00000000-0000-0000-0000-000000000000';"
            + "$script:verifyDiagnostic=$null;"
            + "function Write-AtomicJson { param([string]$Path,$Value) "
            + "$script:verifyDiagnostic=$Value }\n"
            + self.functions
            + r'''
function Read-JsonOnce {
    param([string]$Path)
    [pscustomobject]@{
        run_id = $RunId
        artifact_sha256 = ('a' * 64)
        collector_closure_sha256 = ('b' * 64)
    }
}
function Set-WinsVpnVerifyDiagnosticOwnerOnlyAcl { param([string]$Path) }
function Start-Sleep {
    param([long]$Milliseconds)
    $script:sleeps += $Milliseconds
}
$credential = [pscustomobject]@{
    verify_uri = 'https://example.invalid/verify'
    node_request = [ordered]@{ double_vpn = $false; device_id = 'same-device' }
    core_request = [ordered]@{ double_vpn = $true; device_id = 'same-device' }
}
$script:mode = 'pending-then-success'
$script:calls = 0
$script:sleeps = @()
$script:bodies = @()
function Invoke-WinsVpnVerifyHttpRequest {
    param(
        [Net.Http.HttpClient]$Client, [Uri]$Uri, [byte[]]$Body
    )
    ++$script:calls
    $script:bodies += [Convert]::ToBase64String($Body)
    if ($script:mode -eq 'pending-then-success' -and $script:calls -eq 1) {
        return [pscustomobject]@{
            StatusCode = 503
            Content = '{}'
            Headers = @{
                'X-Wins-Error-Code' = 'double_vpn_assignment_preparing'
                'Retry-After' = '0'
            }
        }
    }
    if ($script:mode -eq 'generic') {
        return [pscustomobject]@{
            StatusCode = 503
            Content = '{"detail":"Double VPN core is not available yet."}'
            Headers = @{}
        }
    }
    if ($script:mode -eq 'single-pending') {
        return [pscustomobject]@{
            StatusCode = 503
            Content = '{}'
            Headers = @{'X-Wins-Error-Code'='double_vpn_assignment_preparing'}
        }
    }
    if ($script:mode -eq 'unsafe-detail') {
        return [pscustomobject]@{
            StatusCode = 503
            Content = '{"detail":"secret endpoint token must never persist"}'
            Headers = @{'X-Wins-Error-Code'='untrusted_backend_value'}
        }
    }
    return [pscustomobject]@{
        StatusCode = 200
        Content = '{"status":"authenticated","vpn_config":{"double_vpn_active":true,"double_vpn_core_id":"core-1","double_vpn_exit_slug":"spain"}}'
        Headers = @{}
    }
}
$result = Invoke-VerifyRequest $credential $true
if ($script:calls -ne 2 -or $script:sleeps.Count -ne 1 -or
    $script:sleeps[0] -ne 250 -or $script:bodies[0] -cne $script:bodies[1] -or
    $result.Json.vpn_config.double_vpn_active -ne $true -or
    $result.AttemptCount -ne 2) { exit 11 }

$script:mode = 'generic'; $script:calls = 0; $script:bodies = @()
try { $null = Invoke-VerifyRequest $credential $true; exit 12 }
catch {
    if ($_.Exception.Message -cne
            'Live /verify request was not accepted (status=503, code=double_vpn_core_unavailable).' -or
        $script:calls -ne 1 -or
        $script:verifyDiagnostic.status_code -ne 503 -or
        $script:verifyDiagnostic.error_code -cne 'double_vpn_core_unavailable' -or
        $script:verifyDiagnostic.requested_mode -cne 'double' -or
        $script:verifyDiagnostic.attempt_count -ne 1 -or
        $script:verifyDiagnostic.artifact_sha256 -cne ('a' * 64) -or
        $script:verifyDiagnostic.collector_closure_sha256 -cne ('b' * 64) -or
        [string]$script:verifyDiagnostic.response_body_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        $script:verifyDiagnostic.raw_response_persisted -ne $false) {
        Write-Output ("GENERIC_FAILURE=" + $_.Exception.Message +
            " DIAGNOSTIC=" + ($script:verifyDiagnostic | ConvertTo-Json -Compress))
        exit 13
    }
}

$script:mode = 'single-pending'; $script:calls = 0; $script:bodies = @()
try { $null = Invoke-VerifyRequest $credential $false; exit 14 }
catch {
    if ($_.Exception.Message -cne
            'Live /verify request was not accepted (status=503, code=double_vpn_assignment_preparing).' -or
        $script:calls -ne 1) { exit 15 }
}

$script:mode = 'unsafe-detail'; $script:calls = 0
try { $null = Invoke-VerifyRequest $credential $false; exit 21 }
catch {
    $rendered = $script:verifyDiagnostic | ConvertTo-Json -Depth 8 -Compress
    if ($_.Exception.Message -cne
            'Live /verify request was not accepted (status=503, code=service_unavailable).' -or
        $script:verifyDiagnostic.error_message -cne
            'The verification service was unavailable.' -or
        $rendered -match 'secret|endpoint|token|untrusted_backend_value') { exit 22 }
}

$legacy = '{"detail":"Double VPN Core assignment is still being prepared. Please try again."}'
if (-not (Test-WinsVpnDoubleAssignmentPreparing -StatusCode 503 -Body $legacy -Headers @{})) { exit 16 }
if (Test-WinsVpnDoubleAssignmentPreparing -StatusCode 503 -Body $legacy `
        -Headers @{'X-Wins-Error-Code'='different'} ) { exit 17 }
if ((Get-WinsVpnDoubleAssignmentRetryDelayMilliseconds `
        -Headers @{'Retry-After'='999'}) -ne 10000) { exit 18 }
if ((Get-WinsVpnDoubleAssignmentRetryDelayMilliseconds `
        -Headers @{'Retry-After'='invalid'}) -ne 1000) { exit 19 }

# Exercise the WebHeaderCollection shape used by Windows PowerShell 5.1.
$legacyHeaders = New-Object System.Net.WebHeaderCollection
$legacyHeaders.Add('X-Wins-Error-Code', 'double_vpn_assignment_preparing')
$legacyHeaders.Add('Retry-After', '5')
if ((Get-WinsVpnResponseHeaderValue -Headers $legacyHeaders `
        -Name 'X-Wins-Error-Code') -cne
        'double_vpn_assignment_preparing' -or
    (Get-WinsVpnResponseHeaderValue -Headers $legacyHeaders `
        -Name 'Retry-After') -cne '5' -or
    $null -ne (Get-WinsVpnResponseHeaderValue `
        -Headers @{'Retry-After'=('x' * 257)} -Name 'Retry-After')) { exit 20 }
'''
        )
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_non_2xx_http_response_is_intact_without_webexception(self) -> None:
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        request_bodies: list[bytes] = []

        class VerifyHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
                length = int(self.headers.get("Content-Length", "0"))
                request_bodies.append(self.rfile.read(length))
                if len(request_bodies) == 1:
                    body = b"{}"
                    self.send_response(503)
                    self.send_header(
                        "X-Wins-Error-Code",
                        "double_vpn_assignment_preparing",
                    )
                    self.send_header("Retry-After", "0")
                    # This must never be retained by the worker result.
                    self.send_header("Set-Cookie", "private-test-value")
                else:
                    body = (
                        b'{"status":"authenticated","vpn_config":'
                        b'{"double_vpn_active":true,'
                        b'"double_vpn_core_id":"core-1",'
                        b'"double_vpn_exit_slug":"spain"}}'
                    )
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VerifyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            command = (
                "$ErrorActionPreference='Stop'\n"
                + "function Get-StringSha256 { param([string]$Value) "
                + "$a=[Security.Cryptography.SHA256]::Create();try{"
                + "([BitConverter]::ToString($a.ComputeHash("
                + "[Text.UTF8Encoding]::new($false).GetBytes($Value))))"
                + ".Replace('-','').ToLowerInvariant()}finally{$a.Dispose()}}\n"
                + self.functions
                + f"\n$credential=[pscustomobject]@{{verify_uri='http://127.0.0.1:{server.server_port}/verify';"
                + "node_request=[ordered]@{double_vpn=$false;device_id='same-device'};"
                + "core_request=[ordered]@{double_vpn=$true;device_id='same-device'}}\n"
                + "$result=Invoke-VerifyRequest $credential $true\n"
                + "if($result.Json.vpn_config.double_vpn_active -ne $true){exit 31}\n"
            )
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(request_bodies), 2)
        self.assertEqual(request_bodies[0], request_bodies[1])

    def test_repeated_failures_in_the_same_run_do_not_collide(self) -> None:
        # verify-error.json is legitimately written more than once per run
        # (Node verify can succeed while Core verify fails, or a later
        # route-lane retry can fail again). It must be replaced cleanly on
        # every failure rather than raising a raw filesystem exception that
        # would hide the intended safe error message.
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory() as private_root:
            posix_root = pathlib.Path(private_root).as_posix()
            command = (
                "$ErrorActionPreference='Stop'\n"
                + "function Get-StringSha256 { param([string]$Value) "
                + "$a=[Security.Cryptography.SHA256]::Create();try{"
                + "([BitConverter]::ToString($a.ComputeHash("
                + "[Text.UTF8Encoding]::new($false).GetBytes($Value))))"
                + ".Replace('-','').ToLowerInvariant()}finally{$a.Dispose()}}\n"
                + f"$PrivateRoot='{posix_root}';"
                + "$RunId='00000000-0000-0000-0000-000000000000';\n"
                + "function Read-JsonOnce { param([string]$Path) "
                + "[pscustomobject]@{ run_id=$RunId; "
                + "artifact_sha256=('a'*64); collector_closure_sha256=('b'*64) } }\n"
                + self.json_writers
                + "\n"
                + self.functions
                + "\nfunction Set-WinsVpnVerifyDiagnosticOwnerOnlyAcl { param([string]$Path) }\n"
                + r'''
$credential = [pscustomobject]@{
    verify_uri = 'https://example.invalid/verify'
    node_request = [ordered]@{ double_vpn = $false; device_id = 'same-device' }
    core_request = [ordered]@{ double_vpn = $true; device_id = 'same-device' }
}
function Invoke-WinsVpnVerifyHttpRequest {
    param([Net.Http.HttpClient]$Client, [Uri]$Uri, [byte[]]$Body)
    ++$script:calls
    if ($script:calls -eq 1) {
        return [pscustomobject]@{
            StatusCode = 503
            Content = '{"detail":"Double VPN core is not available yet."}'
            Headers = @{}
        }
    }
    return [pscustomobject]@{
        StatusCode = 401
        Content = '{"detail":"Account Inactive or Invalid"}'
        Headers = @{}
    }
}
$script:calls = 0
Write-Output 'PROBE-START'
try {
    $null = Invoke-VerifyRequest $credential $true
    Write-Output 'UNEXPECTED-SUCCESS-1'
} catch {
    Write-Output ('FIRST=' + $_.Exception.Message)
}
try {
    $null = Invoke-VerifyRequest $credential $false
    Write-Output 'UNEXPECTED-SUCCESS-2'
} catch {
    Write-Output ('SECOND=' + $_.Exception.Message)
}
Write-Output 'PROBE-END'
'''
            )
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(
                'FIRST=Live /verify request was not accepted '
                '(status=503, code=double_vpn_core_unavailable).',
                result.stdout,
            )
            self.assertIn(
                'SECOND=Live /verify request was not accepted '
                '(status=401, code=authentication_rejected).',
                result.stdout,
            )
            self.assertIn('PROBE-START', result.stdout)
            self.assertIn('PROBE-END', result.stdout)
            self.assertNotIn('UNEXPECTED-SUCCESS', result.stdout)
            receipt_path = pathlib.Path(private_root) / "verify-error.json"
            self.assertTrue(receipt_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status_code"], 401)
            self.assertEqual(receipt["error_code"], "authentication_rejected")
            self.assertEqual(receipt["requested_mode"], "single")

    def test_failure_diagnostic_is_strictly_allowlisted(self) -> None:
        functions = self.functions
        self.assertIn("'winsvpn-windows-lab-verify-error-v1'", functions)
        self.assertIn("Write-AtomicJson $path", functions)
        self.assertNotIn("Write-NewJson $path", functions)
        self.assertIn("raw_response_persisted = $false", functions)
        self.assertIn("response_headers_persisted = $false", functions)
        self.assertIn("request_body_persisted = $false", functions)
        self.assertIn("response_body_sha256 = $BodySha256", functions)
        self.assertIn("attempt_count = $AttemptCount", functions)
        self.assertIn("requested_mode = if ($DoubleVpn)", functions)
        self.assertIn("retry_after_seconds = [int]$RetryAfter.seconds", functions)
        self.assertIn("artifact_sha256 = [string]$context.artifact_sha256", functions)
        self.assertIn("Set-WinsVpnVerifyDiagnosticOwnerOnlyAcl $path", functions)
        self.assertIn("[ValidateRange(100, 599)][int]$StatusCode", functions)
        self.assertNotIn("response_body =", functions.lower())
        self.assertNotIn("response_headers =", functions.lower())

    def test_worker_still_parses(self) -> None:
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        path = str(WORKER).replace("'", "''")
        command = (
            "$tokens=$null;$errors=$null;"
            f"$null=[Management.Automation.Language.Parser]::ParseFile('{path}',"
            "[ref]$tokens,[ref]$errors);"
            "if($errors.Count){$errors|%{$_.ToString()};exit 1}"
        )
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
