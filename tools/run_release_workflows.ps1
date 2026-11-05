param(
    [string]$Ref = "",
    [switch]$Apple,
    [switch]$Linux,
    [switch]$Wait,
    [string]$LinuxStagingReleaseTag = "",
    [string]$LinuxStagingAssetId = "",
    [string]$LinuxExpectedSha256 = ""
)

$ErrorActionPreference = "Stop"
throw "tools/run_release_workflows.ps1 is retired. GitHub is backup storage only and cannot build, sign, verify, or publish a release. Use the local platform release coordinators and preserve their evidence."
