DB-08: IMPLEMENTED. Both requested suites PASS.

Changes, tests only:
- `tools/test_windows_awg_runtime_validation.py`: replaced obsolete `kSystemAdminDaclSddl` with assertions tying directory creation and protected owner/DACL application to `kSystemAdminDirectorySddl`, and atomic AWG config writing to `kSystemAdminFileSddl`. Added exact declaration checks: directory `O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` and file `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`. This retains SYSTEM ownership, protected DACLs, SYSTEM/Administrators-only full access, and directory inheritance flags. Existing atomic/non-reparse/unique-name/deletion and Xray checks remain.
- `tools/test_windows_arm64_release_readiness.py`: replaced old unsealed `$Winn3ArtifactInputDir` assertions with architecture-specific `$ReleaseDir`, staged core and relay paths, and checks scoped to `Invoke-Winn3ArtifactProvenanceVerification`. Asserts sealed-pair verification, candidate architecture and release-stage arguments, owner receipt and signed-artifact hash bindings, failure handling, bounded staged inputs and PE machine checks on BOTH core and relay. Rejects reintroduction of the old input directory. Existing native ARM64 dependency hashes and PE headers remain checked.
- Reviewed `windows/runner/windows_tunnel_backend.cpp:1168,3790,3821` and `installer/windows/build_installer.ps1:1051,1332,1380,3909-4017`. No production Windows or installer edits.

Command outcomes:
- Before changes: `python3 -m unittest tools.test_windows_awg_runtime_validation tools.test_windows_arm64_release_readiness`: exit 1, 39 tests, exactly 2 stale assertion failures (`windows-before.log`).
- `python3 tools/test_windows_awg_runtime_validation.py`: exit 0, 31 tests (`windows-awg-after.log`).
- `python3 tools/test_windows_arm64_release_readiness.py`: exit 0, 8 tests (`windows-arm64-after.log`).
- These are source-contract and local artifact checks on macOS, not Windows runtime or installer execution proof.

Official documentation checked live on 2026-09-13:
- Protected DACL syntax and SDDL flags: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
- ACE rights and object/container inheritance flags: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings

Scope: local fallback lane, no delegation. Read AGENTS.md. Preserved pre-existing edits; no stage, commit, push, deployment, external messaging, Flutter command, installer edit, or ruling edit. Used the Dart SDK binary directly. Pre-edit snapshots are in `fallback-before/`; the exact lane-only delta is `fallback-lane.patch`, both beside this report. Edited files are LF; added lines have no en/em dashes. Scoped `git diff --check` exited 0. Root owns full verification and the final release decision.

Final edited-file SHA-256 at report time:
- `tools/test_windows_awg_runtime_validation.py`: `ee41b3832174582c7716d6ad8ce1574025bd4a49f43e81c725b766e5053a0dc3`
- `tools/test_windows_arm64_release_readiness.py`: `c1d27a50f5f44bfe3b2b3624177f74f6b04521f872adeee474ff9da921042bbe`
