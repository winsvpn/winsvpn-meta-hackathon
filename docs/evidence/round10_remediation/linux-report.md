DB-04: IMPLEMENTED. Focused compiled regression PASS.

Changes:
- `linux/runner/linux_tunnel_backend.cc:4485`: added `StopTunnelPowerProtection()` immediately after `StopLinuxBypassSlice()` on the standalone Winn v3 disconnect branch. Both run before the branch checks teardown success, covering failure and retry as well as success. No other process lifecycle code changed.
- `tools/test_linux_tunnel_shutdown.py`: added exact bypass/power/Xray counter assertions after failed standalone cleanup, successful retry and the subsequent no-op shutdown. Existing committed-session and AWG stop counters remain checked. This pre-existing untracked test file was extended in place and preserved.

Command outcomes:
- `python3 tools/test_linux_tunnel_shutdown.py` with new assertions against old source: exit 1; compiled assertion failed in normal, SIGINT and SIGTERM modes because power cleanup was absent (`linux-before.log`).
- Same command after source fix: exit 0, 1 test with normal/SIGINT/SIGTERM executions (`linux-after.log`). Harness compiles actual teardown functions with C++17, `-Wall -Werror -UNDEBUG`, GLib and recording native-resource fakes.
- `python3 tools/test_linux_round7.py`: exit 0, 1 test (`linux-power.log`). Existing compiled power-inhibition harness covers start, repeated start, missing tools, start failure and repeated stop using recording command fakes.
- Tests executed on macOS with local C++ and gio-2.0. They do not prove a live Linux systemd service was stopped. No host tunnel, service or route was changed.

Official documentation checked live on 2026-09-13: systemd-inhibit holds its lock for the executed command's lifetime and releases it afterwards: https://www.freedesktop.org/software/systemd/man/250/systemd-inhibit.html . The latest manpage URL returned an internal web retrieval error; the official versioned page was available. Production already stops the named user service in `StopTunnelPowerProtection`; this task only wires the existing helper into standalone disconnect.

Scope: local fallback lane, no delegation. Read AGENTS.md. Preserved pre-existing edits; no stage, commit, push, deployment, external messaging, Flutter command, installer edit, or ruling edit. Used the Dart SDK binary directly. Pre-edit snapshots are in `fallback-before/`; the exact lane-only delta is `fallback-lane.patch`, both beside this report. Edited files are LF; added lines have no en/em dashes. Scoped `git diff --check` exited 0. Root owns full verification and the final release decision.

Final edited-file SHA-256 at report time:
- `linux/runner/linux_tunnel_backend.cc`: `559030b209b25c66075e77dac7f583899ab239b3fe10fb0cf00ee3c5b00e0d34`
- `tools/test_linux_tunnel_shutdown.py`: `3fd4990d753331ec4f7e6bebaf0d74b417f94b97697f0699ca2563d4c8533c49`
