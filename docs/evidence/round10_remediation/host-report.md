A10-05: IMPLEMENTED. Focused runtime test PASS.

Changes:
- `tools/native_messaging/host/bin/wins_bridge_host.dart:164`: `_originAuthorized` now requires `allowedOrigins.isNotEmpty && allowedOrigins.contains(_callerOrigin)`; adjacent documentation matches the condition.
- `tools/native_messaging/host/test/wins_bridge_host_identity_test.dart`: existing fake-discovery, public-MAC, missing-owner-root and disconnected-app checks now use a configured matching caller so the new origin gate does not mask their original identity coverage. Seven connected-app denial cases cover empty origins with absent/matching/foreign/prefix-extended callers, and nonempty origins with absent/foreign/prefix-extended callers. Each asserts no credential token and no proxy port, while status queries still work. The authenticated connected-app positive case still mints and revokes a credential for an exact configured origin.

Command outcomes:
- From `tools/native_messaging/host`: `/Users/owner/.local/flutter/bin/cache/dart-sdk/bin/dart --packages=.dart_tool/package_config.json test/wins_bridge_host_identity_test.dart`.
- New tests against pre-fix host: exit 255, `origin must not mint: expected false, got true` (`host-before.log`). This proves the regression catches the original empty-set bypass.
- Same command after source fix: exit 0 (`host-after.log`). All existing identity checks and seven new origin denials passed.
- Dart SDK: 3.12.2 stable, macos_arm64. No package resolution or Flutter invocation.

Installer compatibility review, necessary follow-up BEFORE treating the installed bridge as working:
- Repository search for `allowed_origins.txt` found only the host reader and its comments, no producer. `install_native_host.sh:580`, `install_macos_native_host.sh:597`, `register_native_host.ps1:144`, and their shared layout/manifest renderer write browser JSON registrations, not the companion file read at `wins_bridge_host.dart:475`. With this fix, an installation lacking that file refuses all credentials even when the browser manifest authorizes the extension.
- Required installer follow-up: provision the exact configured caller entries beside the installed host, keep them consistent with all registered browsers sharing that binary, and integrate permissions, rollback, uninstall and read-back validation into the existing installation flow. Do not infer authorization from an empty file. No installer changes made.
- Separate existing host compatibility issue: `main` at lines 448-453 accepts only `chrome-extension://` and `moz-extension://` argv entries. Firefox passes the manifest path and the add-on ID, so its documented caller format is not captured. Installer provisioning alone will not restore Firefox credential issuance. This needs a separately scoped host parser change and browser invocation test; left unchanged because this task authorizes only the origin predicate fix.
- The nonshipping `wins_bridge_host_harness.dart:152` also constructs a host without origins or caller setup. Its positive proxy flows will now refuse credentials until the harness explicitly configures test identity. Left unchanged and reported for root.
- These focused tests use injected caller identity and authenticated local IPC, not a browser or installed production binary.

Official documentation checked live on 2026-09-13:
- Dart `isNotEmpty` means at least one element; `contains` checks membership: https://api.dart.dev/dart-core/Iterable/isNotEmpty.html and https://api.dart.dev/dart-core/Set/contains.html
- Chrome caller origin and manifest authorization: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- Firefox passes manifest path and add-on ID: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging

Scope: local fallback lane, no delegation. Read AGENTS.md. Preserved pre-existing edits; no stage, commit, push, deployment, external messaging, Flutter command, installer edit, or ruling edit. Used the Dart SDK binary directly. Pre-edit snapshots are in `fallback-before/`; the exact lane-only delta is `fallback-lane.patch`, both beside this report. Edited files are LF; added lines have no en/em dashes. Scoped `git diff --check` exited 0. Root owns full verification and the final release decision.

Final edited-file SHA-256 at report time:
- `tools/native_messaging/host/bin/wins_bridge_host.dart`: `eec5fe5f056561c22f3db13a497eb1ed922a108c356f2a2b36391d0b1f45facb`
- `tools/native_messaging/host/test/wins_bridge_host_identity_test.dart`: `d075216d2ba40a0d3d79d4463736ef7c5ae3e47ed7ead88782b04030bfb231d8`
