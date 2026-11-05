SOL-L2: PASS (2026-09-13)

Changed extension/src/background/background.js and added extension/tools/test_background_lifecycle.py only.
startReady calls ready().catch and records a fixed, safe initialization failure/retry message without copying error details. onInstalled, onStartup, and plain load use it. ready() and handlers awaiting it retain rejection/retry behavior.

Verification:
- PYTHONDONTWRITEBYTECODE=1 python3.14 -m pytest -p no:cacheprovider -q extension/tools/test_background_lifecycle.py: exit 0, 6 passed in 0.21s.
- Node runs with --unhandled-rejections=strict. Injected init rejection is handled on load/install/startup; later events retry successfully. Auth/alarm still reject with the original error; message handler returns its existing error response. No dependent action runs after failed init.
- External negative control used background.before.js with the same tests: pytest exit 1, all 6 failed as expected due to the unhandled initialization rejection. See extension-negative-test.log.
- Scoped git diff --check, Python AST parse, LF and no em/en dash checks: passed.

Live official documentation checked:
- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/catch
- https://developer.mozilla.org/en-US/docs/Web/API/Window/unhandledrejection_event

Lane-only source delta: extension-lane.diff. New test file is in the checkout. No package builds, Flutter commands, delegation, staging, commits, pushes, deployment, messaging, or ruling edits. Root retains integration/full verification and package builds.
