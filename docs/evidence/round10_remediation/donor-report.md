DB-07: PASS (2026-09-13)

Changed server/test_donor_acknowledgment_hub.py only.
Added inspect and call_handler(handler, *args, **kwargs). It invokes the handler once, uses harness.asyncio.run only when inspect.isawaitable(result), otherwise returns the result. Updated all five admin route invocation sites. The async PayPal webhook invocation and all assertions remain unchanged by this lane.

Preserved the existing dirty change: LEGAL_DOCUMENT_ACCEPTED_HASHES expected length remains 3. Lane-only delta: donor-lane.diff; pre-edit bytes: donor.before.py.

Verification:
- PYTHONDONTWRITEBYTECODE=1 python3.14 server/test_donor_acknowledgment_hub.py: exit 0, 57 passed, 0 failed, 57 total. Complete output: donor-test.log.
- Runtime verified: Python 3.14.7, OpenSSL 3.6.4. Used the available Homebrew Python because the server preflight requires Python >=3.10.
- Scoped git diff --check, Python AST parse, LF and no em/en dash checks: passed. Final post-test change only aligned indentation in the manual admin call.

Live official documentation checked:
- https://docs.python.org/3/library/inspect.html#inspect.isawaitable
- https://docs.python.org/3/library/asyncio-runner.html#asyncio.run

No control-plane edits, package builds, Flutter commands, delegation, staging, commits, pushes, deployment, messaging, or ruling edits. Root retains integration/full verification.
