# Live public website download audit

Read-only, fail-closed check of the production download surface. It is an
independent live-origin audit, not a website deploy, GitHub mutation, signing,
or packaging step.

## What it reads

The gate fetches only:

- `https://winsvpn.org/`
- `https://winsvpn.org/releases/downloads.json`

Requests use strict TLS, an empty proxy map (`trust_env`/environment proxy
lookup disabled), bounded time and body size, and they refuse redirects that
leave `https://winsvpn.org` or those two paths. Android and Windows artifact
bytes are never downloaded. The homepage response must include HSTS, CSP,
`X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`. A CSP hash
placeholder (`sha256-<REDACTED...>`) is stop-ship.

## Before a signed release is authorized

Every platform in the live manifest must be `verification_pending` with null
URL, filename, SHA-256, and byte count. The HTML must not expose active
download anchors. If an available Android or Windows artifact is still
advertised, the gate binds the exact URL, size, and hash and prints a
stop-ship reason, including the independently verified v1.0.0 debug APK and
unsigned Windows identities.

## Run

```sh
python3 tools/test_public_website_download_live_gate.py
python3 tools/public_website_download_live_gate.py
```

## After an owner-authorized publication deploy

Per-platform launch (owner ruling 2026-10-25) makes some entries available
while others stay `verification_pending` or `store_pending`. The default mode
above treats any advertised binary as stop-ship, so after the deploy run the
published mode with the exact `web/releases/downloads.json` that
`tools/verify_website_public_download_gate.py` reported READY for:

```sh
python3 tools/public_website_download_live_gate.py --published-manifest <staged pages>/releases/downloads.json
```

It fetches `/` and `/releases/downloads.json`; for entries hosted on the pinned
GitHub release (`github_release`, tag `v1.0.16-33`) it also downloads each asset
through exactly one redirect to GitHub's release-asset host and requires the
manifest byte count and SHA-256. R2-served bytes are not fetched here.
PASS requires the live manifest bytes to equal the gate-passed bytes exactly,
the closed v2 entry order, exact production URLs for available entries, and no
static download or store anchor in the HTML. Artifact serving itself is checked
with the HEAD and GET commands in `WEBSITE_DOWNLOAD_R2_PUBLICATION.md`.

The unit tests keep the network disabled and inject fixtures. The gate command
is the live origin read. Exit 0 is PASS. Any other exit means a signed release
is not authorized from this audit.
