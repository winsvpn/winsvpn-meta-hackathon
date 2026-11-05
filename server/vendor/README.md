# Vendored trust material for `wins_core_server_setup_ONETOUCH.sh`

This directory holds third-party trust material that the core setup script
verifies against pinned constants *before* it is used, instead of downloading
and trusting it at deploy time (see finding M-16).

## `cloudflare-main.gpg` (fully populated 2026-07-22)

All four gate constants are now populated and independently corroborated from
two separate vantage points (not fabricated, and not trusted from a single
AI-generated report without re-derivation):

- `CLOUDFLARE_KEY_SHA256`: `1bd95f4082b320d541bee351560fc2765aa9f9cd8efa4c9e32135e63f252721d`
  -- fetched directly from `https://pkg.cloudflare.com/cloudflare-main.gpg`,
  hashed with `shasum -a 256`.
- `CLOUDFLARE_KEY_FINGERPRINT`: `CC94B39C77AE7342A68B89628A682D308D4E5E73`
  (the primary key; UID `CloudFlare Software Packaging 2025 <help@cloudflare.com>`,
  key ID `8A682D308D4E5E73`) -- computed with
  `gpg --show-keys --with-colons cloudflare-main.gpg | grep '^fpr:'` against
  the vendored file, then re-derived from scratch by fetching a second, fresh
  copy of the key from a different host and re-running the same command; both
  the sha256 and the fingerprint matched exactly across both fetches.
- Core cloudflared: exact upstream version `2026.10.0`, commit
  `18cdfe0a6fc7b72a0702d255a1f984e776ce0498`, rebuilt as
  `2026.10.0-security1`. The Core installer verifies the immutable source
  archive, the vendored dependency patch, official Go 1.27.1 toolchain bytes,
  the resolved `go.sum`, and the final per-architecture executable hash. The
  source archive digest and both output digests were measured by the build lane
  on 2026-10-07 and are reproducible from clean caches. Review:
  `cloudflared-2026.10.0-security-review.md`.
  GO-2026-5932 (unmaintained OpenPGP, no fixed version) remains; no package in
  the build graph imports it, but the govulncheck source-mode proof has not been
  re-run for 2026.10.0. The superseded 2026.8.3 patch is obsolete for the Core
  build; the 2026.8.3 review stays because the control and Data deb disposition
  test still reads it.

See the constants comment near `XRAY_VERSION` in both script copies for the
full verification trail. The gate now passes.

## `cloudflared-2026.10.0-security.patch`

This dependency-only patch raises `golang.org/x/crypto` to v0.56.0 (GO-2026-6354,
GO-2026-6355) and `github.com/klauspost/compress` to v1.18.7 (GO-2026-5841), and
changes the `go` line to `1.26.0` as crypto v0.56.0 requires. Upstream 2026.10.0
already carries the fixed `x/net`, `x/sys`, `x/term` and `x/text`. The Core
installer hashes the patch before applying it and checks the post-download
`go.sum` before building. Any source, toolchain, module-resolution, patch, or
output-byte drift fails closed.


`install_cloudflared_package()` in the control and Data installers expects a
vendored copy of Cloudflare's package-repository signing key at:

```
server/vendor/cloudflare-main.gpg
```

Until this file exists and the matching constants are populated, those
installers fail closed at the cloudflared install step instead of downloading
and trusting an unverified key. The Core source-build path does not use this
repository key.

### How this was populated (for future re-rotation)

Cloudflare will rotate this key again eventually (as they did on
2025-10-30). When that happens, repeat this process:

1. Fetch the current key from Cloudflare's own documented endpoint, e.g.:
   `curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o cloudflare-main.gpg`
   (see the official instructions at https://pkg.cloudflare.com/ — make sure
   you are fetching the *current* key, not a cached/old copy).
2. Independently corroborate the key (e.g. compare the fetched bytes/fingerprint
   against a second vantage point, a colleague's independent download, or any
   fingerprint Cloudflare publishes in its own docs) before trusting it — a
   single HTTPS download of the same artifact you are trying to pin is not
   independent verification by itself.
3. Compute the values the script checks:
   - `sha256sum cloudflare-main.gpg` -> set `CLOUDFLARE_KEY_SHA256` near the
     `XRAY_VERSION` constants at the top of both copies of
     `wins_core_server_setup_ONETOUCH.sh`.
   - `gpg --show-keys --with-colons cloudflare-main.gpg | grep '^fpr:'` -> set
     `CLOUDFLARE_KEY_FINGERPRINT` to the *primary* key's fingerprint field
     (not a subkey's).
4. Pick a specific, reviewed `cloudflared` version (do not use "latest"). For
   the Core installer, review the exact source commit, fixed Go patch line, and
   dependency closure. Record source, patch, toolchain, resolved `go.sum`, and
   reproducible amd64/arm64 output hashes. Run both binary and source-mode
   govulncheck, then explicitly disposition every remaining result.
5. Copy `cloudflare-main.gpg` into `server/vendor/` and set the same package
   constants in the control and Data installers.
6. Run `PYTHONPATH=. python3 tools/validate_deployment_scripts.py` and confirm
   all three deployment roles pass the immutable dependency gates.

Do not fabricate any of these values — an incorrect hash/fingerprint just
fails closed (safe but broken); an incorrect *source* for the key (i.e. not
really from Cloudflare) defeats the whole point of pinning it.
