# cloudflared 2026.10.0 deb disposition for control + data roles

File name note: the path still says 2026.8.2 because the pin test binds this
exact path (`server/test_control_data_cloudflared_deb_pin.py`). The content now
describes the 2026.10.0 deb pins. The original 2026.8.2 text is superseded.

Status: PREMISE NOT RE-ATTESTED FOR 2026.10.0 (UNVERIFIED, review needed).

The earlier disposition (written for 2026.8.2 against the 2026.8.3 review) said
a source rebuild of the control and data roles would be churn, because the
single material delta was GO-2026-5932 in the unmaintained OpenPGP module and
the 2026.8.3 build of `./cmd/cloudflared/...` does not call the affected OpenPGP symbols.
That reachability premise was proven for 2026.8.3 only (govulncheck v1.7.0, see
`server/vendor/cloudflared-2026.8.3-security-review.md`).

The premise has NOT been re-attested for 2026.10.0. Only static evidence exists for 2026.10.0 (see
`server/vendor/cloudflared-2026.10.0-security-review.md`): no package in the
2026.8.3 build graph imports `golang.org/x/crypto/openpgp`, and the 2026.8.3 to
2026.10.0 source comparison adds no such import. That is not a call graph
proof. Until a govulncheck run on the 2026.10.0 source is recorded, treat the
premise as unverified and this disposition as provisional.

## What is known about the 2026.10.0 deb

- Pinned version and per-architecture digests (identical in both installers,
  and equal to the SHA256 fields in Cloudflare's apt `Packages` index, read on
  2026-10-06):
  - amd64 `9721287c28f78cb623e77c7b95a63feea87e909054d75666a0ec9eff20e5d548`
  - arm64 `7e0d76de3858b6396bd234ae26182bee222133398667d2647b90381d00c00e98`
- Toolchain, read from the 2026.10.0 source, not from the deb (the deb was not
  downloaded or inspected): the upstream CI builder image installs
  `go-boring=1.26.8-1` and `GO_VERSION` is `1.26.8`, so the official Linux
  packages are expected to be built with Go 1.26.8. This is inferred from the
  CI files and not confirmed from the shipped bytes (UNVERIFIED).
- Dependencies: upstream 2026.10.0 `go.mod` pins `golang.org/x/crypto` v0.55.0
  and `github.com/klauspost/compress` v1.18.0 (indirect). A module level scan
  against the Go vulnerability database (modified 2026-10-01) shows, for those
  versions: GO-2026-5932 (OpenPGP, no fixed version), GO-2026-6354
  (CVE-2026-78662) and GO-2026-6355 (CVE-2026-56855), both ssh channel deadlock
  denial of service fixed in x/crypto v0.56.0, and GO-2026-5841
  (GHSA-259r-337f-4rfw), an `s2` out of bounds read fixed in klauspost/compress
  v1.18.7. `golang.org/x/crypto/ssh` is part of the build graph. Whether the
  daemon's `tunnel run` or `access ssh` paths reach the affected ssh or `s2`
  symbols has not been analysed (UNVERIFIED). The deb therefore carries the
  two ssh advisories and the `s2` advisory unfixed; the Core source build
  carries a patch for them and the deb path does not.

## Why the deb path was accepted on control/data

1. Exact pinned version: `CLOUDFLARED_VERSION=2026.10.0` in both
   `wins_control_plane_setup_ONETOUCH.sh:4939` and
   `wins_data_plane_setup_ONETOUCH.sh:5619`.
2. Per-arch digests pinned (values above), identical in both installers.
3. Committed vendored apt key + fingerprint (never curled at deploy time):
   `server/vendor/cloudflare-main.gpg`, key
   `1bd95f4082b320d541bee351560fc2765aa9f9cd8efa4c9e32135e63f252721d`,
   fingerprint `CC94B39C77AE7342A68B89628A682D308D4E5E73`, identical in both.
4. M-6 exact-version gate: reinstall is skipped only when the EXACT pinned
   version is present AND `cloudflared tunnel run --help` still exposes the
   root-only `--token-file` flag; any other installed version is reinstalled,
   and `apt-mark hold` freezes the package afterward. This is also the guard
   against the 2026.6.0 service-token regression.
5. The `--token-file` flag the deployment handoff requires is verified
   present at install time on both roles (and still exists in the 2026.10.0
   source).

## What would make this disposition expire

If a govulncheck run on the 2026.10.0 source, or a later Cloudflare deb, shows
that a reachable code path (tunnel, access-ssh, QUIC, or TLS handling) is
affected by GO-2026-5932, GO-2026-6354, GO-2026-6355 or GO-2026-5841, the
source-build extension becomes mandatory for control and data, using the same
reviewed patch as the Core role. The pin test
(`server/test_control_data_cloudflared_deb_pin.py`) enforces the pins and the
presence of this document's version, digests and the "NOT been re-attested"
statement; it does not prove reachability.
