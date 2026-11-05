# cloudflared 2026.10.0-security1 review

Review date: 2026-10-06 UTC

Status: PARTIAL, build lane 2026-10-07 applied. Source identity, dependency
patch, patched module files and the toolchain pin were verified from published
text. The build lane has since measured the source archive digest and both
per-architecture output digests, resolved the module download under
`go mod verify`, shown the outputs reproducible, and run the module test suite
under Go 1.27.1 (see "Verified by the build lane"). The govulncheck source-mode
scan is still open (see "Not yet verified"). This file deliberately carries no
source archive or output digest: those values live only in the Core installer
constants, so this file stays byte-stable when they change.

## Provenance and fixed inputs

- Upstream release: `2026.10.0`, published 2026-10-05T17:43:45Z, not a prerelease,
  returned by the GitHub `releases/latest` endpoint.
- Annotated tag object: `5eb7b904cb26e9ddc9b0ab490c8f1a0898155b34`
- Upstream commit: `18cdfe0a6fc7b72a0702d255a1f984e776ce0498` (commit message
  "Release 2026.10.0", dated 2026-10-05T15:39:13Z). GitHub reports neither the
  tag nor the commit as signature-verified; the identity binding is the exact
  commit id plus the source archive digest pinned in the installer.
- Security patch: `server/vendor/cloudflared-2026.10.0-security.patch`,
  SHA-256 `8ec5ecde3a9ded36d10800b9cc0457264a7aee7e083e5eaf7e4cba76dcf8493d`
- Go toolchain: `1.27.1` (released 2026-09-01), chosen by the arbiter as the
  latest stable Go. Upstream 2026.10.0 builds and tests with Go 1.26.8 in its
  own CI files (Dockerfiles, `.gitlab-ci.yml`, `.ci/image/Dockerfile`), so a
  Go 1.27.1 build is not exercised by upstream. Static check: no module in the
  patched `go.mod` (replace targets included) declares a `go` line above
  1.26.0 (the highest is `golang.org/x/crypto` v0.56.0), and the build flags the
  installer uses carry over unchanged. Nothing found rules 1.27.1 out; whether
  it compiles and runs correctly with the quic-go fork is unverified. Fall back
  to Go 1.26.8 (amd64 `d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b`,
  arm64 `211ffced9dcb9633a55eac6364816ec0ddd951389a740e88fa8b3337971bdda0`) if
  the build lane fails.
- Go linux-amd64 archive SHA-256 `63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`
- Go linux-arm64 archive SHA-256 `3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec`
  (both read from `https://go.dev/dl/?mode=json` on 2026-10-06)
- Patched `go.mod` SHA-256: `2f00aef341c813be5385dfe3ecd5be3c12f79fe04066f47ab28874a945f5d947`
- Patched `go.sum` SHA-256: `2235fabd50493ee2291a5470931268a62e783ce572c67e56c6562b989b773a6a`

Upstream `go.mod` at the commit has SHA-256
`1a9fbf726b1816625d709fcaabfd27a24005ce89e16bee76838e70d2ee423fee` and upstream
`go.sum` has `a99cd810e0a3ee653472c414a4d419f889565fb9c3f4c62f6fd1a0135a2b67e5`
(raw files fetched at the commit id, identical to the files at the tag name).

## What the patch changes and why

Upstream 2026.10.0 already carries the golang.org/x/net v0.58.0, x/sys v0.47.0,
x/term v0.45.0 and x/text v0.41.0 that the 2026.8.3 patch had to force, and it
dropped vendoring. Two reviewed fixes are still missing upstream, so the patch is
reduced to exactly these module-file edits:

- `golang.org/x/crypto` v0.55.0 to v0.56.0. Fixes GO-2026-6354 (CVE-2026-78662)
  and GO-2026-6355 (CVE-2026-56855), ssh channel deadlock denial of service
  in `golang.org/x/crypto/ssh`.
- `github.com/klauspost/compress` v1.18.0 to v1.18.7 (indirect). Fixes
  GO-2026-5841 (GHSA-259r-337f-4rfw), an out of bounds read in the `s2` package.
- `go 1.26` to `go 1.26.0`, because crypto v0.56.0 declares `go 1.26.0` and a
  module may not require a dependency with a newer go line than its own.
- `go.sum` gains the four lines for those two versions. Their `h1:` values were
  copied from the 2026.8.3 review and cross-checked against
  `https://sum.golang.org/lookup/` for both modules on 2026-10-06 (exact match).

The 2026.8.3 patch no longer applies to 2026.10.0 (three of five go.mod hunks
fail), so it is obsolete for the Core build.

### Verification method for the patch

1. Fetched upstream `go.mod` and `go.sum` as raw text at the commit id.
2. Ran `patch --batch --forward -d <dir> -p1 < cloudflared-2026.10.0-security.patch`
   on those two files. Exit 0, both files patched, no code files touched.
3. Hashed the result (values above). A second forward apply is refused.
4. The same method applied to the 2026.8.3 inputs reproduced the previously
   pinned 2026.8.3 hashes exactly, which validates the method.
5. Checked that every module in the patched `go.mod` has its `h1:` and
   `/go.mod h1:` lines in the patched `go.sum` (replace targets included) and
   that every `go.sum` line is well formed.

The resolved `go.sum` pin equals the patched `go.sum` pin. That equality is
derived, not observed: it holds only if `go mod download` under
`-mod=readonly` needs no further entries. The installer checks the `go.sum`
digest before and after the download and the build, so any difference fails
closed.

## Dependency vulnerability disposition

Module level scan, 2026-10-06, against the Go vulnerability database index
(`https://vuln.go.dev/index/modules.json`, database modified 2026-10-01T20:24:15Z),
all 88 modules listed in `go.mod`, versions compared against each entry's
affected ranges:

- Upstream 2026.10.0 `go.mod`: 4 affected entries (crypto v0.55.0: GO-2026-5932,
  GO-2026-6354, GO-2026-6355; klauspost/compress v1.18.0: GO-2026-5841).
- Patched `go.mod`: 1 affected entry, GO-2026-5932, which has no fixed version.

GO-2026-5932 is the unmaintained `golang.org/x/crypto/openpgp` package. Static
evidence that it is not part of the build, not a call graph proof:

- The 2026.8.3 `vendor/modules.txt` (the full set of packages needed to build and
  test the module) lists no `golang.org/x/crypto/openpgp` package, only
  blake2b, blowfish, chacha20, chacha20poly1305, cryptobyte, curve25519, hkdf,
  nacl, salsa20 and ssh.
- The 2026.8.3 to 2026.10.0 source comparison contains no added or changed line that
  mentions `openpgp`.

This does not replace govulncheck. Binary mode scanning is expected to report
GO-2026-5932 conservatively, as it did for 2026.8.3.

Review-by: 2026-10-13 UTC. A new upstream release, a dependency change, a
vulnerability database update touching this graph, or any output byte change
requires a fresh review before that date.

## Behavior changes 2026.8.3 to 2026.10.0 relevant to the Core service

The Core unit runs `cloudflared --no-autoupdate tunnel run --token-file <file>`.
Read from the upstream release notes and source comparison: no flag, command or
configuration key used by this repo was removed.
`--transport-loglevel` became a hidden deprecated no-op. New optional flags are
`--allowed-mail` (Quick Tunnels only) and `--disable-path-normalization`
(affects only ingress rules that require Cloudflare Access). The installer gate
`tunnel run --help` still finds `--token-file` in the 2026.10.0 source.

## Verified by the build lane (2026-10-07)

- Source archive: `https://codeload.github.com/cloudflare/cloudflared/tar.gz/18cdfe0a6fc7b72a0702d255a1f984e776ce0498`
  was downloaded twice and hashed (identical bytes both times); the digest is
  the `CLOUDFLARED_SOURCE_SHA256` installer constant. GitHub publishes no digest
  for source archives, so the binding is the commit id: the archive's tar pax
  comment is that commit, and the annotated tag `2026.10.0` resolves to it.
  The earlier 2026.8.3 archive digest no longer appears in the installer.
- Patched module files: the forward patch applied cleanly to the archive and
  the resulting `go.mod` and `go.sum` hashes equal the two values above.
  `go mod download` (clean module cache, `GOFLAGS=-mod=readonly`,
  `GOPROXY=https://proxy.golang.org`, `GOSUMDB=sum.golang.org`) and
  `go mod verify` ("all modules verified") left both files byte-identical,
  and so did the build. The derived `go.sum` equality stated above is therefore
  now observed.
- Outputs: linux/amd64 (`GOAMD64=v1`) and linux/arm64 (`GOARM64=v8.0`), built
  exactly as the installer does with Go 1.27.1 (`CGO_ENABLED=0`, `-trimpath`,
  `-buildvcs=false`, the installer's `-ldflags`). Two builds from freshly
  extracted sources with empty module and build caches produced identical
  bytes for both architectures. Those builds cross-compiled on a macOS arm64
  host with the official darwin-arm64 Go 1.27.1 archive. A third build ran
  natively on linux/arm64 with the digest-checked linux-arm64 Go 1.27.1 archive
  (patched `go.mod` and `go.sum` taken from the first build after their hashes
  were checked against the pins) and produced the same bytes for both
  architectures, so the outputs do not depend on the build host. The digests are the `CLOUDFLARED_AMD64_SHA256` and `CLOUDFLARED_ARM64_SHA256`
  installer constants. `go version -m` on both outputs shows
  `golang.org/x/crypto` v0.56.0 and `github.com/klauspost/compress` v1.18.7
  with the `h1:` values the installer greps for.
- Compilation and tests under Go 1.27.1: the patched tree builds, and
  `go test -short -count=1 ./...` passed in all 49 packages that have tests
  (macOS arm64 host, Go 1.27.1). Upstream's own CI still uses Go 1.26.8; the
  Go 1.26.8 fallback above was not needed.

## Not yet verified

- govulncheck source mode (`./cmd/cloudflared/...`) and binary mode on the
  built outputs. It needs the Go vulnerability database (`vuln.go.dev`), which
  was not reachable under the build lane's approved-source list, and no local
  copy of the database exists on the build host. The static evidence above
  stands in until a run is recorded.
- A run of the built linux binaries against a real tunnel (the build lane has
  no Cloudflare credentials). The installer's `tunnel run --help` check for
  `--token-file` is the only runtime gate.

## Official sources

- Cloudflare release: https://github.com/cloudflare/cloudflared/releases/tag/2026.10.0
- Cloudflare commit: https://github.com/cloudflare/cloudflared/commit/18cdfe0a6fc7b72a0702d255a1f984e776ce0498
- Release notes: https://raw.githubusercontent.com/cloudflare/cloudflared/master/RELEASE_NOTES
- Go downloads: https://go.dev/dl/?mode=json
- Go checksum database: https://sum.golang.org/
- Go vulnerability database: https://vuln.go.dev/
- GO-2026-5932: https://pkg.go.dev/vuln/GO-2026-5932
- GO-2026-6354: https://pkg.go.dev/vuln/GO-2026-6354
- GO-2026-6355: https://pkg.go.dev/vuln/GO-2026-6355
- GO-2026-5841: https://pkg.go.dev/vuln/GO-2026-5841
