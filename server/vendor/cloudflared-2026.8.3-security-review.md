# cloudflared 2026.8.3-security1 review

Review date: 2026-09-03 UTC

## Provenance and fixed inputs

- Upstream release: `2026.8.3`
- Upstream commit: `fe70e951a3c52d92abf9f6c4248e32937b2f42fc`
- Source archive SHA-256: `908aab97646925b8df7cd832c3aed96113cff070d3b41f665ffa55a86f1b04b5`
- Security patch SHA-256: `1095e00bb26735782562656d98df60918f7bbd5ca8160fb0810b3c7b462f0f2f`
- Go toolchain: `1.26.6`
- Go linux-amd64 archive SHA-256: `708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89`
- Go linux-arm64 archive SHA-256: `d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e`
- Patched `go.mod` SHA-256: `3b71981f6e62fba6d517bcad5df64cf8faf0a09f7f6a51a748bfd99e6d3b19d9`
- Patched `go.sum` SHA-256: `2aa9151dc405ae0421219e944522dba22c915cc0e2bc2796efb42e0be00275c9`
- linux-amd64 output SHA-256: `428926d0654f2aa8383995a152232056edbc5e64b1cd72598692e2cb907eec39`
- linux-arm64 output SHA-256: `857e5fc472834432e59d4188595fa6d997c7791ed7ed03825721c873efda7aeb`

The release and commit mapping were re-derived from Cloudflare's official
GitHub release and tag on 2026-09-03. The Go toolchain hashes were re-derived
from Go's official download metadata. The Core installer fetches only the exact
commit archive and verifies all bytes listed above.

## Build and reproducibility

The reviewed build used `CGO_ENABLED=0`, explicit `GOOS=linux`, explicit
`GOARCH`, `GOAMD64=v1` or `GOARM64=v8.0`, `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=readonly`, empty `GOEXPERIMENT`, `GOFIPS140=off`, `-trimpath`,
`-buildvcs=false`, an empty build ID, and fixed Version and BuildTime linker
values. Module and build caches were new and isolated.

Two separate clean macOS-hosted cross-builds produced the output hashes above.
A third clean build in an Ubuntu 24.04 arm64 container, using the pinned
official Go 1.26.6 linux-arm64 toolchain, reproduced both amd64 and arm64 hashes.
The `go.mod` and `go.sum` hashes were unchanged by `go mod download` and both
builds under `-mod=readonly`.

## Vulnerability scan and disposition

Scanner: `govulncheck@v1.7.0`

Database: `https://vuln.go.dev`, updated 2026-09-02 19:12:04 UTC

Disposition review-by: 2026-09-10 UTC. A new upstream release, dependency
change, vulnerability-database update affecting this graph, or output-byte
change requires a fresh source call-graph review before that date.

Source-mode command:

```text
GOFLAGS=-mod=readonly GOTOOLCHAIN=go1.26.6 govulncheck ./cmd/cloudflared/...
```

Result: exit 0. Zero called vulnerabilities, zero imported-package
vulnerabilities, and one required-module advisory not reached by the command's
call graph.

Binary-mode command, repeated for both architecture outputs:

```text
govulncheck -mode=binary ./cloudflared-linux-ARCH
```

Result: exit 3. The sole result is GO-2026-5932 in
`golang.org/x/crypto/openpgp` at `golang.org/x/crypto@v0.56.0`. The advisory has
no fixed version because the OpenPGP package is unmaintained. Binary mode has no
call graph and conservatively reports the linked symbols. Source mode against
the exact source, dependency graph, and Go toolchain used for the pinned bytes
proves that `./cmd/cloudflared/...` does not call the affected OpenPGP symbols.
The output-byte pins prevent a future dependency or reachability change from
silently entering deployment.

## Official sources

- Cloudflare release: https://github.com/cloudflare/cloudflared/releases/tag/2026.8.3
- Cloudflare commit: https://github.com/cloudflare/cloudflared/commit/fe70e951a3c52d92abf9f6c4248e32937b2f42fc
- Go downloads: https://go.dev/dl/?mode=json
- Go vulnerability scanner: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
- GO-2026-5932: https://pkg.go.dev/vuln/GO-2026-5932
