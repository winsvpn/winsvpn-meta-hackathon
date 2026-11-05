# Winn Protocol v3 - Build and Reproduction Guide

Measured against the tree at **2026-08-03T15:21:33Z**. See
[README.md](README.md) for measurement provenance.

**Goal: an auditor is building and running this within the hour.** Every
command below was executed on the measurement host, and the observed result is
recorded, including the one that fails.

Host used for all measurements: darwin/arm64, Darwin 25.6.0,
`go version go1.26.5 darwin/arm64`.

---

## 0. Sixty-second start

```sh
cd winn_protocol_experimental
go mod verify          # expect: all modules verified
go build ./...         # expect: silence, exit 0
go vet ./...           # expect: silence, exit 0
sh scripts/smoke.sh    # expect: PASS line, ~8 seconds
```

If those four succeed you have a working toolchain and a working control
plane. Observed on the measurement host: all four pass, `smoke.sh` in
**8 seconds**.

---

## 1. Toolchain

| Requirement | Value | Source |
|---|---|---|
| Minimum Go | `1.26.0` | `go.mod` |
| Pinned toolchain | `go1.26.5` | `go.mod` `toolchain` directive |
| Module path | `winsvpn.local/winnprotocol` | `go.mod` |

`GOTOOLCHAIN=auto` (the default) means a runner with an older Go will
automatically download 1.26.5. No manual toolchain management is needed.

### `go.sum` is complete and verifiable

| Command | Observed |
|---|---|
| `go mod verify` | `all modules verified`, exit 0 |
| `go mod tidy -diff` | exit 0, no diff |
| `go list -mod=readonly -deps -test ./...` | exit 0, no stderr |

**One trap.** `go mod download all` will **fail** on missing sums. Nine modules
in `go list -m all` have no `go.sum` entry, because they are test or tool
dependencies of dependencies that are never built here. This is correct
behaviour under Go 1.17+ module-graph pruning, not a defect. Use
`go mod download` without `all`, or just `go mod verify`.

---

## 2. Release build matrix

**There is no Makefile.** The canonical build script is
`scripts/build_release.sh`.

### The five target tuples

Defined at `scripts/build_release.sh`, in the `for target in ...` loop and the
two trailing `build_binary` lines:

| GOOS/GOARCH | Commands built |
|---|---|
| `linux/amd64` | all 10 |
| `linux/arm64` | all 10 |
| `darwin/arm64` | all 10 |
| `windows/amd64` | all 10, with `.exe` |
| `android/arm64` | `winn-client` and `winn-carrier-client` only |

The ten commands: `winn-server`, `winn-client`, `winn-carrier-server`,
`winn-carrier-client`, `winn-token-issuer`, `winn-token`, `winn-manifest`,
`winn-admin`, `winn-audit`, `winn-pki`.

**Total: 42 release binaries from 5 tuples.** Earlier statements of "9 targets"
appear to have counted the same five tuples written in two notations
(`linux-amd64` and `linux/amd64`).

### Exact build invocation

Reproduced from `scripts/build_release.sh`:

```sh
CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "$GO_BIN" build \
  -mod=readonly \
  -trimpath \
  -buildvcs=false \
  -ldflags="-s -w -buildid=" \
  -o "$destination" \
  "./cmd/$command"
```

Preceded by `go mod verify`. The script also emits a `.buildinfo` per artifact,
a CycloneDX SBOM via `cyclonedx-gomod@v1.10.0`, a `SHA256SUMS` file, and copies
`internal/masque/LICENSE` and `internal/masque/UPSTREAM.md` into
`third_party_licenses/`.

### Verify cross-compilation in 30 seconds

```sh
for t in linux/amd64 linux/arm64 darwin/arm64 windows/amd64 android/arm64; do
  os=${t%/*}; arch=${t#*/}
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -mod=readonly -trimpath \
    -buildvcs=false -o /dev/null ./cmd/winn-client \
    && echo "OK   $t" || echo "FAIL $t"
done
```

**Observed on the measurement host: all five OK.**

### The CGO gap

The release script and every scanner run set `CGO_ENABLED=0`. Two packages
`import "C"` and are therefore **never compiled by any automated gate in this
repository**:

- `cdatapath` - `c-archive` for iOS and macOS
- `cshared` - `c-shared` for desktop FFI

Their build commands exist only as package doc comments:

```sh
CGO_ENABLED=1 go build -buildmode=c-archive -o libwinn_datapath.a  ./cdatapath
CGO_ENABLED=1 go build -buildmode=c-shared  -o libwinn_clientbinding.<ext> ./cshared
```

**UNVERIFIED:** `cshared/winn_clientbinding.go` states that Android and iOS use
`gomobile bind`. **No `gomobile` invocation exists anywhere in the tree.** How
the mobile binding is actually produced could not be determined.

**UNVERIFIED:** `tools/winn_conformance_build_out/` contains prebuilt iOS and
darwin `.a` archives and android, darwin and windows binaries. No script, Go
generator, or document in the tree produces them, and the exact
`GOOS=ios GOARCH=arm64 -buildmode=c-archive` flags cannot be reconstructed.

### Build tags

14 distinct `//go:build` expressions constrain 161 files. Platform tags are
conventional. **One custom tag exists: `winn_incomplete_e8`**, used by 24 files
in `cmd/winn-local-sealed-node` and `cmd/winn-phase1-soak-controller`.
**No script in the repository passes it**, so those files are never vetted,
raced, or tested.

Package counts by configuration, measured 2026-08-03T15:30Z:

| Configuration | Packages listed |
|---|---|
| darwin/arm64, CGO=1 (host default) | 91 |
| darwin/arm64, CGO=0 | 89 |
| linux/amd64, CGO=0 | 92 |
| linux/amd64, CGO=1 | 94 |
| linux/amd64, CGO=0, `-tags winn_incomplete_e8` | 93 |
| windows/amd64, CGO=0 | 88 |
| android/arm64, CGO=0 | 92 |

The CGO=1 minus CGO=0 delta of 2 on both darwin and linux is exactly
`cdatapath` and `cshared`.

Excluded on darwin but present on linux, each `//go:build linux` on its
`main.go`: `cmd/winn-acceptance`, `cmd/winn-aicore-directawg-e2e`,
`cmd/winn-h3-e2e`. Excluded everywhere without the tag:
`cmd/winn-local-sealed-node`.

---

## 3. Tests

### Full suite

```sh
go test ./...              # all packages, host platform
go test -race ./...        # what the release gate runs
```

1331 `func Test*` declarations exist across the tree (raw count, all tags).

### What silently does not run

An auditor should know what a green run does **not** cover.

| Gate | Effect |
|---|---|
| Host GOOS | On darwin, three Linux-only `cmd/` packages and the entire `//go:build linux` half of `internal/directawg` never compile. **81 Linux-gated test functions** exist across 28 files. |
| `-tags winn_incomplete_e8` | **33 test functions** never run, because no script passes the tag. |
| `WINN_POSTGRES_TEST_DSN` unset | 6 Postgres integration tests skip. |
| OpenSSL < 3.5 absent | ML-DSA and hybrid-group interop tests skip. Inside the release gate (`WINN_RELEASE_GATE=1`) they **fail instead of skipping**, which is the correct design. |
| No C++ toolchain | `datapath/duplex` reference conformance tests skip. |
| Running as **root** | `internal/auditcheckpoint/custody_test.go` **skips**, because root ignores directory permissions. Running the suite as root silently *reduces* coverage. |

Exactly **two** test functions require root:
`internal/directawg/linux_policy_anchor_privileged_linux_test.go` (also needs
`WINN_PRIVILEGED_ANCHOR_E2E=1`, and expects a disposable network namespace) and
`spikes/ios_maximum_privacy/stagebreflector/private_server_linux_test.go`.

78 `t.Skip` call sites exist in total.

### Postgres-backed tests

```sh
sh scripts/postgres_test.sh    # requires a healthy Docker daemon
```

It starts a container, exports `WINN_POSTGRES_TEST_DSN`, and runs
`go test ./internal/state -run 'Postgres' -count=1`.

---

## 4. Fuzzing

### The 24 fuzz targets

All are in-package, none carries a build constraint, so every one is reachable
on any GOOS with a plain `go test`.

| Package | Targets |
|---|---|
| `internal/carrier` | `FuzzReadFrame`, `FuzzDecodeEnvelope`, `FuzzReadFrameStream` |
| `internal/carrierauth` | `FuzzSignatureHeader`, `FuzzRequestClaimsFromHeaders`, `FuzzResponseClaimsFromHeaders`, `FuzzParseTimestamp` |
| `internal/pqauth` | `FuzzDecodeSignature`, `FuzzVerifierSetDocument`, `FuzzVerifyDomainMessage`, `FuzzVerifyMLDSASignatureEncoding` |
| `internal/protocol` | `FuzzValidatePeerPublicKey`, `FuzzValidateRequest`, `FuzzValidateResponse` |
| `internal/echconfig` | `FuzzValidateConfigList`, `FuzzValidateConfig` |
| `internal/wcf3` | `FuzzDecode`, `FuzzReplayWindowAccept`, `FuzzDecodeWithReplay` |
| `internal/gatewaymanifest` | `FuzzDecodeManifestV2` |
| `internal/masque` | `FuzzParseProxyRequest` |
| `internal/privacytoken` | `FuzzDecodeTokenHeader` |
| `internal/realcycle` | `FuzzInspectJSONRejectsDuplicateNames` |
| `internal/realtopology` | `FuzzInspectJSONNamesNestingDepth` |

Enumerate them yourself:

```sh
grep -rn --include='*_test.go' -E 'func Fuzz[A-Za-z0-9_]*\(' . \
  | grep -v '/\._' | grep 'testing.F'
```

Note the `grep -v '/\._'` filter. See section 7.

### Running one

```sh
go test ./internal/carrier -run '^$' -fuzz '^FuzzDecodeEnvelope$' -fuzztime 60s -parallel 4
```

### What the release gate actually fuzzes

**9 of the 24 targets, for 80 seconds total.** Reproduced from
`scripts/verify.sh`:

```sh
go test ./internal/protocol     -run '^$' -fuzz '^FuzzValidatePeerPublicKey$'      -fuzztime 10s -parallel 4
go test ./internal/protocol     -run '^$' -fuzz '^FuzzValidateRequest$'            -fuzztime 10s -parallel 4
go test ./internal/protocol     -run '^$' -fuzz '^FuzzValidateResponse$'           -fuzztime 10s -parallel 4
go test ./internal/pqauth       -run '^$' -fuzz '^FuzzVerifyMLDSASignatureEncoding$' -fuzztime 5s -parallel 1
go test ./internal/carrierauth  -run '^$' -fuzz '^FuzzSignatureHeader$'            -fuzztime 10s -parallel 4
go test ./internal/carrier      -run '^$' -fuzz '^FuzzReadFrame$'                  -fuzztime 10s -parallel 4
go test ./internal/carrier      -run '^$' -fuzz '^FuzzDecodeEnvelope$'             -fuzztime 10s -parallel 4
go test ./internal/privacytoken -run '^$' -fuzz '^FuzzDecodeTokenHeader$'          -fuzztime 10s -parallel 4
go test ./internal/wcf3         -run '^$' -fuzz '^FuzzDecode$'                     -fuzztime 5s -parallel 1
```

Not in the gate, and high value: `FuzzDecodeManifestV2`, `FuzzParseProxyRequest`,
both `internal/echconfig` targets, and three of four `internal/pqauth` targets.

### There is effectively no seed corpus

Exactly one `testdata/fuzz` directory exists in the tree,
`internal/carrierauth/testdata/fuzz/FuzzSignatureHeader/`, and **it contains
zero seed files**. All seeding is in-code via `f.Add`. Every fuzz run starts
near-cold; there is no accumulated corpus to inherit.

---

## 5. Standing up a local two-endpoint session

Two scripts do this without any external infrastructure. Both generate their
own PKI into a temp directory and clean up on exit.

### 5.1 Control plane: rekey, rotation, revocation

```sh
sh scripts/smoke.sh
```

What it does: builds `winn-pki`, `winn-server`, `winn-client`, `winn-admin`,
`winn-audit`; generates a lab PKI; starts `winn-server` on `127.0.0.1:19443`;
drives a full rekey against it with `winn-client`; repeats for all three
hybrid suites; then exercises monotonic rotation and revocation.

**Observed: PASS in 8 seconds.** Output:

```
PASS: 3 strict hybrid suites, matching controller/device PSKs, monotonic rotation, and revocation
```

Override the port with `WINN_SMOKE_PORT` if 19443 is taken.

This is the fastest end-to-end proof that the post-quantum control plane
works: three suites, real mutual TLS, real ML-DSA signatures, real ECH, real
PSK application.

### 5.2 Carrier data plane: HTTP/3 and HTTP/2

```sh
sh scripts/carrier_smoke.sh
```

What it does: starts a UDP echo backend, starts `winn-carrier-server` with
HTTP/3 on UDP and HTTP/2 on TCP, waits for `/readyz` on the metrics port, then
runs `winn-carrier-client` and asserts the expected carrier path becomes
active.

Ports are overridable: `WINN_CARRIER_PORT`, `WINN_CARRIER_METRICS_PORT`,
`WINN_CARRIER_BACKEND_PORT`, `WINN_CARRIER_LOCAL_PORT`.

> ### Observed result: FAIL
>
> **At the measurement snapshot this script does not pass.** Recorded here
> rather than omitted, because an auditor will run it within the first hour.
>
> ```
> carrier client readiness timeout
> ```
>
> With the working directory preserved, the client log contains exactly:
>
> ```
> winn-carrier-client: no authenticated carrier became ready: use of closed network connection
> ```
>
> The server starts correctly and both listeners come up:
>
> ```
> Winn carrier HTTP/3 listening on udp/127.0.0.1:29475
> Winn carrier metrics listening on http://127.0.0.1:29476
> Winn carrier HTTP/2 listening on tcp/127.0.0.1:29475
> ```
>
> Established facts:
>
> - Not a port collision. Reproduced on three separate clean port ranges.
> - Not a build failure. `go build ./...` and `go vet ./...` are clean.
> - Not a unit-test failure. `internal/carrier`, `internal/carrierauth`,
>   `internal/masque`, `internal/tlsconfig` and `internal/echconfig` all pass
>   `go test`.
> - The server also now emits a new warning that the script does not account
>   for: `lab mode without -device-revocation-list; revoked devices retain
>   carrier data-plane access`. `cmd/winn-carrier-server` gained
>   `-device-revocation-list`, `-device-revocation-state`, and related flags
>   from the new `internal/revocation` package; `scripts/carrier_smoke.sh`
>   passes none of them. In lab mode this is a warning, not the cause.
>
> **Root cause UNVERIFIED.** The failure is strongly correlated with work that
> landed in this tree the same day: caller-supplied socket adoption in
> `internal/carrier` (which introduces deliberate single-use socket semantics
> and one-shot dial closures whose failure mode is exactly "use of closed
> network connection"), plus same-day edits to `internal/carrierauth`,
> `internal/masque`, `internal/tlsconfig`, `internal/echconfig`, and the new
> `internal/revocation` package. See
> [04](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md#14-code-that-landed-during-preparation-of-this-package).
>
> **This should be reconciled before the tree is handed to an auditor.** It is
> most likely in-flight breakage rather than a latent defect, but it is
> reported as observed rather than assumed.

### 5.3 Advanced carrier behaviour

```sh
sh scripts/advanced_carrier_smoke.sh
```

Exercises path migration, anonymous carrier authorisation, and recovery.
**Not executed during preparation of this package**, because 5.2 fails first
and the two share the carrier stack. Status **UNVERIFIED**.

### 5.4 A real tunnel

There is no cross-platform script for this. The only end-to-end tunnel path is
`cmd/winn-auto-e2e`, which is `//go:build linux`, requires root or a network
namespace, and requires `amneziawg-go`, `awg`, `ip`, `nft` and `resolvectl`
present at the configured absolute paths. Build it with:

```sh
sh scripts/build_auto_e2e_linux.sh
```

Related Linux-only builders: `scripts/build_acceptance_linux.sh`,
`scripts/build_h3_e2e_linux.sh`,
`scripts/build_conservation_smoke_linux.sh`.

See [04, section 1](04-KNOWN-LIMITATIONS-AND-OPEN-QUESTIONS.md#1-maturity-what-actually-works-today)
for what this does and does not demonstrate.

---

## 6. The full release gate

```sh
sh scripts/verify.sh
```

It sets `WINN_RELEASE_GATE=1` and runs, in order: `go mod verify`; `gofmt -l .`
must be empty; `sh -n` on every script; `go vet ./...`;
`scripts/test_scanner_matrix.sh`; `scripts/scanner_matrix.sh` (staticcheck
2026.1, gosec v2.25.0, govulncheck v1.6.0, each pinned by module hash, across
5 tuples = 15 scanner runs); `go test -race ./...`; the 9 fuzz runs;
`smoke.sh`; `carrier_smoke.sh`; `advanced_carrier_smoke.sh`;
`reproducible_build_test.sh`; a hard failure if Docker is unhealthy; then
`postgres_test.sh`.

Requirements: Docker, OpenSSL 3.5 or later with ML-DSA and hybrid ML-KEM
groups, and network egress to install the pinned scanners.

> **Observed: the gate does not currently pass.** Two independent blockers at
> the measurement snapshot:
>
> 1. `gofmt -l .` reports `datapath/classify_test.go` as unformatted. The gate
>    treats this as a hard failure at step two.
> 2. `carrier_smoke.sh` fails as described in 5.2.
>
> `go mod verify`, `go vet ./...` and `smoke.sh` all pass.

There is **no CI**. No `.github/`, `.gitlab-ci.yml`, `.buildkite/`,
`.circleci/` or `.travis.yml` exists. The gate is run manually and nothing
enforces it.

---

## 7. Two traps in this working tree

Both will waste an auditor's time if not known in advance.

### 7.1 AppleDouble sidecar files

This working tree lives on a volume that creates a `._<name>` sidecar for every
file. **There are 26,295 of them, including 526 files matching `*.go`.**

Consequences:

- `find . -name '*.go' | wc -l` overcounts by 526.
- `grep -r` produces hundreds of spurious binary matches.
- `scripts/` appears to hold about 120 entries; it holds **59**.

Every command in this package uses `! -name '._*'` or `grep -v '/\._'`. Use the
same filters, or better, ask for a clean export rather than this working tree.

### 7.2 It is not a git repository

There is **no `.git` directory**. There is no history, no authorship metadata,
and no way to scan past commits for secrets. A committed build artifact records
`vcs.revision=6bf733e00706b9da0cf42e17dec2d756a28cc29d`,
`vcs.time=2026-07-25T06:01:00Z` and `vcs.modified=true`, so a repository exists
somewhere.

**Ask for the actual repository.** A history scan for previously committed
secrets cannot be done against this tree, and it should be done.

---

## 8. Re-measuring this package's numbers

Every count in this package can be reproduced with these commands. Run them
against whatever commit you are given and reconcile any difference as drift.

```sh
# Directories containing Go code
find . -name '*.go' ! -name '._*' ! -path './winn_protocol_experimental/*' \
  | sed 's|/[^/]*$||' | sort -u | wc -l

# Non-test files and lines
find . -name '*.go' ! -name '._*' ! -name '*_test.go' \
  ! -path './winn_protocol_experimental/*' | wc -l
find . -name '*.go' ! -name '._*' ! -name '*_test.go' \
  ! -path './winn_protocol_experimental/*' -exec cat {} + | wc -l

# Test files and lines
find . -name '*_test.go' ! -name '._*' ! -path './winn_protocol_experimental/*' | wc -l
find . -name '*_test.go' ! -name '._*' ! -path './winn_protocol_experimental/*' \
  -exec cat {} + | wc -l

# Packages, per configuration
go list ./... | wc -l
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list ./... | wc -l

# Fuzz targets
grep -rn --include='*_test.go' -E 'func Fuzz[A-Za-z0-9_]*\(' . \
  | grep -v '/\._' | grep -c 'testing.F'

# Per-directory line counts (the input to the code map's tiers)
for d in $(find . -name '*.go' ! -name '._*' ! -path './winn_protocol_experimental/*' \
    | sed 's|^\./||; s|/[^/]*$||' | sort -u); do
  n=$(find "$d" -maxdepth 1 -name '*.go' ! -name '._*' ! -name '*_test.go' \
      -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
  echo "$n $d"
done | sort -rn
```

Snapshot values at 2026-08-03T15:21:33Z: 93 directories, 330 non-test files,
111,279 non-test lines, 239 test files, 85,845 test lines, 89 packages on the
host, 24 fuzz targets.
