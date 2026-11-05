# Export notes, lane B

Public-safe copy of part of the Win's VPN source for the Meta hackathon repository.

- Source: git worktree `podium/lanes/rel17`, branch `release-1.0.17`, commit `faff0b5`. Read-only; the worktree was clean before and after the export (`git status --porcelain` empty, HEAD still `faff0b5`).
- File list: `git ls-files` over the lane B paths (tracked files only, 1643 listed). Nothing untracked, nothing from `build/` or `.artifacts/`.
- Output: this directory (`fullsrc/laneB/`), original relative paths preserved, file mode bits preserved.
- Export date: 2026-11-04.

## 1. Included directories and file counts

| Path | Tracked in source | Exported | Note |
|---|---|---|---|
| `winn_protocol_experimental/` | 1585 | 1585 | Winn Protocol Go module (`winsvpn.local/winnprotocol`) plus docs, scripts, iOS spike |
| `winn3-nodes/` | 3 | 3 | demo gateway staging scripts, scrubbed (see section 3) |
| `router/` | 34 | 34 | AI router (Python) |
| `staging-hub/` | 16 | 13 | three data files excluded under rule 1 (see section 2) |
| root Go files | 5 | 5 | `go.mod`, `go.sum`, `pinned.go`, `recovery.go`, `transaction.go` |
| **Total** | **1643** | **1640** | plus this notes file |

Root files `ledger.go`, `main.go`, `model.go`, `model_test.go` exist in the source but were not in the lane B slice, so the root module copy here is incomplete on its own (see section 6).

No symlinks were encountered. No file in the slice is binary (git attributes and a NUL-byte scan both agree), and the largest file is well under 1 MB, so rule 2 (prebuilt binaries, files over 5 MB) excluded nothing.

## 2. Excluded paths, grouped by rule

### Rule 1: secrets, key material, node inventories with real addresses

| Path | Reason |
|---|---|
| `staging-hub/nodes.json` | Node inventory of the two live demo gateways: real egress IPv4 addresses, regions, subnets and the live gateway AWG-compat public keys. |
| `staging-hub/descriptors/demo-route-a.json` | Signed live descriptor. The base64 `payload` decodes to JSON containing the real gateway endpoint (IPv4:port), the gateway static public key and an `admission_secret` field, plus an ed25519 `sig`. Scrubbing the payload would break the signature, so the file is excluded rather than edited. |
| `staging-hub/descriptors/demo-route-b.json` | Same as above for the second gateway. |

Impact: `staging-hub/app.py` reads `nodes.json` at startup (`NODES_FILE`, overridable by environment) and lands descriptors from `descriptors/`. The hub will need an operator-supplied `nodes.json` to run, and `staging-hub/tests/test_hub.py` cases that rely on the committed descriptors will fail. No code was changed to hide that.

### Rule 2: prebuilt binaries and large non-source files

None found. Extension census of the slice: `.go` 1260, `.sh` 83, `.md` 60, no extension 53 (Dockerfiles, LICENSE, fuzz corpus entries, two shell scripts), `.swift` 40, `.json` 27, `.py` 25, `.txt` 13, `.jsonl` 13, `.c` 12, `.h` 11, `.service` 7, `.example` 7, and small numbers of `.checked`, `.sum`, `.sql`, `.plist`, `.pin`, `.ok`, `.mod`, `.lock`, `.gitignore`, `.entitlements`, `.xcscheme`, `.xcconfig`, `.timer`, `.spark_dummy`, `.sha256`, `.rb`, `.pbxproj`, `.patch`, `.mut_tmp`, `.f2_damaged_backup`, `.expected`. All are text.

### Checked and kept

- All seven `*.example` files (`router/.env.example`, `router/aicore.env.example`, `router/wins-edge-router.service.example`, three `deploy/systemd/*.env.example`, `spikes/ios_maximum_privacy/Config/Signing.xcconfig.example`): every secret-bearing variable is empty; the remaining values are ports, timeouts, loopback URLs and unit settings.
- `*.pem` with private keys, `*.key`, `*.p12`, `*.pfx`, `*.keystore`, env files with values, garble seeds, SSH keys, token-issuer signing keys: none exist in the slice. The three `ssh-ed25519` strings in the tree are labelled fixtures (`...FAKE`, `...FIXTUREONE`, `...FIXTURETWO`).
- Files named `*seed*`: none.
- Fuzz corpora under `testdata/fuzz/`, `testvectors/v2.json`, `winn3/core/testdata/winn3_kat_v1.json`, `stagebreflector/testdata/stageb-v1-vectors.json`: synthetic test vectors (sequential byte patterns such as 0x00..0x1f, repeated 0x5a, and so on).

## 3. Scrubbed files

Plain substring replacement only. No code logic, formatting or comments were changed beyond the replaced token. 21 files, 60 replacements. Everything else (1619 files) is byte-identical to the source (SHA-256 compared) and `go.mod`/`go.sum` in both modules are unchanged after the build in section 6.

Placeholders used:

| Class | Placeholder |
|---|---|
| Real IPv4 of demo gateway A egress | `203.0.113.10` (RFC 5737 TEST-NET-3) |
| Real IPv4 of demo gateway B egress | `203.0.113.20` |
| Owner's macOS home directory prefix | `/Users/owner` (rest of each path kept) |
| Two SSH host aliases for the private AICORE lab host | `aicore-lab-host` |
| Three cloud VM hostnames of the demo gateways and hub | `gateway-vm-a`, `gateway-vm-b`, `hub-vm` |
| Real cover-certificate domain in a usage example | `cdn.example.com` |
| Six cloud provider resource UUIDs (four server/instance ids, one deleted server id, one SSH-key resource id) | `<UPCLOUD_SERVER_UUID_EXIT_CHI>`, `<UPCLOUD_SERVER_UUID_LEAK_CLIENT_V2>`, `<VULTR_INSTANCE_UUID_ENTRY_MIA>`, `<VULTR_INSTANCE_UUID_CONTROL_ATL>`, `<VULTR_INSTANCE_UUID_ENTRY_NYC>`, `<VULTR_SSH_KEY_RESOURCE_ID>` |

Per file (replacements, changed lines):

| File | Replacements | Lines | What |
|---|---|---|---|
| `router/CONTINUE.md` | 2 | 2 | home path |
| `router/receipts/prod_sanity.txt` | 1 | 1 | home path (pytest warning line) |
| `staging-hub/FIELD_MAP.md` | 3 | 3 | home path |
| `staging-hub/LANE_REPORT.md` | 2 | 2 | home path |
| `staging-hub/tests/test_hub.py` | 1 | 1 | gateway A IPv4 in an assertion (that test also depends on the excluded descriptors) |
| `winn3-nodes/README.md` | 4 | 2 | both IPv4, two VM hostnames |
| `winn3-nodes/deploy_and_verify.sh` | 8 | 7 | both IPv4 (`role_facts` endpoints), home path, three VM hostnames (5 occurrences) |
| `winn3-nodes/provision_gw.sh` | 6 | 6 | both IPv4 (two places each), home path (`GO_BIN` default), one VM hostname |
| `winn_protocol_experimental/CLOUD_COST_SNAPSHOT_2026-07-26.json` | 2 | 2 | provider server UUID |
| `winn_protocol_experimental/CLOUD_COST_SNAPSHOT_2026-07-26_VULTR.json` | 3 | 3 | three provider instance UUIDs |
| `winn_protocol_experimental/WINN_PROTOCOL_V3_CONTINUATION_LOG.md` | 8 | 8 | SSH aliases (3), provider UUIDs (5) |
| `winn_protocol_experimental/WINN_PROTOCOL_V3_INVENTION_LOG.md` | 1 | 1 | SSH alias |
| `winn_protocol_experimental/WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md` | 10 | 10 | SSH alias (1), provider UUIDs (9) |
| `winn_protocol_experimental/docs/audit/README.md` | 1 | 1 | home path |
| `winn_protocol_experimental/docs/reviews/server-readiness-20260803/SERVER_READINESS_REVIEW.md` | 1 | 1 | home path |
| `winn_protocol_experimental/redteam_format.ok` | 1 | 1 | home path |
| `winn_protocol_experimental/scripts/obtain_cover_cert.sh` | 1 | 1 | cover domain in the usage comment |
| `winn_protocol_experimental/winn3/agent/corpus/agent_corpus_growth.txt` | 2 | 1 | home path |
| `winn_protocol_experimental/winn3/agent/nodash_gate_test.go` | 1 | 1 | home path inside a string literal (fallback candidate path; compiles unchanged) |
| `winn_protocol_experimental/winn3/redteam/corpus_link_test.go` | 1 | 1 | home path inside a string literal (same) |
| `winn_protocol_experimental/winn3/redteam/redteam_format.ok` | 1 | 1 | home path |

Note on the six provider UUIDs: the exclusion rules list IPs, hostnames, SSH aliases, emails, local paths and key-like tokens. Cloud resource UUIDs are not on that list. They were scrubbed anyway because, together with provider, region and role, they form an inventory of the owner's cloud resources. This is a judgment call that can be reversed by re-exporting without those six map entries; it touched only two JSON cost records and two Markdown logs.

## 4. Reviewed and deliberately kept (so the owner can overrule)

- Apple `DEVELOPMENT_TEAM` id in the iOS spike (`Signing.xcconfig.example`, `generate_project.rb`, `project.pbxproj`). Team ids ship inside every signed app's entitlements; not a credential.
- One progress-log line naming the owner's personal iPhone model by first name (`WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md`). Not an address or credential.
- `CLOUD_COST_*.json`: provider account balances and hourly rates in EUR/USD, with the author's own `<NODE_...>` IP placeholders. Financial detail, not credentials.
- Node role names of the phase-1 lab (`winn-exit-chi`, `winn-entry-nyc`, `winn-entry-mia`, `winn-control-atl`) in nine files. They double as SSH config aliases in one log, but they are also resource labels in code, JSON and docs, carry no resolvable address, and their IPs were already placeholders in the source.
- Two SSH host-key fingerprints (`SHA256:...`) in `scripts/winn_leak_acceptance_v2_*.example.json`, attached to placeholder hosts. Public fingerprints, not keys.
- `admin@winsvpn.org` (role address) and the `@winn.local`, `@example.*` test addresses. No personal email exists in the slice.
- Shared AWG public-key test fixture used as `testPeerKey` in 13 test files, and the other base64 keys in `device_generated_static_key_test.go`, `applier_test.go` and vector files. Test fixtures.
- Public resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `2606:4700:4700::1111`, `2620:fe::fe`), Go module hosts, `python.org`, `debian.org`, `docker.io`, `sslip.io` (mentioned by name only, no IP-encoded hostname).
- Synthetic cover domains inside `provision_gw.sh` and the `coverlisten` tests (`static-assets-cdn.net`, `content-delivery-edge.net`, `cdn-static-assets.local`, and similar): generated placeholder names, not infrastructure.

## 5. Scanner output

### gitleaks

Command: `gitleaks detect --no-git --source /Volumes/WinsBuild/winsvpn/hackathon/fullsrc/laneB --redact` (gitleaks 8.30.1, run before this notes file was added).

Output:

```
INF scanned ~19437678 bytes (19.44 MB) in 1.11s
WRN leaks found: 21
```

All 21 are `generic-api-key` rule hits. Each was opened and classified; none is a secret:

| # | File:line | What the matched line is |
|---|---|---|
| 1 | `winn_protocol_experimental/cmd/winn-clientinfo/main_test.go:180` | suite name `x25519-mlkem768` as a CLI argument |
| 2 | `winn_protocol_experimental/cmd/winn-phase1-conservation-smoke/main_test.go:507` | metric label string `redemptions_equal_authenticated` |
| 3 | `winn_protocol_experimental/WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md:2467` | matrix batch label (`batch_key=constrained-...`) |
| 4 | `winn_protocol_experimental/deploy/systemd/winn-token-issuer.env.example:7` | the `WINN_TOKEN_ISSUER_SUITE` variable set to the suite name `x25519-mlkem768` |
| 5 | `winn_protocol_experimental/internal/awg/applier_test.go:14` | `testPeerKey` fixture (shared AWG public-key test constant) |
| 6 | `winn_protocol_experimental/internal/linuxauto/rotation_key_provider_test.go:217` | same fixture |
| 7 | `winn_protocol_experimental/internal/observability/errorlog_test.go:48` | log line fixture containing `suite=x25519-mlkem768` |
| 8 | `winn_protocol_experimental/internal/observability/errorlog_test.go:50` | expected-substring list containing `x25519-mlkem768` |
| 9 | `winn_protocol_experimental/WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md:8582` | `uapi_parser_sha256=<digest>` (sha256 of a source file) |
| 10 | `...SHARED_PROGRESS_MONITOR.md:8645` | `native_uapi_header_sha256=<digest>` |
| 11 | `...SHARED_PROGRESS_MONITOR.md:8646` | `native_uapi_source_sha256=<digest>` |
| 12 | `...SHARED_PROGRESS_MONITOR.md:8647` | `native_uapi_tests_sha256=<digest>` |
| 13 | `...SHARED_PROGRESS_MONITOR.md:8649` | `swift_uapi_parser_sha256=<digest>` |
| 14 | `winn_protocol_experimental/internal/preparation/rotation_psk_source_test.go:236` | same `testPeerKey` fixture |
| 15 | `winn_protocol_experimental/internal/preparation/production_assembler_test.go:136` | credential name string `credential-h3-primary` |
| 16 | `...SHARED_PROGRESS_MONITOR.md:8823` | `uapi_parser_tests_sha256=<digest>` |
| 17 | `winn_protocol_experimental/internal/preparation/production_factory_test.go:207` | `credential-h3-primary` |
| 18 | `...production_factory_test.go:524` | `credential-h3-primary` |
| 19 | `...production_factory_test.go:580` | `credential-h3-primary` |
| 20 | `winn_protocol_experimental/scripts/aicore_auto_e2e.sh:601` | an `echo` of the label `credential_inventory` with the value `AES-256-GCM-vault` |
| 21 | `winn_protocol_experimental/spikes/ios_maximum_privacy/stagebreflector/testdata/stageb-v1-vectors.json:4` | `public_test_key_base64` = bytes 0x00..0x1f |

### grep checks on the exported tree

| Pattern | Result |
|---|---|
| IPv4 literals outside the allowed ranges | 31 unique values in 41 file hits, all reviewed: X.500 OID arcs `2.5.4.x` in `coverlisten/covercert.go`; netns/forwarding test addresses (`45.0.0.0`, `45.0.1.2`, `46.0.0.1`, `3.3.3.3`, `8.8.8.1`, `8.8.8.2`, `1.2.3.4`, `198.20.0.1`); CIDR boundary probes in `forward_isolation_test.go` (`9.255.255.255`, `11.0.0.0`, `11.64.0.1`, `100.63.255.255`, `100.128.0.0`, `100.128.0.1`, `172.15.255.255`, `172.32.0.0`, `192.167.255.255`, `192.169.0.0`, `203.0.114.1`); `128.0.0.0` half-space route in `conform.go` and `PRODUCTION_READINESS.md`. None is infrastructure. The two real gateway addresses: 0 hits. |
| IPv6 literals outside loopback/ULA/link-local/documentation | `2606:4700:4700::1111` (Cloudflare resolver, 4 files) and `2620:fe::fe` (Quad9, 1 test). Public resolvers. |
| `BEGIN .*PRIVATE KEY` | 3 files, all pattern strings used to refuse key material: `router/provider_common.py:21` (regex), `router/tests/test_router_supply_chain.py:42-43` and `staging-hub/tests/test_supply_chain.py:72-73` (forbidden-marker lists). No PEM block exists. |
| owner home path prefix, and the owner's user name on its own | 0 hits |
| name of the private secrets repository (`winsvpn-` prefix plus `secrets`) | 0 hits |
| `garble` | 1 hit, `WINN_PROTOCOL_V3_SHARED_PROGRESS_MONITOR.md:3926`, the English word "garbled" in prose. Not a seed. |
| files named `*seed*` | none |
| former SSH aliases, VM hostnames, cover domain | 0 hits |
| private-key / token / bearer / vendor-key regexes (AWS, GitHub, Slack, Google, OpenAI shapes) | 0 hits |
| personal emails | 0 hits |

## 6. Build result

Toolchain: a locally installed Go 1.27.1 (`go version go1.27.1 darwin/arm64`), matching `go 1.27.1` in the module file. Environment: `GOFLAGS=-mod=mod`, `GOMODCACHE=/Volumes/WinsBuild/winsvpn/hackathon/fullsrc/.gomodcache` (private cache), `GOTOOLCHAIN=local`. Module dependencies were downloaded into that private cache (`golang.org/x/net v0.59.0`, `github.com/quic-go/quic-go v0.63.0`, `golang.org/x/sys v0.48.0`, `golang.org/x/crypto v0.57.0`, `github.com/cloudflare/circl v1.6.5`, `github.com/jackc/pgx/v5 v5.11.0`, and transitive modules).

In `fullsrc/laneB/winn_protocol_experimental`:

```
go build ./...   exit 0
go vet ./...     exit 0 (no output)
```

`go.mod` and `go.sum` were re-hashed after the build and are byte-identical to the source.

Root module copy (`fullsrc/laneB`, module `winn.local/e8r7promoterr2`): `go vet .` fails with `./pinned.go:21:10: undefined: identity`, because `ledger.go`, `main.go`, `model.go` and `model_test.go` are outside the lane B slice. The three root files exported here are unmodified; the module will compile once the other lane delivers the remaining root files.

## 7. Integrity summary

- 1640 files exported, 0 extra files, 0 missing files (walk of the output compared with the included list).
- 1619 files byte-identical to the source; 21 files differ only on the lines listed in section 3.
- File mode bits identical for all 1640 files (executable scripts stay executable).
- Source worktree clean and unchanged at `faff0b5`.
- Nothing was pushed, published, committed or written outside `fullsrc/laneB/` and the private module cache `fullsrc/.gomodcache/`. `laneA`, `laneC`, `laneD` were not touched.
