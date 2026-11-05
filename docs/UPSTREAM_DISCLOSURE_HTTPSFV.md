# Upstream disclosure — `dunglas/httpsfv` parser panic, and its reach into `quic-go/masque-go`

Prepared 2026-08-03. **Nothing here has been filed yet.** Two reports are drafted
below because the defect has two owners: the root cause is in `httpsfv`, and the
most severe reachable path is in `masque-go`, which is a separate project with
its own users.

Filing these is the owner's call — a public issue is an outward-facing action and
it starts a disclosure clock. Read the sequencing note at the bottom first.

---

## What was verified, and how

Everything below was reproduced on 2026-08-03 against pinned versions. The
reproduction is eight lines of Go and takes seconds; re-run it before filing so
the report describes the current release.

**The panic itself**, `github.com/dunglas/httpsfv v1.1.0` (newest published
release), `UnmarshalItem`:

```
PANIC  bare         ["@"]        -> runtime error: index out of range [1] with length 1
PANIC  param        ["1;a=@"]    -> runtime error: index out of range [5] with length 5
PANIC  param2       ["a;b=@"]    -> runtime error: index out of range [5] with length 5
ok     control-ok   ["1;a=?0"]   -> err=<nil>
ok     control-bad  ["!!!"]      -> err=unrecognized character: character 0
ok     capsule      ["connect-udp;@"] -> err=invalid key format: character 12
```

The three controls matter as much as the three panics. `"!!!"` returns a clean
error, so the parser does handle malformed input correctly in general — this is a
specific missing bounds check, not a design stance. And `"connect-udp;@"` does
*not* panic, which is why the defect is not obvious from casual testing of
realistic header values.

**Root cause**, an ordering bug — `isNeg` dereferences before `parseNumber`
checks for end of input:

```
integer.go:95   func isNeg(s *scanner) bool { if s.data[s.off] == '-' {
integer.go:40   neg := isNeg(s); if neg && s.eof() { ...
```

The `@` character is the RFC 9651 Date marker, which routes into the numeric
scanner. When `@` is the final byte, `s.off` is already at `len(s.data)` when
`isNeg` indexes it.

**Fix**, one guard at the top of `parseNumber`, before the `isNeg` call: return
the existing end-of-input error rather than indexing.

---

## Reachability, stated precisely

`internal/masque` in this project is an internal fork of `quic-go/masque-go`
v0.4.0 (commit `03179c5407a332f0509fa8e165244e6410ac165a`). The same two call
sites exist unmodified in upstream v0.3.0 and v0.4.0, so this is not a
Winn-specific problem.

**Client side — the serious one.** `nextHopAddr` (`client.go:94` in v0.4.0)
parses the `Proxy-Status` response header, and is called from `Client.Dial` at
`client.go:78`. There is **no `recover()` anywhere in masque-go**, and this runs
on the caller's own goroutine, inside no server. A malicious or
man-in-the-middled proxy that answers with `Proxy-Status: @` **crashes the client
process**.

**Server side — real but contained.** `ParseProxyRequest` (`proxy_request.go:67`)
parses the `Capsule-Protocol` header from an incoming CONNECT-UDP request, before
any application-level authentication. Any client can reach it. However
`http3.Server` *does* recover handler panics (`http3/server_conn.go:206` in
quic-go v0.60.0), logging a 64 KiB stack trace and aborting that stream. So the
effect is a per-request denial plus log amplification, **not** a process crash.

That asymmetry is the finding, and the report should lead with it. A reader who
assumes "unauthenticated server-side parser panic" will over-rate the server path
and under-rate the client path, which is the one that actually takes a process
down.

**`govulncheck` is clean for this.** There is no advisory, so scanning does not
catch it. That is precisely why it is worth filing.

---

## Report 1 — `dunglas/httpsfv` (root cause)

**Where:** GitHub issue at `github.com/dunglas/httpsfv`. Request a GHSA through
the repository's Security tab; if private reporting is not enabled, open a normal
issue — see the sequencing note.

**Title:** `UnmarshalItem panics (index out of range) on a value ending in '@'`

> `UnmarshalItem` panics instead of returning an error when a Structured Fields
> value ends with the Date marker `@`. Reproduced on v1.1.0 with Go 1.26:
>
> ```go
> httpsfv.UnmarshalItem([]string{"@"})      // panic: index out of range [1] with length 1
> httpsfv.UnmarshalItem([]string{"1;a=@"})  // panic: index out of range [5] with length 5
> httpsfv.UnmarshalItem([]string{"a;b=@"})  // panic: index out of range [5] with length 5
> ```
>
> For contrast, `UnmarshalItem([]string{"!!!"})` correctly returns
> `unrecognized character: character 0`, so the parser handles malformed input
> properly in general — this looks like a single missing bounds check rather than
> intended behaviour.
>
> The cause appears to be an ordering issue in `parseNumber`: `isNeg` dereferences
> `s.data[s.off]` at `integer.go:95` before `parseNumber` performs its `s.eof()`
> check at `integer.go:40`. With `@` as the final byte, `s.off == len(s.data)` on
> entry to `isNeg`.
>
> A guard at the top of `parseNumber` returning the existing end-of-input error
> before calling `isNeg` would resolve it.
>
> **Why this matters beyond a crash in a test:** this parser is used on
> attacker-controlled HTTP header values. In `quic-go/masque-go` (v0.3.0 and
> v0.4.0) `UnmarshalItem` is called on the `Proxy-Status` response header inside
> `Client.Dial`, on the caller's goroutine with no recover in the path, so a
> hostile proxy can crash a client process with a five-byte header. I am filing
> that separately with masque-go and am happy to coordinate on timing.
>
> I would suggest a fuzz target over `UnmarshalItem` as part of the fix — the
> defect class is an unchecked index in a hand-written scanner, and one bounds
> check is unlikely to be the only one.

---

## Report 2 — `quic-go/masque-go` (affected consumer)

**Where:** `github.com/quic-go/masque-go`. quic-go runs a security policy; prefer
private reporting via the Security tab.

**Title:** `Client.Dial can be crashed by a proxy via the Proxy-Status header`

> `nextHopAddr` (`client.go:94`, v0.4.0) passes the `Proxy-Status` response header
> to `httpsfv.UnmarshalItem`, which panics rather than returning an error when the
> value ends in `@` (`dunglas/httpsfv` v1.1.0; filed separately upstream).
>
> `nextHopAddr` is called from `Client.Dial` at `client.go:78`. There is no
> `recover()` in masque-go and this executes on the caller's goroutine, so a
> proxy that responds with `Proxy-Status: @` **crashes the client process**. The
> `err != nil` branch immediately below the call shows the intent was to handle
> malformed values gracefully; a panic bypasses it.
>
> `ParseProxyRequest` (`proxy_request.go:67`) has the same unguarded call on the
> `Capsule-Protocol` request header, reachable pre-authentication by any client.
> That one is contained in practice because `http3.Server` recovers handler
> panics (`http3/server_conn.go:206`), so the effect is a per-stream denial plus a
> 64 KiB stack trace in the log rather than a crash — but it is still remote
> unauthenticated input reaching a panicking parser, and log amplification is a
> usable primitive on its own.
>
> Both call sites exist unchanged in v0.3.0 and v0.4.0.
>
> This will be fixed upstream in `httpsfv`, but masque-go may want a defensive
> `recover` around the third-party parser regardless, given that both call sites
> take fully peer-controlled bytes. That is what we did in our fork rather than
> guarding the one known input shape, on the reasoning that the defect class is
> "unchecked index in a hand-written scanner."

---

## Exposure map in this repository

Liveness was determined from evidence, not from directory names. **An earlier
version of this table called `wins_vpn_developer` a frozen snapshot that was not a
build target, and that was wrong** — it is a live, buildable working tree with
uncommitted work. It has since been patched. The corrected map:

| Tree | Status |
|---|---|
| `source/wins_vpn/winn_protocol_experimental/internal/masque/` | **Guarded** since 2026-08-03. `sfv.go` wraps the parser; four regression tests in `sfv_test.go`; `FuzzParseProxyRequest` and its crasher corpus in `testdata/`. |
| `source/wins_vpn_developer/winn_protocol_experimental/internal/masque/` | **LIVE — patched 2026-08-03.** `sfv.go` and `sfv_test.go` ported, both call sites converted, `httpsfv` import dropped from each. `gofmt` clean, `go vet` clean, `go build ./...` exit 0, all four regression tests pass with the recover observably firing. |
| `docs/downloads_misc/winn_cgroup_finish_p1_docker_payload_57243/`, `..._r2_docker_payload_42611/` | **Inert. Confirmed, not assumed. Deliberately not edited.** |
| `go/pkg/mod/.../masque-go@v0.3.0`, `@v0.4.0` | Module cache copies of upstream. Not compiled by us — we carry the fork in-module. Read-only by definition; the fix for these is the upstream report. |

**Why `wins_vpn_developer` is live.** It has its own `go.mod` with the same module
path `winsvpn.local/winnprotocol`; `go build ./...` returns exit 0; it carries **46
modified tracked files**, so someone worked in it; its newest Go file is dated
2026-07-31, three days before the fix. It sits on the *same* branch and commit as
the shipping tree (`snapshot/vendored-baseline-20260724`, `6bf733e`, 2026-07-25) —
the two are peer checkouts, not original and archive. Its `internal/masque`
differed from the shipping copy **only** by lacking the fix: identical files apart
from the two call lines and the two import lines, with `sfv.go`, `sfv_test.go`,
`proxy_request_fuzz_test.go` and `testdata/` simply absent. It was not a tree that
rejected the fix; it was a tree that had not received it, and work resuming there
would have resumed vulnerable.

Nothing in the repository references it — no CI, script, Makefile, Gradle or
config, verified by search. That makes it dormant, which is **not** the same as
dead, and the distinction is the whole point of this exercise.

**Why the two payloads are inert.** Each contains `gocache/`, `gocache-race/`,
`modcache/` and `src/` — Docker build contexts, a staged Go build cache beside a
source tree. They are archived copies of container working directories that
`WIN_FOR_ALL_R19_LOCAL_TEMP_CLEANUP_INVENTORY_20260730.md:111-112` recorded as live
Cursor worker temp dirs on 2026-07-30 (`winn_cgroup_finish_p1_isolated_57243_7671`
and `..._r2_isolated_42611_27776`; the trailing numbers match the payload names).
Their newest file is a `.DS_Store` — Finder metadata, not content. Nothing outside
`docs/downloads_misc/` references them except this document and that inventory. They
are evidence of a past run, and editing evidence to fix a bug in it is the wrong
move; the note is the action.

**Not ported to the developer tree, deliberately:** `FuzzParseProxyRequest` and its
`testdata/` corpus. The four regression tests pin the exact defect and pass; a fuzz
target in a dormant tree nobody runs adds upkeep without adding protection. Port it
if that tree becomes active again.

---

## Sequencing note — read before filing

**These are two reports about one defect, and the order matters.** Report 1 is the
root cause and Report 2 is a consumer that a fix in Report 1 resolves. Filing
Report 2 publicly first would disclose an exploitable client-crash in a live
project before its dependency has a fix available.

Recommended order:

1. File Report 1 with `dunglas/httpsfv`, privately if the Security tab allows it.
2. File Report 2 with `quic-go/masque-go`, privately, referencing Report 1.
3. Only after a fixed `httpsfv` release exists, or after the maintainers decline
   or go unresponsive past a stated deadline, discuss public detail.

If neither project accepts private reports, a plain issue on `httpsfv` alone is
defensible — it reads as a parser robustness bug — and the masque-go report can
follow once there is a fix to point at.

**Do not describe this as a CVE or GHSA until an identifier is actually
assigned.** It is a verified crash with a clear remote path; that is enough on its
own, and claiming an identifier that does not exist is the exact failure mode the
project has already been bitten by.

**Once a GHSA or CVE is assigned, this becomes addable to the ORCID record** as a
citable work. Until then it is not, and it has been deliberately left off.
