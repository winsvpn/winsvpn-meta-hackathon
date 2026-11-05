# A10-04 gateway lane result

Completed 2026-09-13 in `/Users/owner/xprize/winsvpnv3`.

Implemented the current audit's proposed stale-owner eviction in `winn_protocol_experimental/cmd/winn3-gateway/forward.go`. Under the existing table mutex, `learn` evicts a conflicting owner only after `registry.innerForPeer(existing.Session().PeerStatic())` no longer authorizes that address. Still-authorized owners retain their mapping and increment collisions. Missing registry, nil owner, and missing session retain collision rejection. Eviction increments forgotten; replacement increments learned. Existing owner-checked cleanup is preserved. Updated the adjacent lifecycle comments.

Added `winn_protocol_experimental/cmd/winn3-gateway/forward_round10_test.go`. Real authenticated session fixtures cover revocation, reassignment of the former peer to another address, replacement outbound writes and return routing, counters, late old-device cleanup, real authority collision rejection, same-owner relearning, and missing authority-evidence guards. This file uses the existing, previously untracked `gateway_authority_test.go` fixture without editing it.

Command outcomes (Go commands ran from `winn_protocol_experimental`):

- `go test -race -count=1 -run '^TestRound10Forward' ./cmd/winn3-gateway` before the source fix: exit 1, expected failures for both revoked and reassigned owner replacement. Both reported `gateway inner source is owned by another live session`.
- `go test -race -count=1 -run '^(TestRound10Forward|TestForwardTable|TestGatewayForwardDevice|TestGatewayAuthority|TestForwardDevice)' ./cmd/winn3-gateway` after the fix: exit 0, `ok winsvpn.local/winnprotocol/cmd/winn3-gateway 3.975s`.
- `go version` inside the module: `go1.27.0 darwin/arm64`; `go env GOTOOLCHAIN`: `auto`.
- `gofmt -l` on both scoped files: exit 0, no output.
- `git diff --check -- winn_protocol_experimental/cmd/winn3-gateway/forward.go`: exit 0, no output.
- Python byte checks on both files: exit 0, LF only and no em/en dashes.

Final SHA-256:

```text
fffadcaebab648fd809a43f42eb8836b3440c7d31dd31635ab8f2d7507369621  winn_protocol_experimental/cmd/winn3-gateway/forward.go
cf0d4f7e220df6a650782aa9301f145a3dd5dfb4151167b00f60cbb8dcd4bf8e  winn_protocol_experimental/cmd/winn3-gateway/forward_round10_test.go
```

Read root `AGENTS.md`; no nested `AGENTS.md` found under the Go module. Checked live official [Go race detector documentation](https://go.dev/doc/articles/race_detector) on 2026-09-13 for targeted `go test -race` usage. Audit's A10-04 finding and proposed diff were checked against current source.

Only the two scoped repository files were edited. Pre-existing changes to `forward.go` were preserved. No delegation, staging, commits, pushes, deployment, external messaging, Flutter commands, ruling edits, or full-module tests. Root retains integration, full verification, and final reporting. These are local session/forwarding tests, not deployed TUN evidence. Registry refresh may perform disk I/O while the table lock is held on a conflicting learn, as in the audit proposal.
