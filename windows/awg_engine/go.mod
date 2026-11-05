// Deliberately its own module, for the same reason as its sibling
// windows/winn_framing_fixture: this package must resolve
// github.com/amnezia-vpn/amneziawg-go/v3 WITHOUT dragging that module graph into
// the repo root. The root module (winn.local/e8r7promoterr2) declares go 1.23.0
// and golang.org/x/sys v0.28.0; amneziawg-go/v3 v3.1.20260828 declares Go
// 1.25.0 and
// x/sys v0.36.0, so a root-level `require` would silently bump the Go language
// version and x/sys for every Winn Protocol package in the tree. Nesting keeps
// that blast radius at zero.
//
// THE PIN. Live-verified 2026-08-24 against official GitHub tags: latest upstream
// tag; stability designation unavailable.
// amneziawg-go is v3.1.20260828, tag-bound to commit
// b5928efb6ca19f0153958460c3d141f04abc5c2e. GitHub archive SHA-256
// 10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4. That is
// the exact engine revision the reviewed Windows builder pins:
//   tools/build_windows_awg_engine.ps1  ->  $engineVersion / $engineCommit
// That script is the SHIPPING build path. It git-clones amneziawg-go at the
// pinned commit, rewrites the entry point's four pre-v3 imports, and builds
// inside upstream's own tree against upstream's own byte-SHA-256-pinned
// go.mod/go.sum (Windows CRLF). A direct in-place build is not an acceptance
// path because the checked-in entry point deliberately remains unchanged; this
// module records the exact dependency and toolchain contract for editors and
// audits.
//
// This Go module version is not the Windows client release 3.1.0 and not
// amneziawg-tools v3.1.20260812.
//
// Keep this exact require and tools/build_windows_awg_engine.ps1's
// $engineVersion in lockstep. Do not float it to a range.
module winsvpn.local/winsvpnawgengine

go 1.27.1

toolchain go1.27.1

require (
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	golang.org/x/sys v0.36.0
)

require (
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
