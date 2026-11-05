// The Windows Winn Protocol v3 tun relay and opt-in direct engine candidate.
// The historical relay-only dependency rationale below applies to the default
// mode. The direct candidate imports the local Winn module for its own crypto;
// Wintun itself remains outside the Winn protocol module's dependencies.
//
// Deliberately its own module, for the same reason as its siblings
// windows/awg_engine and windows/winn_framing_fixture: nesting keeps this
// package's dependency graph out of the repo root. The root module
// (winn.local/e8r7promoterr2) declares go 1.27.1, and the winn3 module
// (winsvpn.local/winnprotocol) declares go 1.27.1; neither should acquire a
// Wintun dependency because one Windows binary needs it.
//
// WHAT IS DELIBERATELY ABSENT: github.com/amnezia-vpn/amneziawg-go.
//
// That absence is the whole point of this module and is not an oversight to be
// "fixed" by a later hand reaching for tun.CreateTUN because it is familiar.
// windows/awg_engine depends on amneziawg-go because it IS AmneziaWG: it owns
// the adapter AND does the cryptography. This binary owns an adapter and does
// no cryptography at all -- winn/3 is the crypto, in cmd/winn-datapath, below
// this relay. Pulling amneziawg-go in here to get at its tun wrapper would drag
// a WireGuard implementation into the v3 datapath, which is the exact thing the
// standalone ruling removed from datapath/.
//
// golang.zx2c4.com/wintun is the upstream WireGuard project's Wintun binding
// and contains no WireGuard protocol code -- it is the adapter and the ring,
// nothing else. It is pinned to the SAME revision windows/awg_engine already
// resolves transitively, so both Windows binaries drive the same Wintun
// userspace against the same wintun.dll that
// installer/windows/dependencies/ ships. Two revisions of the ring code in one
// installer would be two different loss profiles for the same driver.
module winsvpn.local/winsvpnwinn3engine

go 1.27.1

require (
	golang.org/x/sys v0.48.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	winsvpn.local/winnprotocol v0.0.0
)

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
)

// Required only to instantiate the opt-in direct Winn v3 candidate in-process.
replace winsvpn.local/winnprotocol => ../../winn_protocol_experimental
