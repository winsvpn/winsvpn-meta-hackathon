// wins-awg-carry-client: the hub's userspace AmneziaWG carrying canary client
// (design v17 3.15, ruling E). Built from the same official amneziawg-go v3
// module and version that the data-plane nodes run
// (amneziavpn/amneziawg-go:v3.1.20260828) and that backs the shipping Android
// AAR (android/devicecheck/awgresponder), so both ends of the canary handshake
// use the identical implementation.
module winsvpn.local/awgcarryclient

go 1.27.1

require (
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	golang.org/x/crypto v0.57.0
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20260122175437-89a5d21be8f0 // indirect
)
