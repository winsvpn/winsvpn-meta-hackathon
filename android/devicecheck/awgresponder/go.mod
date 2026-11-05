// The responder half of the device check's AmneziaWG handshake. This exact
// official v3 module and version also back the shipping Android AAR.
module winsvpn.local/winndevicecheck/awgresponder

go 1.27.1

require github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828

// AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e

require (
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
