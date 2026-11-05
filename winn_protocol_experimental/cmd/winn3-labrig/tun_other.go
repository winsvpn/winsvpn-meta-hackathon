//go:build !linux

package main

import (
	"errors"
	"net"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// The lab rig is Linux-only on purpose.
//
// It exists to stand a v3 session up against a REAL kernel tun device, and
// "real kernel tun device" is a different object on every other platform this
// protocol targets. A portable stub that quietly did something else would let
// this file's evidence be produced somewhere it does not apply, which is the
// failure mode the capability table was made honest to prevent.
//
// The refusals below are why the package still builds and vets on a development
// Mac: a lab rig nobody can compile is a lab rig that rots.

var errNotLinux = errors.New(
	"winn3-labrig creates a /dev/net/tun device and runs on Linux only")

func openConfiguredTun(string, string, string, int, []string) (tun.Device, func() error, error) {
	return nil, nil, errNotLinux
}

func peekPeer(*net.UDPConn) (*net.UDPAddr, error) { return nil, errNotLinux }

func runTunFDExec(string, string, string, int, int, []string, []string) error {
	return errNotLinux
}
