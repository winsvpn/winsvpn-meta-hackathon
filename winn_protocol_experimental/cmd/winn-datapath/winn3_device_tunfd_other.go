//go:build !linux

package main

import (
	"errors"
	"runtime"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// The tun-descriptor backend is Linux-only, and this refuses rather than
// degrading to something that looks similar.
//
// Windows has no /dev/net/tun and no SCM_RIGHTS, so the Windows host owns its
// Wintun adapter and uses the loopback seam instead. Silently substituting one
// backend for the other would give a host a working-looking tunnel with a
// different containment argument than the one its own review approved.

type winn3TunFDDevice struct{}

func newWinn3TunFDDevice(int, string) (*winn3TunFDDevice, error) {
	return nil, errors.New(
		"device kind " + winn3DeviceTunFD + " needs /dev/net/tun and a " +
			"descriptor hand-off, neither of which exists on " + runtime.GOOS +
			"; use device kind " + winn3DeviceLoopbackUDP + " and keep the tun " +
			"adapter in the host")
}

func (d *winn3TunFDDevice) ReadPacket([]byte) (int, error)  { return 0, errors.New("unsupported") }
func (d *winn3TunFDDevice) WritePacket([]byte) (int, error) { return 0, errors.New("unsupported") }
func (d *winn3TunFDDevice) MTU() int                        { return 0 }
func (d *winn3TunFDDevice) Close() error                    { return nil }

var _ tun.Device = (*winn3TunFDDevice)(nil)
