//go:build !linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
)

// Real forwarding is Linux-only, and this refuses rather than degrading to
// something that looks similar.
//
// macOS and every other non-Linux build of this binary keep the reflector as
// their only inner side, exactly as before this file existed: -forward
// simply is not offered there. That mirrors cmd/winn-datapath's own
// winn3_device_tunfd_other.go, for the reason stated there -- silently
// substituting one backend for another gives a host a working-looking
// tunnel with a different containment argument than the one that was
// reviewed.

type sharedGatewayTun struct{}

// tunOptions mirrors forward_linux.go's construction options.
type tunOptions struct {
	vnetHdr bool
	queues  int
}

func newSharedGatewayTunOpts(name string, addr netip.Addr, prefixLen, mtu int, table *forwardTable, _ tunOptions) (*sharedGatewayTun, error) {
	return newSharedGatewayTun(name, addr, prefixLen, mtu, table)
}

func newSharedGatewayTun(name string, _ netip.Addr, _, _ int, _ *forwardTable) (*sharedGatewayTun, error) {
	return nil, fmt.Errorf(
		"-forward needs a real Linux /dev/net/tun interface (%q would have been created); "+
			"none exists on %s, so this flag refuses rather than falling back to the reflector "+
			"silently. Build and run this binary on linux/amd64 or linux/arm64 for real forwarding",
		name, runtime.GOOS)
}

var _ innerWriter = (*sharedGatewayTun)(nil)

func (s *sharedGatewayTun) write([]byte) (int, error) {
	return 0, errors.New("gateway forwarding is unavailable on " + runtime.GOOS)
}

func (s *sharedGatewayTun) run(context.Context) {}

// enableAsyncWrites is unreachable here: newSharedGatewayTun always refuses.
func (s *sharedGatewayTun) enableAsyncWrites() {}

func (s *sharedGatewayTun) Close() error { return nil }

func (s *sharedGatewayTun) Stats() sharedGatewayTunStats { return sharedGatewayTunStats{} }

type sharedGatewayTunStats struct {
	Interface   string `json:"interface"`
	MTU         int    `json:"mtu"`
	Queues      int    `json:"queues"`
	Reads       uint64 `json:"reads"`
	Delivered   uint64 `json:"delivered"`
	UnknownDest uint64 `json:"unknown_dest"`
	Malformed   uint64 `json:"malformed"`
	SendRefused uint64 `json:"send_refused"`
	DeviceGone  bool   `json:"device_gone"`

	AsyncWrites bool `json:"async_writes,omitempty"`
	tunWriteQueueStats
}
