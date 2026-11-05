//go:build !linux && !android

package main

import (
	"errors"
	"net"
	"net/netip"
)

// measureEgressRoute has no rtnetlink to ask here. checkEgressMTU reports
// errors.ErrUnsupported as "not available on this platform".
func measureEgressRoute(egressLookup) ([]egressRoute, error) {
	return nil, errors.ErrUnsupported
}

// measureEgressRouteTo is likewise unavailable; the per-client guard then
// serves every client (an unmeasured route never refuses).
func measureEgressRouteTo(egressLookup, []netip.AddrPort) ([]egressRoute, error) {
	return nil, errors.ErrUnsupported
}

// listRoutingSelectors: no rtnetlink here.
func listRoutingSelectors() ([]routingSelector, error) { return nil, errors.ErrUnsupported }

// listenerMark: no SO_MARK here.
func listenerMark(*net.UDPConn) (uint32, error) { return 0, nil }
