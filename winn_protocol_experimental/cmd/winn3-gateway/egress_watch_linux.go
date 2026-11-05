//go:build linux || android

package main

import (
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// egressWatchGroups are the rtnetlink multicast groups whose messages can
// change the route, or the MTU, a reply to an established client takes:
// links (a device MTU or state change), IPv4 addresses (source selection),
// IPv4 routes, IPv4 policy rules and nexthop objects. Round CM3 Turn 3.
var egressWatchGroups = []int{
	unix.RTNLGRP_LINK,
	unix.RTNLGRP_IPV4_IFADDR,
	unix.RTNLGRP_IPV4_ROUTE,
	unix.RTNLGRP_IPV4_RULE,
	unix.RTNLGRP_NEXTHOP,
}

// startRouteWatch subscribes to egressWatchGroups and signals changed (a
// coalescing channel: one pending signal at most) on every notification. A
// receive-buffer overrun (ENOBUFS, events were lost) also signals, so a lost
// event still causes a sweep. The subscription socket carries notifications
// only; it never sends a request. stop ends the reader within one receive
// timeout.
func startRouteWatch() (changed <-chan struct{}, stop func(), err error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, nil, fmt.Errorf("rtnetlink watch socket: %w", err)
	}
	fail := func(what string, err error) (<-chan struct{}, func(), error) {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("rtnetlink watch %s: %w", what, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fail("bind", err)
	}
	for _, g := range egressWatchGroups {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			return fail(fmt.Sprintf("join group %d", g), err)
		}
	}
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("receive timeout", err)
	}
	ch := make(chan struct{}, 1)
	signal := func() {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	var stopped atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = unix.Close(fd) }()
		buf := make([]byte, 64<<10)
		for !stopped.Load() {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			switch {
			case err == nil && n > 0:
				signal()
			case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			case errors.Is(err, unix.ENOBUFS):
				// Notifications were dropped: the routes may have changed
				// in ways this reader never saw. Sweep.
				signal()
			case err != nil:
				// The watch is gone; the backstop sweep still runs.
				signal()
				return
			}
		}
	}()
	return ch, func() {
		stopped.Store(true)
		<-done
	}, nil
}
