package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"winsvpn.local/winnprotocol/winn3/hostqueue"
)

// runDirectCandidate is a separate, explicit control protocol for an
// authenticated LocalSystem host. The existing supervisor does not select it.
// Stdin: one JSON line {"profile":"absolute protected profile path"}, then
// EOF to stop. Stdout: ready line then desktop status JSON. No host-port or
// engine-port exists in this mode, and no child datapath is launched.
func runDirectCandidate(stopEvent windows.Handle) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, windows.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		if result, _ := windows.WaitForSingleObject(stopEvent, windows.INFINITE); result == windows.WAIT_OBJECT_0 {
			cancel()
		}
	}()
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	// A stuck native call or status pipe must not retain a privileged adapter.
	// Exiting leaves ring reclamation to the OS; it never frees under a caller.
	go func() {
		<-ctx.Done()
		time.Sleep(pumpQuiesceTimeout)
		os.Exit(9)
	}()
	control := bufio.NewScanner(os.Stdin)
	control.Buffer(make([]byte, 4096), 64<<10)
	if !control.Scan() {
		return fmt.Errorf("direct start command missing")
	}
	profile, err := parseDirectStart(control.Text())
	if err != nil {
		return err
	}
	go func() {
		// Any second command or EOF ends this one-session process. There is no
		// live profile replacement or implicit downgrade to the relay mode.
		control.Scan()
		cancel()
	}()
	var stats counters
	var luid uint64
	var mtu int
	runtime, err := hostqueue.Open(ctx, profile, func(floor int) (hostqueue.Device, error) {
		adapter, err := wintun.CreateAdapter(adapterName, tunnelType, nil)
		if err != nil {
			return nil, err
		}
		session, err := adapter.StartSession(ringCapacity)
		if err != nil {
			_ = adapter.Close()
			return nil, err
		}
		quit, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil || quit == 0 {
			session.End()
			_ = adapter.Close()
			return nil, fmt.Errorf("create direct quit event: %w", err)
		}
		var stopping atomic.Bool
		side := wintunSide{session: session, readWait: session.ReadWaitEvent(), quit: quit, stopping: &stopping}
		luid, mtu = adapter.LUID(), floor
		return &directDevice{side: side, mtu: floor, stats: &stats,
			wake: func() { stopping.Store(true); _ = windows.SetEvent(quit) },
			free: func() error {
				session.End()
				_ = windows.CloseHandle(quit)
				return adapter.Close()
			},
		}, nil
	})
	if err != nil {
		return err
	}
	defer runtime.Close()
	if _, err := fmt.Fprintf(os.Stdout, "ready name=%s luid=%d mtu=%d floor-mtu=%d ipv6=%v\n",
		adapterName, luid, mtu, winn3ShippingFloorInnerMTU, mtu >= winn3IPv6MinLinkMTU); err != nil {
		return err
	}
	err = runtime.Run(ctx, os.Stdout)
	fmt.Fprintf(os.Stderr, "winn3-direct: tun-to-engine=%d engine-to-tun=%d invalid=%d oversize=%d ring-full=%d\n",
		stats.tunToSeam.Load(), stats.seamToTun.Load(), stats.dropInvalid.Load(), stats.dropOversize.Load(), stats.dropRingFull.Load())
	if ctx.Err() != nil {
		return nil
	}
	return err
}
