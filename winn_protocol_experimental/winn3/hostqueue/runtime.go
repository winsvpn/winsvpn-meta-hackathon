// Package hostqueue hosts the strict Winn client with a directly attached host
// device. Despite the package name it uses no inner packet queue or socket.
// The privileged host retains descriptor authentication and route authority.
package hostqueue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// Device.Close must wake ReadPacket, prevent further device access, and wait
// for existing device calls before releasing native resources. WritePacket
// must return an error if a packet was not actually accepted by the host.
type Device interface {
	tun.Device
	io.Closer
}

// Runtime owns one carrier, one session and one host device. Open constructs
// everything before Run starts packet processing. Call Run once, then Close.
type Runtime struct {
	loop      *driver.Loop
	device    *attachedDevice
	sizing    driver.Sizing
	exclusion string
	closeOnce sync.Once
	closeErr  error
	stateMu   sync.Mutex
	started   bool
	closed    bool
}

// attachedDevice lets the real session constructor validate the complete
// configuration before the host creates an adapter. Publication happens before
// Run, so no device method can race with attachment.
type attachedDevice struct {
	Device
	mtu       int
	failed    chan error
	closeOnce sync.Once
	closeErr  error
}

func (d *attachedDevice) MTU() int { return d.mtu }
func (d *attachedDevice) Close() error {
	d.closeOnce.Do(func() { d.closeErr = d.Device.Close() })
	return d.closeErr
}
func (d *attachedDevice) ReadPacket(buf []byte) (int, error) {
	n, err := d.Device.ReadPacket(buf)
	if err != nil {
		select {
		case d.failed <- err:
		default:
		}
	}
	return n, err
}

// Open accepts only a protected, strict-PQ client profile with both gateway
// attestation keys and device kind wintun-direct. The upstream securefile
// readers enforce custody on the profile and every key file. The authenticated
// supervisor must install the outer route exclusion before calling Open.
// This function never authenticates a served descriptor or installs routes.
func Open(ctx context.Context, profilePath string, factory func(int) (Device, error)) (*Runtime, error) {
	if factory == nil {
		return nil, errors.New("direct host: nil device factory")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := loadWinn3Profile(profilePath)
	if err != nil {
		return nil, err
	}
	classes, err := profile.classes()
	if err != nil {
		return nil, err
	}
	pathMTU := profile.PathMTU
	if pathMTU == 0 {
		pathMTU = carrier.DefaultPathMTU
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return nil, err
	}
	cfg, admission, err := winn3BuildSession(profile)
	if err != nil {
		return nil, err
	}
	assignment, err := profile.Inner.assignmentAddrs()
	if err != nil {
		return nil, err
	}
	device := &attachedDevice{mtu: sizing.InnerMTU, failed: make(chan error, 1)}
	tunConfig := tun.Config{
		Assign: tun.Assignment{V4: assignment.V4, V6: assignment.V6,
			RouterV4: assignment.RouterV4, RouterV6: assignment.RouterV6},
		Device: device,
		Clock:  driver.SessionClock{Clock: driver.SystemClock{}},
	}
	// Validate the actual session/tun constructors before dialing or creating
	// the native adapter. The pipe cannot emit anything. A second key read
	// below avoids reusing material wiped by the probe's orderly Close.
	probeCarrier, err := carrier.NewPipe(carrier.PipeConfig{
		Class: classes[0], MaxMessageSize: sizing.MessageSize, PathMTU: sizing.PathMTU,
		Out: func([]byte) error { return errors.New("direct preflight cannot send") },
	})
	if err != nil {
		return nil, err
	}
	probe, err := driver.NewClient(driver.Config{Session: cfg, Sizing: sizing, Carrier: probeCarrier, Tun: &tunConfig})
	if err != nil {
		_ = probeCarrier.Close()
		return nil, err
	}
	closeUnstartedLoop(probe)
	cfg, admission, err = winn3BuildSession(profile)
	if err != nil {
		return nil, err
	}
	conn, err := winn3DialCarrier(ctx, profile, sizing, admission)
	if err != nil {
		return nil, err
	}
	loop, err := driver.NewClient(driver.Config{Session: cfg, Sizing: sizing, Carrier: conn, Tun: &tunConfig})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		closeUnstartedLoop(loop)
		return nil, err
	}
	native, err := factory(sizing.InnerMTU)
	if err != nil {
		if native != nil {
			_ = native.Close()
		}
		closeUnstartedLoop(loop)
		return nil, err
	}
	if native == nil {
		closeUnstartedLoop(loop)
		return nil, errors.New("direct host: nil device")
	}
	if native.MTU() != sizing.InnerMTU {
		_ = native.Close()
		closeUnstartedLoop(loop)
		return nil, errors.New("direct host: device MTU differs from plan floor")
	}
	device.Device = native
	r := &Runtime{loop: loop, device: device, sizing: sizing, exclusion: profile.OuterSocketExclusion}
	if err := ctx.Err(); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

// Run publishes the same promotion predicate as the desktop engine: carrying
// gate plus a successful validated device delivery. Cancellation or a failed
// device read stops the engine and closes the native device. The caller must
// bound its output writer; Windows additionally enforces a process exit bound.
func (r *Runtime) Run(ctx context.Context, out io.Writer) error {
	r.stateMu.Lock()
	if r.closed || r.started {
		r.stateMu.Unlock()
		return errors.New("direct host: runtime closed or already run")
	}
	r.started = true
	r.stateMu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.loop.Run(ctx) }()
	closed := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() { _ = r.device.Close(); close(closed) })
	defer func() {
		cancel()
		if !stopClose() {
			<-closed
		}
		_ = r.Close()
	}()
	promoted := false
	write := func(event string, runErr error) error {
		status := winn3StatusFrom(event, r.loop, r.sizing, r.exclusion)
		if event == "posture" && status.PromotionReady && !promoted {
			status.Event = "carrying"
			promoted = true
		}
		if event == "stopped" {
			status.PromotionReady = false
			status.Posture = winn3PostureBootstrap
			if runErr != nil {
				status.Refusal = "direct engine stopped"
			}
		}
		return winn3WriteStatus(out, status)
	}
	if err := write("posture", nil); err != nil {
		cancel()
		<-done
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var deviceErr error
	failed := r.device.failed
	for {
		select {
		case err := <-done:
			if deviceErr != nil {
				err = fmt.Errorf("direct host read: %w", deviceErr)
			}
			if writeErr := write("stopped", err); writeErr != nil {
				return writeErr
			}
			return err
		case deviceErr = <-failed:
			failed = nil
			cancel()
		case <-ticker.C:
			if err := write("posture", nil); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}

func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.stateMu.Lock()
		r.closed = true
		r.stateMu.Unlock()
		// Device.Close wakes the outbound reader even though Loop.Run does not
		// join that goroutine. Later device calls see a closed device, not a
		// freed Wintun ring.
		r.closeErr = r.device.Close()
		r.closeErr = errors.Join(r.closeErr, r.loop.Close())
		r.closeErr = errors.Join(r.closeErr, r.loop.Carrier().Close())
	})
	return r.closeErr
}

// Closing an unstarted client terminates and wipes its initiator immediately,
// but Loop.Close does not close the carrier. No run goroutine exists to do so.
func closeUnstartedLoop(loop *driver.Loop) {
	_ = loop.Close()
	_ = loop.Carrier().Close()
}
