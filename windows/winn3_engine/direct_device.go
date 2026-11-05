package main

import (
	"errors"
	"io"
	"sync"

	"winsvpn.local/winnprotocol/winn3/tun"
)

// directDevice hands packets straight to the Winn tun layer. No socket, queue,
// or borrowed Wintun slice crosses this boundary. Close refuses new calls,
// wakes the existing receive, and drains all ring access before freeing it.
type directDevice struct {
	side     tunSide
	mtu      int
	stats    *counters
	wake     func()
	free     func() error
	mu       sync.Mutex
	closed   bool
	active   sync.WaitGroup
	once     sync.Once
	wakeOnce sync.Once
	closeErr error
}

func (d *directDevice) enter() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	d.active.Add(1)
	return true
}

func (d *directDevice) MTU() int { return d.mtu }

func (d *directDevice) ReadPacket(buf []byte) (int, error) {
	if !d.enter() {
		return 0, io.ErrClosedPipe
	}
	defer d.active.Done()
	for {
		packet, release, err := d.side.receivePacket()
		if errors.Is(err, errTunAgain) {
			if err = d.side.waitReadable(); err != nil {
				return 0, err
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		if problem := classifyInnerPacket(packet, d.mtu); problem != nil {
			countRefusal(d.stats, problem)
			release()
			continue
		}
		if len(buf) < len(packet) {
			release()
			return 0, io.ErrShortBuffer
		}
		n := copy(buf, packet)
		release()
		d.stats.tunToSeam.Add(1)
		return n, nil
	}
}

func (d *directDevice) WritePacket(packet []byte) (int, error) {
	if !d.enter() {
		return 0, io.ErrClosedPipe
	}
	defer d.active.Done()
	if problem := classifyInnerPacket(packet, d.mtu); problem != nil {
		countRefusal(d.stats, problem)
		return 0, problem
	}
	if err := d.side.sendPacket(packet); err != nil {
		if errors.Is(err, errTunRingFull) {
			d.stats.dropRingFull.Add(1)
		} else {
			// Fatal writes also wake an idle read, which tells the runtime to
			// stop. Ring pressure is the sole recoverable write refusal.
			d.stop()
		}
		// Failed delivery must remain an error: the tun layer must never count
		// a full ring as RxPackets and thereby permit posture promotion.
		return 0, err
	}
	d.stats.seamToTun.Add(1)
	return len(packet), nil
}

func (d *directDevice) Close() error {
	d.once.Do(func() {
		d.stop()
		d.active.Wait()
		d.closeErr = d.free()
	})
	return d.closeErr
}

func (d *directDevice) stop() {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	d.wakeOnce.Do(d.wake)
}

var _ tun.Device = (*directDevice)(nil)
