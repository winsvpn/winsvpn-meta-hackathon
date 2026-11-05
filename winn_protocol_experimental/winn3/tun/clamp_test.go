package tun

// ClampInnerMTU is the tun half of silent-refusal instance #3's APPLY path.
// These tests pin it independently of the loop, so a loop-level green cannot
// hide a clamp that does not actually move the device MTU.

import (
	"errors"
	"testing"
	"time"
)

// setterDevice is a fakeDevice that implements MTUSetter. It is a distinct
// type on purpose: the package's fakeDevice models production hosts that
// cannot SetMTU, and ClampInnerMTU must still refuse those.
type setterDevice struct {
	fakeDevice
}

func (d *setterDevice) SetMTU(n int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n > d.mtu {
		return errors.New("setterDevice: raising the MTU is refused")
	}
	if n < 1 {
		return errors.New("setterDevice: MTU is not positive")
	}
	d.mtu = n
	return nil
}

func newSetterFixture(t *testing.T, mutate ...func(*Config)) (*fixture, *setterDevice) {
	t.Helper()
	dev := &setterDevice{fakeDevice: fakeDevice{mtu: fixtureInnerMTU}}
	sink := &fakeSink{}
	clock := newFakeClock()
	gate := NewGate()
	cfg := Config{
		Assign:                  fixtureAssign(),
		Device:                  dev,
		Sink:                    sink,
		Clock:                   clock,
		Gate:                    gate,
		CarrierFloorMessageSize: fixtureCarrierFloor,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	tn, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{t: t, tun: tn, dev: &dev.fakeDevice, sink: sink, clock: clock, gate: gate}, dev
}

func TestClampInnerMTULowersTheDeviceAndTheTunnelTogether(t *testing.T) {
	f, dev := newSetterFixture(t)
	before := f.tun.InnerMTU()
	if before != fixtureInnerMTU {
		t.Fatalf("InnerMTU is %d, want %d", before, fixtureInnerMTU)
	}
	want := IPv6MinLinkMTU
	if want >= before {
		t.Fatalf("harness: clamp target %d is not below %d", want, before)
	}
	if err := f.tun.ClampInnerMTU(want); err != nil {
		t.Fatalf("ClampInnerMTU(%d): %v", want, err)
	}
	if got := f.tun.InnerMTU(); got != want {
		t.Fatalf("InnerMTU is %d after clamp, want %d", got, want)
	}
	if got := f.tun.DeviceMTU(); got != want {
		t.Fatalf("DeviceMTU is %d after clamp, want %d", got, want)
	}
	if got := dev.MTU(); got != want {
		t.Fatalf("device.MTU is %d after clamp, want %d", got, want)
	}
}

func TestClampInnerMTUIsANoOpWhenTheValueIsUnchanged(t *testing.T) {
	f, _ := newSetterFixture(t)
	if err := f.tun.ClampInnerMTU(f.tun.InnerMTU()); err != nil {
		t.Fatalf("equal clamp: %v", err)
	}
}

func TestClampInnerMTURefusesToRaise(t *testing.T) {
	f, _ := newSetterFixture(t)
	if err := f.tun.ClampInnerMTU(f.tun.InnerMTU() + 1); !errors.Is(err, ErrConfig) {
		t.Fatalf("raising returned %v, want ErrConfig", err)
	}
}

func TestClampInnerMTURefusesWhileTheGateIsCarrying(t *testing.T) {
	f, _ := newSetterFixture(t)
	f.carrying()
	if err := f.tun.ClampInnerMTU(IPv6MinLinkMTU); !errors.Is(err, ErrConfig) {
		t.Fatalf("clamp while carrying returned %v, want ErrConfig", err)
	}
}

func TestClampInnerMTURefusesADeviceThatCannotSetMTU(t *testing.T) {
	f := newFixture(t)
	if err := f.tun.ClampInnerMTU(IPv6MinLinkMTU); !errors.Is(err, ErrConfig) {
		t.Fatalf("non-setter clamp returned %v, want ErrConfig", err)
	}
	if f.tun.InnerMTU() != fixtureInnerMTU {
		t.Fatalf("a refused clamp mutated InnerMTU to %d", f.tun.InnerMTU())
	}
}

func TestClampInnerMTURefusesBelowTheIPv6FloorWhenV6IsAssigned(t *testing.T) {
	f, _ := newSetterFixture(t)
	if err := f.tun.ClampInnerMTU(IPv6MinLinkMTU - 1); !errors.Is(err, ErrConfig) {
		t.Fatalf("below-IPv6 clamp returned %v, want ErrConfig", err)
	}
}

func TestClampInnerMTURefusesBelowTheIPv4Floor(t *testing.T) {
	v4only := func(c *Config) {
		c.Assign = Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4}
	}
	f, _ := newSetterFixture(t, v4only)
	if err := f.tun.ClampInnerMTU(MinInnerMTUv4 - 1); !errors.Is(err, ErrConfig) {
		t.Fatalf("below-IPv4 clamp returned %v, want ErrConfig", err)
	}
	if f.tun.InnerMTU() != fixtureInnerMTU {
		t.Fatalf("a refused clamp mutated InnerMTU to %d", f.tun.InnerMTU())
	}
}

// failSetter implements MTUSetter but never changes the device. A clamp that
// updated the tunnel's innerMTU anyway would recreate the black hole New
// refuses (device MTU > inner MTU).
type failSetter struct {
	setterDevice
}

func (d *failSetter) SetMTU(int) error {
	return errors.New("setmtu boom")
}

func TestClampInnerMTULeavesBothUnchangedWhenSetMTUFails(t *testing.T) {
	dev := &failSetter{setterDevice: setterDevice{fakeDevice: fakeDevice{mtu: fixtureInnerMTU}}}
	sink := &fakeSink{}
	clock := newFakeClock()
	gate := NewGate()
	tn, err := New(Config{
		Assign:                  fixtureAssign(),
		Device:                  dev,
		Sink:                    sink,
		Clock:                   clock,
		Gate:                    gate,
		CarrierFloorMessageSize: fixtureCarrierFloor,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	beforeInner, beforeDev := tn.InnerMTU(), tn.DeviceMTU()
	if err := tn.ClampInnerMTU(IPv6MinLinkMTU); !errors.Is(err, ErrConfig) {
		t.Fatalf("failed SetMTU returned %v, want ErrConfig", err)
	}
	if tn.InnerMTU() != beforeInner || tn.DeviceMTU() != beforeDev {
		t.Fatalf("failed SetMTU mutated tunnel MTU inner=%d device=%d, want %d and %d",
			tn.InnerMTU(), tn.DeviceMTU(), beforeInner, beforeDev)
	}
	if dev.MTU() != beforeDev {
		t.Fatalf("failed SetMTU mutated the host device to %d", dev.MTU())
	}
}

// blockingSetter holds SetMTU until release is closed, so a test can observe
// whether ClampInnerMTU holds the gate write lock across the device call.
type blockingSetter struct {
	setterDevice
	entered chan struct{}
	release chan struct{}
}

func (d *blockingSetter) SetMTU(n int) error {
	select {
	case <-d.entered:
	default:
		close(d.entered)
	}
	<-d.release
	return d.setterDevice.SetMTU(n)
}

// TestClampInnerMTUHoldsTheGateUntilSetMTUReturns is the teeth for the
// exclude() lock. Without it, Gate.Set(StateCarrying) returns while SetMTU is
// still running and Outbound can observe a half-clamped MTU.
func TestClampInnerMTUHoldsTheGateUntilSetMTUReturns(t *testing.T) {
	dev := &blockingSetter{
		setterDevice: setterDevice{fakeDevice: fakeDevice{mtu: fixtureInnerMTU}},
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	tn, err := New(Config{
		Assign:                  fixtureAssign(),
		Device:                  dev,
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		Gate:                    NewGate(),
		CarrierFloorMessageSize: fixtureCarrierFloor,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	clampErr := make(chan error, 1)
	go func() { clampErr <- tn.ClampInnerMTU(IPv6MinLinkMTU) }()
	select {
	case <-dev.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("SetMTU was never entered")
	}

	setReturned := make(chan struct{})
	go func() {
		tn.Gate().Set(StateCarrying)
		close(setReturned)
	}()
	select {
	case <-setReturned:
		t.Fatal("Gate.Set returned while ClampInnerMTU still held the write lock")
	case <-time.After(100 * time.Millisecond):
	}

	close(dev.release)
	if err := <-clampErr; err != nil {
		t.Fatalf("clamp: %v", err)
	}
	select {
	case <-setReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Gate.Set never returned after clamp released the lock")
	}
	if tn.InnerMTU() != IPv6MinLinkMTU {
		t.Fatalf("InnerMTU=%d, want %d", tn.InnerMTU(), IPv6MinLinkMTU)
	}
	if tn.Gate().State() != StateCarrying {
		t.Fatalf("gate is %s, want carrying after Set unblocked", tn.Gate().State())
	}
}
