package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func directFixture(t *testing.T) (*directDevice, *fakeTun, *atomic.Int32) {
	t.Helper()
	f := newFakeTun()
	freed := new(atomic.Int32)
	d := &directDevice{side: f, mtu: harnessMTU, stats: &counters{},
		wake: func() { close(f.closed) }, free: func() error { freed.Add(1); return nil }}
	t.Cleanup(func() { _ = d.Close() })
	return d, f, freed
}

func TestDirectReadOwnsBytesAndReleasesRejectedPackets(t *testing.T) {
	d, f, _ := directFixture(t)
	f.push([]byte{0x45})
	f.push(ipv4(harnessMTU+1, harnessMTU+1))
	p := ipv4(48, 48)
	want := bytes.Clone(p)
	f.push(p)
	buf := make([]byte, harnessMTU)
	n, err := d.ReadPacket(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("read = %d, %v", n, err)
	}
	clear(p)
	if !bytes.Equal(buf[:n], want) {
		t.Fatal("read aliases released native buffer")
	}
	if f.released.Load() != 3 || d.stats.dropInvalid.Load() != 1 || d.stats.dropOversize.Load() != 1 {
		t.Fatal("missing release or refusal accounting")
	}
	f.push(ipv4(48, 48))
	if n, err := d.ReadPacket(make([]byte, 20)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read = %d, %v", n, err)
	}
	if f.released.Load() != 4 {
		t.Fatal("short read leaked borrowed packet")
	}
}

func TestDirectFullRingIsNeverSuccessfulDelivery(t *testing.T) {
	d, f, _ := directFixture(t)
	f.ringFull.Store(true)
	if n, err := d.WritePacket(ipv4(48, 48)); n != 0 || !errors.Is(err, errTunRingFull) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if d.stats.seamToTun.Load() != 0 || d.stats.dropRingFull.Load() != 1 {
		t.Fatal("failed delivery counted as success")
	}
	f.ringFull.Store(false)
	if n, err := d.WritePacket(ipv4(48, 48)); n != 48 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if len(<-f.in) != 48 {
		t.Fatal("wrong native packet")
	}
	for _, p := range [][]byte{{0x45}, ipv4(harnessMTU+1, harnessMTU+1)} {
		if n, err := d.WritePacket(p); n != 0 || err == nil {
			t.Fatal("malformed packet reached native ring")
		}
	}
}

func TestDirectCloseWakesIdleReaderAndRefusesNewCalls(t *testing.T) {
	d, _, freed := directFixture(t)
	done := make(chan error, 1)
	go func() { _, err := d.ReadPacket(make([]byte, harnessMTU)); done <- err }()
	var closers sync.WaitGroup
	for range 16 {
		closers.Go(func() { _ = d.Close() })
	}
	closers.Wait()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("reader stuck")
	}
	if freed.Load() != 1 {
		t.Fatalf("native frees = %d", freed.Load())
	}
	if _, err := d.ReadPacket(make([]byte, harnessMTU)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("post-close read admitted")
	}
	if _, err := d.WritePacket(ipv4(48, 48)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("post-close write admitted")
	}
}

type heldSendTun struct {
	*fakeTun
	entered chan struct{}
	release chan struct{}
}

func (f *heldSendTun) sendPacket([]byte) error { close(f.entered); <-f.release; return nil }

func TestDirectCloseDoesNotFreeUnderActiveWrite(t *testing.T) {
	d, f, freed := directFixture(t)
	held := &heldSendTun{fakeTun: f, entered: make(chan struct{}), release: make(chan struct{})}
	d.side = held
	written := make(chan struct{})
	go func() { _, _ = d.WritePacket(ipv4(48, 48)); close(written) }()
	<-held.entered
	closed := make(chan struct{})
	go func() { _ = d.Close(); close(closed) }()
	<-f.closed
	if freed.Load() != 0 {
		t.Fatal("ring freed under active send")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before native call")
	default:
	}
	close(held.release)
	<-written
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not drain")
	}
	if freed.Load() != 1 {
		t.Fatal("ring was not freed exactly once")
	}
}

func TestDirectControlRejectsAmbiguity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	valid := `{"profile":` + strconv.Quote(path) + `}`
	if got, err := parseDirectStart(valid); err != nil || got != path {
		t.Fatalf("valid = %q, %v", got, err)
	}
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"profile":"relative.json"}`, `{"Profile":` + strconv.Quote(path) + `}`,
		valid + ` {}`, valid + ` garbage`, `{"profile":null}`, `{"profile":` + strconv.Quote(path) + `,"profile":` + strconv.Quote(path) + `}`,
		`{"profile":` + strconv.Quote(path) + `,"engine_port":123}`, `{"profile":"//server/profile.json"}`,
	} {
		if _, err := parseDirectStart(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

type fatalSendTun struct{ *fakeTun }

func (f fatalSendTun) sendPacket([]byte) error { return errTunClosed }

func TestDirectFatalWriteWakesReaderAndClosesAdmission(t *testing.T) {
	d, f, freed := directFixture(t)
	d.side = fatalSendTun{f}
	done := make(chan error, 1)
	go func() { _, err := d.ReadPacket(make([]byte, harnessMTU)); done <- err }()
	if _, err := d.WritePacket(ipv4(48, 48)); !errors.Is(err, errTunClosed) {
		t.Fatalf("fatal write = %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fatal write did not stop read")
		}
	case <-time.After(time.Second):
		t.Fatal("idle reader stranded")
	}
	if _, err := d.WritePacket(ipv4(48, 48)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("fatal write left adapter admission open")
	}
	_ = d.Close()
	if freed.Load() != 1 {
		t.Fatal("fatal write cleanup did not free once")
	}
}
