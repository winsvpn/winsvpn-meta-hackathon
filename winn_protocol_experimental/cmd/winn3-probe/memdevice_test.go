package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestMemDeviceReadPacketRefusesTruncation(t *testing.T) {
	d := newMemDevice(1280)
	t.Cleanup(func() { _ = d.Close() })
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 64, 0, 2, 1, 1, 1, 1}
	select {
	case d.in <- pkt:
	default:
		t.Fatal("in channel refused the packet")
	}
	n, err := d.ReadPacket(make([]byte, 8))
	if err == nil {
		t.Fatalf("short buffer was accepted as n=%d; copy would have truncated silently", n)
	}
	if n != 0 {
		t.Fatalf("n=%d on truncation error, want 0", n)
	}
	if !strings.Contains(err.Error(), "truncate") {
		t.Fatalf("error does not say the copy would truncate: %v", err)
	}
}

func TestMemDeviceReadPacketCopiesWhenBufferFits(t *testing.T) {
	d := newMemDevice(1280)
	t.Cleanup(func() { _ = d.Close() })
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 64, 0, 2, 1, 1, 1, 1}
	d.in <- pkt
	buf := make([]byte, 64)
	n, err := d.ReadPacket(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(pkt) {
		t.Fatalf("n=%d, want %d", n, len(pkt))
	}
	if string(buf[:n]) != string(pkt) {
		t.Fatalf("got %x want %x", buf[:n], pkt)
	}
}

func TestMemDeviceReadPacketClosed(t *testing.T) {
	d := newMemDevice(1280)
	_ = d.Close()
	_, err := d.ReadPacket(make([]byte, 64))
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("got %v, want os.ErrClosed", err)
	}
}
