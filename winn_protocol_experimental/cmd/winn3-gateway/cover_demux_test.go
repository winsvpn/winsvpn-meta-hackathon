package main

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestIsQUICLongHeaderAcceptsKnownVersionsOnly(t *testing.T) {
	long := func(version uint32) []byte {
		b := []byte{quicHeaderFormLong | quicFixedBit, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:5], version)
		return b
	}
	for _, tc := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"v1", long(quicVersion1), true},
		{"v2", long(quicVersion2), true},
		{"version negotiation", long(quicVersionNegotiation), true},
		{"unknown version", long(0x12345678), false},
		{"short header", []byte{quicFixedBit, 1, 2, 3, 4, 5}, false},
		{"too short", []byte{quicHeaderFormLong, 0, 0, 0}, false},
		{"empty", nil, false},
		{"v3-looking high entropy without long bit", []byte{0x41, 0x00, 0x00, 0x00, 0x01, 0x00}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isQUICLongHeader(tc.pkt); got != tc.want {
				t.Fatalf("isQUICLongHeader(%x) = %v, want %v", tc.pkt, got, tc.want)
			}
		})
	}
}

func TestSplitUDPDeliversNonQUICToV3AndQUICToCover(t *testing.T) {
	real, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	split := newSplitUDP(real, demuxDatagramMin)
	defer func() {
		split.stop()
		_ = real.Close()
	}()

	client, err := net.DialUDP("udp4", nil, real.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	v3Payload := []byte("not-quic-high-entropy-v3-shape")
	if _, err := client.Write(v3Payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	_ = split.v3.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := split.v3.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("v3 side did not receive the non-QUIC datagram: %v", err)
	}
	if string(buf[:n]) != string(v3Payload) {
		t.Fatalf("v3 got %q, want %q", buf[:n], v3Payload)
	}

	quicPkt := []byte{quicHeaderFormLong | quicFixedBit, 0, 0, 0, 1, 0, 0, 0x11, 0x22}
	if _, err := client.Write(quicPkt); err != nil {
		t.Fatal(err)
	}
	_ = split.quic.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = split.quic.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("QUIC side did not receive the long-header datagram: %v", err)
	}
	if string(buf[:n]) != string(quicPkt) {
		t.Fatalf("QUIC got %q, want %q", buf[:n], quicPkt)
	}

	_ = split.v3.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	n, _, err = split.v3.ReadFromUDPAddrPort(buf)
	if n > 0 {
		t.Fatalf("v3 side received the QUIC datagram (%q); the classifier leaked cover into the protocol path", buf[:n])
	}
	if err == nil || (!os.IsTimeout(err) && err != os.ErrDeadlineExceeded) {
		t.Fatalf("v3 read after QUIC packet: n=%d err=%v, want timeout", n, err)
	}
}

// TestSplitUDPUnblocksV3WhenTheRealSocketCloses pins the cover-failure path:
// cover.go closes the real UDP socket when the HTTPS/QUIC listener dies, and
// splitUDP.pump's ReadFromUDP then returns an error. If pump returns without
// closing done, server.readLoop is parked forever on demuxSide.recv and the
// gateway keeps printing posture while carrying nothing — silence that, to a
// client, is indistinguishable from censorship.
func TestSplitUDPUnblocksV3WhenTheRealSocketCloses(t *testing.T) {
	real, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	split := newSplitUDP(real, demuxDatagramMin)
	defer split.stop()

	parked := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, readErr := split.v3.ReadFromUDPAddrPort(buf)
		parked <- readErr
	}()

	// Give recv a chance to park on incoming/done before the socket disappears.
	time.Sleep(50 * time.Millisecond)
	if err := real.Close(); err != nil {
		t.Fatalf("closing the real socket: %v", err)
	}

	select {
	case readErr := <-parked:
		if readErr == nil {
			t.Fatal("v3 ReadFromUDPAddrPort returned a nil error after the real socket closed")
		}
		if !errors.Is(readErr, net.ErrClosed) {
			t.Fatalf("v3 unblocked with %v (%T); want net.ErrClosed so readLoop observes the same closed-socket path it already handles", readErr, readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("v3 ReadFromUDPAddrPort still blocked 2s after the real UDP socket closed; splitUDP.pump returned without closing done")
	}
}

func TestCoverCIDGenGeneratesAndMatches(t *testing.T) {
	gen, err := newCoverCIDGen()
	if err != nil {
		t.Fatalf("newCoverCIDGen: %v", err)
	}
	if gen.ConnectionIDLen() != coverCIDLen {
		t.Fatalf("ConnectionIDLen = %d, want %d", gen.ConnectionIDLen(), coverCIDLen)
	}

	cid, err := gen.GenerateConnectionID()
	if err != nil {
		t.Fatalf("GenerateConnectionID: %v", err)
	}
	cidBytes := cid.Bytes()
	if len(cidBytes) != coverCIDLen {
		t.Fatalf("generated CID len = %d, want %d", len(cidBytes), coverCIDLen)
	}

	pkt := make([]byte, 1+coverCIDLen+16)
	pkt[0] = quicFixedBit // 0x40
	copy(pkt[1:1+coverCIDLen], cidBytes)

	var scratch [2][aes.BlockSize]byte
	if !gen.matches(pkt, &scratch) {
		t.Fatal("gen.matches failed for valid generated connection ID")
	}

	corrupted := append([]byte(nil), pkt...)
	corrupted[1+coverCIDNonceLen] ^= 0x01
	if gen.matches(corrupted, &scratch) {
		t.Fatal("gen.matches accepted corrupted connection ID tag")
	}

	corruptedNonce := append([]byte(nil), pkt...)
	corruptedNonce[1] ^= 0x01
	if gen.matches(corruptedNonce, &scratch) {
		t.Fatal("gen.matches accepted modified nonce without matching tag")
	}

	if gen.matches(pkt[:1+coverCIDLen-1], &scratch) {
		t.Fatal("gen.matches accepted truncated packet")
	}
}

func TestSplitUDPDeliversShortHeaderQUICToCover(t *testing.T) {
	real, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	split := newSplitUDP(real, demuxDatagramMin)
	defer func() {
		split.stop()
		_ = real.Close()
	}()

	client, err := net.DialUDP("udp4", nil, real.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	cid, err := split.cidGen.GenerateConnectionID()
	if err != nil {
		t.Fatalf("GenerateConnectionID: %v", err)
	}

	shortHeaderPkt := make([]byte, 1+coverCIDLen+8)
	shortHeaderPkt[0] = quicFixedBit
	copy(shortHeaderPkt[1:1+coverCIDLen], cid.Bytes())
	copy(shortHeaderPkt[1+coverCIDLen:], []byte("quicdata"))

	if _, err := client.Write(shortHeaderPkt); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 128)
	_ = split.quic.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := split.quic.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("QUIC side did not receive short-header packet: %v", err)
	}
	if string(buf[:n]) != string(shortHeaderPkt) {
		t.Fatalf("QUIC got %x, want %x", buf[:n], shortHeaderPkt)
	}

	fakeShortPkt := make([]byte, 1+coverCIDLen+8)
	fakeShortPkt[0] = quicFixedBit
	copy(fakeShortPkt[1:], []byte("forged-dcid-not-matching-our-tag"))
	if _, err := client.Write(fakeShortPkt); err != nil {
		t.Fatal(err)
	}

	_ = split.v3.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = split.v3.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("v3 side did not receive non-matching short-header packet: %v", err)
	}
	if string(buf[:n]) != string(fakeShortPkt) {
		t.Fatalf("v3 got %x, want %x", buf[:n], fakeShortPkt)
	}
}

