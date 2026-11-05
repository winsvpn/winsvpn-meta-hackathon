//go:build linux || android

package carrier

// Shared-socket IP_RECVERR behaviour on a real kernel, over loopback.
//
// These tests use only NewRawBatchConn, WriteBatchTo and ReadBatchFrom, and set
// IP_RECVERR with a raw setsockopt rather than EnableSendErrorReporting, so the
// same file also compiles against a tree without the send-error change. That is
// deliberate: run there it shows what enabling IP_RECVERR alone does to a
// socket shared by every session.

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func setRawRecvErr(t *testing.T, c *net.UDPConn) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVERR, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatalf("IP_RECVERR: %v", serr)
	}
}

// closedLoopbackPort returns an address nothing listens on, so a datagram to it
// draws an ICMP port unreachable. Loopback is exempt from the ICMP rate limit
// (icmpv4_xrlim_allow, net/ipv4/icmp.c).
func closedLoopbackPort(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = c.Close()
	return ap
}

func seqMsgs(first uint32, count, size int) []BatchMsg {
	msgs := make([]BatchMsg, count)
	for i := range msgs {
		msgs[i].Payload = make([]byte, size)
		binary.BigEndian.PutUint32(msgs[i].Payload, first+uint32(i))
		msgs[i].N = size
	}
	return msgs
}

// readSeqs reads datagrams from c until quiet for the given gap.
func readSeqs(t *testing.T, c *net.UDPConn, gap time.Duration) map[uint32]int {
	t.Helper()
	got := map[uint32]int{}
	buf := make([]byte, 65536)
	for {
		_ = c.SetReadDeadline(time.Now().Add(gap))
		n, err := c.Read(buf)
		if err != nil {
			return got
		}
		if n >= 4 {
			got[binary.BigEndian.Uint32(buf)]++
		}
	}
}

// provokePortUnreachable sends one datagram to a closed port and waits for the
// ICMP error to land on the gateway socket.
func provokePortUnreachable(t *testing.T, raw *RawBatchConn, closed netip.AddrPort) {
	t.Helper()
	if n, err := raw.WriteBatchTo(seqMsgs(900000, 1, 64), closed); n != 1 || err != nil {
		t.Fatalf("send to the closed port: n=%d err=%v", n, err)
	}
	time.Sleep(50 * time.Millisecond)
}

// TestAPortUnreachableAboutOnePeerIsNotAnotherPeersSendVerdict pins the send
// half: another peer's ICMP result must not fail, or lose, a send to a healthy
// peer on the same socket.
func TestAPortUnreachableAboutOnePeerIsNotAnotherPeersSendVerdict(t *testing.T) {
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	setRawRecvErr(t, gw)
	healthy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	closed := closedLoopbackPort(t)
	dest := healthy.LocalAddr().(*net.UDPAddr).AddrPort()

	for round := 0; round < 3; round++ {
		provokePortUnreachable(t, raw, closed)
		msgs := seqMsgs(uint32(round*8), 8, 200)
		n, err := raw.WriteBatchTo(msgs, dest)
		if n != len(msgs) || err != nil {
			t.Fatalf("round %d: WriteBatchTo to the healthy peer returned (%d, %v) after "+
				"ANOTHER peer's port unreachable; that error is not this batch's verdict", round, n, err)
		}
	}
	got := readSeqs(t, healthy, 200*time.Millisecond)
	for s := uint32(0); s < 24; s++ {
		if got[s] != 1 {
			t.Fatalf("healthy peer received datagram %d %d times, want once (got %d distinct)", s, got[s], len(got))
		}
	}
}

// TestAPortUnreachableAboutOnePeerDoesNotFailTheSharedReceive pins the receive
// half: the pump reading the shared socket must still get a healthy peer's
// datagram.
func TestAPortUnreachableAboutOnePeerDoesNotFailTheSharedReceive(t *testing.T) {
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	setRawRecvErr(t, gw)
	healthy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	closed := closedLoopbackPort(t)
	gwAddr := gw.LocalAddr().(*net.UDPAddr)

	for round := 0; round < 3; round++ {
		if _, err := healthy.WriteToUDP([]byte{0, 0, 0, byte(round), 1, 2, 3, 4}, gwAddr); err != nil {
			t.Fatal(err)
		}
		provokePortUnreachable(t, raw, closed)
		msgs := make([]BatchMsg, 8)
		for i := range msgs {
			msgs[i].Payload = make([]byte, 2048)
		}
		_ = gw.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := raw.ReadBatchFrom(msgs)
		if err != nil || n < 1 {
			t.Fatalf("round %d: ReadBatchFrom returned (%d, %v) with a healthy peer's datagram queued; "+
				"another peer's port unreachable must not fail the shared receive", round, n, err)
		}
		if msgs[0].N != 8 || msgs[0].Payload[3] != byte(round) {
			t.Fatalf("round %d: read the wrong datagram: n=%d", round, msgs[0].N)
		}
	}
}
