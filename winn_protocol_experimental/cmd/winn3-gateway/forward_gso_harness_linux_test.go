//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestTunGSOHarness is -tun-gso against a real kernel. It needs root and two
// network namespaces, so it skips unless WINN_TUN_GSO_HARNESS=1; run it with
// testdata/tun_gso_harness.sh, which builds the namespaces and runs this test
// inside the gateway one. It never touches the host's own namespace.
//
// The test is a user-space TCP client behind the gateway's TUN, the way a
// phone's packets arrive. It opens a TCP connection through the TUN to a
// listener in the far namespace and sends 4 MiB in two stages: stage A writes
// each window as one GSO frame it builds itself (deterministic coalescing),
// stage B submits each segment to the async writers, which coalesce whatever
// is queued. The far side's TCP stack is the oracle: the veth it reads from
// has checksum offload off, so a wrong IP or TCP checksum in any segment the
// kernel cut from a super packet is dropped there, the ACK never covers it and
// the test fails on the timeout; a wrong segmentation corrupts the stream,
// which is compared byte for byte at the end.
func TestTunGSOHarness(t *testing.T) {
	if os.Getenv("WINN_TUN_GSO_HARNESS") != "1" {
		t.Skip("needs root and the namespaces from testdata/tun_gso_harness.sh (WINN_TUN_GSO_HARNESS=1)")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	farNS := harnessEnv("WINN_TUN_GSO_FAR_NS", "wgso-far")
	far := netip.MustParseAddrPort(harnessEnv("WINN_TUN_GSO_FAR", "10.78.0.2:5201"))
	client := netip.MustParseAddr("10.77.0.7")
	const (
		mss       = 1321
		stageSize = 2 << 20
		sport     = 40123
	)

	ln := listenInNetns(t, farNS, far.String())
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- b
	}()

	s, err := newSharedGatewayTunOpts("wgso0", netip.MustParseAddr("10.77.0.1"), 24, 1400, newForwardTable(),
		tunOptions{vnetHdr: true, queues: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.enableAsyncWrites()
	s.async.gap = time.Hour // hand every packet off so the writer sees queued runs

	c := &harnessConn{t: t, s: s, src: client, dst: far.Addr(), sport: sport, dport: far.Port(), iss: 7_000_000}
	c.handshake()

	payload := make([]byte, 2*stageSize)
	for i := range payload {
		payload[i] = byte(i*7 + i>>11)
	}
	// Stage A: one GSO frame per window, written directly.
	frame := make([]byte, vnetHdrLen+gsoMaxIPTotal)
	for off := 0; off < stageSize; {
		segs := c.window(payload[off:stageSize], mss)
		for len(segs) > 0 {
			run := gsoRun(segs)
			if run < 2 {
				if _, err := s.writeQueue(0, segs[0]); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.writeGSOFrame(0, buildGSO(segs[:run], frame)); err != nil {
				t.Fatalf("the kernel refused a GSO frame of %d segments: %v", run, err)
			}
			segs = segs[run:]
		}
		off = int(c.sndNxt - c.iss - 1)
		c.waitAcked()
	}
	// Stage B: the async writers coalesce what they find queued.
	var pending atomic.Int64
	for off := stageSize; off < len(payload); {
		for _, seg := range c.window(payload[off:], mss) {
			if _, err := s.async.submit(0, &pending, seg); err != nil {
				t.Fatal(err)
			}
		}
		off = int(c.sndNxt - c.iss - 1)
		c.waitAcked()
	}
	c.fin()

	select {
	case b := <-got:
		if !bytes.Equal(b, payload) {
			t.Fatalf("the far side read %d bytes that differ from the %d sent", len(b), len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the far side never saw the end of the stream")
	}
	st := s.async.stats()
	t.Logf("stage B: %d GSO frames carried %d segments; %d packets written alone", st.GSOFrames, st.GSOSegments, st.Written-st.GSOSegments)
	if st.Failed != 0 {
		t.Fatalf("%d async writes failed", st.Failed)
	}
}

func harnessEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// listenInNetns opens a TCP listener inside the named namespace from a
// dedicated OS thread, then moves that thread back. A socket belongs to the
// namespace it was created in, so the listener stays there.
func listenInNetns(t *testing.T, ns, addr string) net.Listener {
	t.Helper()
	type result struct {
		ln  net.Listener
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer orig.Close()
		target, err := os.Open("/var/run/netns/" + ns)
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- result{err: err}
			return
		}
		ln, lerr := net.Listen("tcp4", addr)
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
			// Leave the thread locked: it dies with this goroutine.
			ch <- result{ln: ln, err: errors.Join(lerr, err)}
			return
		}
		runtime.UnlockOSThread()
		ch <- result{ln: ln, err: lerr}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatalf("listen in netns %s: %v", ns, r.err)
	}
	return r.ln
}

// harnessConn is the client half of one TCP connection, spoken through the
// TUN. It never retransmits: any segment the kernel drops fails the test.
type harnessConn struct {
	t            *testing.T
	s            *sharedGatewayTun
	src, dst     netip.Addr
	sport, dport uint16
	iss, irs     uint32
	sndNxt, una  uint32
	wnd          uint32
	ipID         uint16
}

func (c *harnessConn) segment(seq uint32, flags byte, opts, payload []byte) []byte {
	thl := 20 + len(opts)
	p := make([]byte, 20+thl+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], c.ipID)
	c.ipID++
	binary.BigEndian.PutUint16(p[6:8], ipv4FlagDF)
	p[8] = 64
	p[9] = 6
	s4, d4 := c.src.As4(), c.dst.As4()
	copy(p[12:16], s4[:])
	copy(p[16:20], d4[:])
	binary.BigEndian.PutUint16(p[10:12], ^foldChecksum(onesSum(p[:20], 0)))
	binary.BigEndian.PutUint16(p[20:22], c.sport)
	binary.BigEndian.PutUint16(p[22:24], c.dport)
	binary.BigEndian.PutUint32(p[24:28], seq)
	if flags&tcpFlagACK != 0 {
		binary.BigEndian.PutUint32(p[28:32], c.irs+1)
	}
	p[32] = byte(thl/4) << 4
	p[33] = flags
	binary.BigEndian.PutUint16(p[34:36], 65535)
	copy(p[40:], opts)
	copy(p[20+thl:], payload)
	sum := onesSum(p[12:20], 0) + 6 + uint32(len(p)-20)
	binary.BigEndian.PutUint16(p[36:38], ^foldChecksum(onesSum(p[20:], sum)))
	return p
}

func (c *harnessConn) send(p []byte) {
	if _, err := c.s.writeQueue(0, p); err != nil {
		c.t.Fatal(err)
	}
}

// read returns the next TCP segment of this connection from the TUN, with
// its virtio_net_hdr checked and stripped as drainQueue does.
func (c *harnessConn) read(deadline time.Time) (seq, ack uint32, flags byte, wnd uint16) {
	buf := make([]byte, vnetHdrLen+c.s.mtu+1)
	f := c.s.files[0]
	for {
		if err := f.SetReadDeadline(deadline); err != nil {
			c.t.Fatal(err)
		}
		n, err := f.Read(buf)
		if err != nil {
			c.t.Fatalf("waiting for the far side (snd.una %d, snd.nxt %d): %v", c.una-c.iss, c.sndNxt-c.iss, err)
		}
		if n < vnetHdrLen || buf[1] != vnetHdrGSONone || buf[0]&vnetHdrFNeedsCsum != 0 {
			c.t.Fatalf("read a virtio_net_hdr asking for offload (% x) without TUNSETOFFLOAD", buf[:min(n, vnetHdrLen)])
		}
		p := buf[vnetHdrLen:n]
		if len(p) < 40 || p[0]>>4 != 4 || p[9] != 6 {
			continue
		}
		ihl := int(p[0]&0xf) * 4
		tcp := p[ihl:]
		if binary.BigEndian.Uint16(tcp[0:2]) != c.dport || binary.BigEndian.Uint16(tcp[2:4]) != c.sport {
			continue
		}
		return binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]), tcp[13], binary.BigEndian.Uint16(tcp[14:16])
	}
}

func (c *harnessConn) handshake() {
	mssOpt := []byte{2, 4, 0, 0}
	binary.BigEndian.PutUint16(mssOpt[2:], 1321)
	c.send(c.segment(c.iss, 0x02, mssOpt, nil))
	seq, ack, flags, wnd := c.read(time.Now().Add(5 * time.Second))
	if flags&0x12 != 0x12 || ack != c.iss+1 {
		c.t.Fatalf("no SYN-ACK: flags %#x ack %d", flags, ack-c.iss)
	}
	c.irs, c.sndNxt, c.una, c.wnd = seq, c.iss+1, c.iss+1, uint32(wnd)
	c.send(c.segment(c.sndNxt, tcpFlagACK, nil, nil))
}

// window cuts the next window's segments from rest: full MSS segments with
// ACK, PSH on the last, at most gsoMaxMembers and the peer's window.
func (c *harnessConn) window(rest []byte, mss int) [][]byte {
	limit := min(len(rest), int(c.wnd), gsoMaxMembers*mss)
	var segs [][]byte
	for off := 0; off < limit; off += mss {
		end := min(off+mss, limit)
		flags := byte(tcpFlagACK)
		if end == limit {
			flags |= tcpFlagPSH
		}
		segs = append(segs, c.segment(c.sndNxt, flags, nil, rest[off:end]))
		c.sndNxt += uint32(end - off)
	}
	return segs
}

// waitAcked reads until everything sent is acknowledged and the peer's window
// is open again. The window is never inflated: a segment beyond it would be
// dropped and fail the test for the wrong reason.
func (c *harnessConn) waitAcked() {
	deadline := time.Now().Add(3 * time.Second)
	for c.una != c.sndNxt || c.wnd == 0 {
		_, ack, flags, wnd := c.read(deadline)
		if flags&0x04 != 0 {
			c.t.Fatalf("the far side reset the connection at snd.una %d", c.una-c.iss)
		}
		if flags&tcpFlagACK != 0 && int32(ack-c.una) > 0 && int32(ack-c.sndNxt) <= 0 {
			c.una = ack
		}
		c.wnd = uint32(wnd)
	}
}

func (c *harnessConn) fin() {
	c.send(c.segment(c.sndNxt, tcpFlagACK|0x01, nil, nil))
	c.sndNxt++
	c.waitAcked()
}
