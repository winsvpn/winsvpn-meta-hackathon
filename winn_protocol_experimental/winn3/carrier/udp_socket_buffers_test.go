package carrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUDPSocketBufferDefaultSitsInTheGatewayRange(t *testing.T) {
	if DefaultUDPSocketBufferBytes < 4<<20 || DefaultUDPSocketBufferBytes > 16<<20 {
		t.Fatalf("DefaultUDPSocketBufferBytes is %d; the gateway brief is 4–16 MiB", DefaultUDPSocketBufferBytes)
	}
	// ROUND 41 PACING EXPERIMENT: the default returns to 8 MiB for the
	// carrier-buffer A/B on the ingest tool; the range check is the invariant.
	if DefaultUDPSocketBufferBytes != 8<<20 {
		t.Fatalf("DefaultUDPSocketBufferBytes is %d, want the experiment 8 MiB", DefaultUDPSocketBufferBytes)
	}
}

func TestASocketLeftAtDefaultIsBelowTheClientRequest(t *testing.T) {
	conn := loopbackUDP(t)
	got, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	if got >= DefaultUDPSocketBufferBytes {
		t.Fatalf("kernel default SO_RCVBUF is %d, already >= the %d request; "+
			"skipping SetReadBuffer would not be visible, so this test is a zero-clause on this host",
			got, DefaultUDPSocketBufferBytes)
	}
}

func TestUDPSocketBuffersAreActuallyRequestedByNewUDP(t *testing.T) {
	conn := loopbackUDP(t)
	peer := loopbackUDP(t)
	beforeRead, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	beforeWrite, err := udpSockoptInt(conn, syscall.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	if beforeRead >= DefaultUDPSocketBufferBytes {
		t.Fatalf("kernel default SO_RCVBUF is %d, already >= %d; this test would pass without SetReadBuffer",
			beforeRead, DefaultUDPSocketBufferBytes)
	}

	c, err := NewUDP(UDPConfig{
		Conn: conn, Peer: peer.LocalAddr().(*net.UDPAddr), Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer func() { _ = c.Close() }()

	afterRead, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	afterWrite, err := udpSockoptInt(conn, syscall.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	if afterRead <= beforeRead {
		t.Fatalf("SO_RCVBUF did not rise: before=%d after=%d (SetReadBuffer was skipped or a no-op)",
			beforeRead, afterRead)
	}
	if afterWrite <= beforeWrite {
		t.Fatalf("SO_SNDBUF did not rise: before=%d after=%d (SetWriteBuffer was skipped or a no-op)",
			beforeWrite, afterWrite)
	}

	requested, gotRead, gotWrite := c.SocketBuffers()
	if requested != DefaultUDPSocketBufferBytes {
		t.Fatalf("SocketBuffers requested %d, want %d", requested, DefaultUDPSocketBufferBytes)
	}
	if gotRead != afterRead {
		t.Fatalf("SocketBuffers read %d != getsockopt %d", gotRead, afterRead)
	}
	if gotWrite != afterWrite {
		t.Fatalf("SocketBuffers write %d != getsockopt %d", gotWrite, afterWrite)
	}
}

func TestUDPSocketBuffersAreActuallyRequestedByDialUDP(t *testing.T) {
	gw := loopbackUDP(t)
	raw := loopbackUDP(t)
	defRead, err := udpSockoptInt(raw, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	defWrite, err := udpSockoptInt(raw, syscall.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialUDP(ctx, UDPConfig{
		Remote: gw.LocalAddr().(*net.UDPAddr), Clock: newFakeClock(),
	})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer func() { _ = c.Close() }()

	requested, gotRead, gotWrite := c.SocketBuffers()
	if requested != DefaultUDPSocketBufferBytes {
		t.Fatalf("DialUDP requested %d, want %d", requested, DefaultUDPSocketBufferBytes)
	}
	if gotRead <= defRead {
		t.Fatalf("DialUDP left SO_RCVBUF at kernel default %d (granted %d); SetReadBuffer was skipped",
			defRead, gotRead)
	}
	if gotWrite <= defWrite {
		t.Fatalf("DialUDP left SO_SNDBUF at kernel default %d (granted %d); SetWriteBuffer was skipped",
			defWrite, gotWrite)
	}
	liveRead, err := udpSockoptInt(c.conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	if liveRead != gotRead {
		t.Fatalf("SocketBuffers read %d != live getsockopt %d", gotRead, liveRead)
	}
}

func TestUDPSocketBuffersDoNotRefuseAShortGrant(t *testing.T) {
	conn := loopbackUDP(t)
	peer := loopbackUDP(t)
	const huge = 1 << 30
	c, err := NewUDP(UDPConfig{
		Conn:              conn,
		Peer:              peer.LocalAddr().(*net.UDPAddr),
		Clock:             newFakeClock(),
		SocketBufferBytes: huge,
	})
	if err != nil {
		t.Fatalf("NewUDP refused a short grant (client policy is warn-and-continue): %v", err)
	}
	defer func() { _ = c.Close() }()
	requested, gotRead, gotWrite := c.SocketBuffers()
	if requested != huge {
		t.Fatalf("requested %d, want %d", requested, huge)
	}
	if gotRead >= huge && gotWrite >= huge {
		t.Fatalf("this host granted the 1GiB request (read=%d write=%d); the test cannot prove we continue on a short grant",
			gotRead, gotWrite)
	}
	if !shortUDPSocketGrant(requested, gotRead, gotWrite) {
		t.Fatalf("shortUDPSocketGrant(%d, %d, %d) is false; the grant is short and the helper must say so",
			requested, gotRead, gotWrite)
	}
}

func TestUDPSocketBufferHookSeesTheGrant(t *testing.T) {
	conn := loopbackUDP(t)
	peer := loopbackUDP(t)
	var (
		seenReq, seenRead, seenWrite int
		called                       int
	)
	c, err := NewUDP(UDPConfig{
		Conn: conn, Peer: peer.LocalAddr().(*net.UDPAddr), Clock: newFakeClock(),
		SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
			called++
			seenReq, seenRead, seenWrite = requested, gotRead, gotWrite
			if setErr != nil {
				t.Errorf("Set* error on a default 8MiB request: %v", setErr)
			}
		},
	})
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	defer func() { _ = c.Close() }()
	if called != 1 {
		t.Fatalf("hook called %d times, want 1", called)
	}
	req, gotR, gotW := c.SocketBuffers()
	if seenReq != req || seenRead != gotR || seenWrite != gotW {
		t.Fatalf("hook saw requested=%d read=%d write=%d; SocketBuffers is %d %d %d",
			seenReq, seenRead, seenWrite, req, gotR, gotW)
	}
}

func TestDialUDPAndNewUDPDoNotDoubleFireTheHook(t *testing.T) {
	gw := loopbackUDP(t)
	var called int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialUDP(ctx, UDPConfig{
		Remote: gw.LocalAddr().(*net.UDPAddr), Clock: newFakeClock(),
		SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
			called++
		},
	})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer func() { _ = c.Close() }()
	if called != 1 {
		t.Fatalf("hook called %d times, want 1 (DialUDP apply + NewUDP must not both fire)", called)
	}
}

func TestNegativeSocketBufferBytesIsConfigError(t *testing.T) {
	conn := loopbackUDP(t)
	peer := loopbackUDP(t)
	_, err := NewUDP(UDPConfig{
		Conn: conn, Peer: peer.LocalAddr().(*net.UDPAddr),
		SocketBufferBytes: -1,
	})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("negative SocketBufferBytes returned %v, want ErrConfig", err)
	}
}

func TestFormatUDPSocketBufferGrantNamesThePolicyOnAShortGrant(t *testing.T) {
	line := FormatUDPSocketBufferGrant(8<<20, 212992, 212992, nil)
	for _, needle := range []string{
		"short grant",
		"212992",
		"continuing",
		"rmem_max",
	} {
		if !strings.Contains(line, needle) {
			t.Errorf("short-grant line does not name %q:\n  %s", needle, line)
		}
	}
	fullGrant := 8 << 20
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		fullGrant *= 2
	}
	ok := FormatUDPSocketBufferGrant(8<<20, fullGrant, fullGrant, nil)
	if strings.Contains(ok, "short grant") {
		t.Fatalf("a full grant was worded as a short grant: %s", ok)
	}
	if !strings.Contains(ok, fmt.Sprintf("granted read=%d", fullGrant)) {
		t.Fatalf("full-grant line does not name the grant: %s", ok)
	}
}

func TestUDPSocketBuffersSourcePinsTheSets(t *testing.T) {
	udpSrc, err := os.ReadFile("udp.go")
	if err != nil {
		t.Fatal(err)
	}
	bufSrc, err := os.ReadFile("udp_socket_buffers.go")
	if err != nil {
		t.Fatal(err)
	}
	udp := string(udpSrc)
	buf := string(bufSrc)

	if strings.Count(udp, "applyConfiguredUDPSocketBuffers(&cfg)") < 2 {
		t.Fatal("udp.go must call applyConfiguredUDPSocketBuffers from both DialUDP and NewUDP")
	}
	for _, n := range []string{
		"conn.SetReadBuffer(requested)",
		"conn.SetWriteBuffer(requested)",
		"udpSockoptInt(conn, syscall.SO_RCVBUF)",
		"udpSockoptInt(conn, syscall.SO_SNDBUF)",
	} {
		if !strings.Contains(buf, n) {
			t.Fatalf("udp_socket_buffers.go no longer contains %q", n)
		}
	}
	unixSrc, err := os.ReadFile("udp_socket_buffers_unix.go")
	if err != nil {
		t.Fatal(err)
	}
	winSrc, err := os.ReadFile("udp_socket_buffers_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unixSrc), "syscall.GetsockoptInt") {
		t.Fatal("udp_socket_buffers_unix.go must call syscall.GetsockoptInt")
	}
	if !strings.Contains(string(winSrc), "syscall.GetsockoptInt") {
		t.Fatal("udp_socket_buffers_windows.go must call syscall.GetsockoptInt")
	}
	if !strings.Contains(string(winSrc), "syscall.Handle(descriptor)") {
		t.Fatal("udp_socket_buffers_windows.go must pass syscall.Handle(descriptor); an int does not compile on windows")
	}
	for _, n := range []string{
		"udpSocketBufferMinBytes",
		"want at least",
		"udpBuffersTooSmall",
	} {
		if strings.Contains(buf, n) {
			t.Fatalf("client buffer helper contains gateway refusal marker %q; a phone cannot raise rmem_max", n)
		}
	}
}

func TestApplyUDPSocketBuffersReadsBackWithGetsockoptNotTheSetsockoptReturn(t *testing.T) {
	src, err := os.ReadFile("udp_socket_buffers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "SetReadBuffer returning nil is not evidence") {
		t.Fatal("the getsockopt-not-setsockopt warning was deleted from the helper")
	}
	conn := loopbackUDP(t)
	before, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	gotRead, gotWrite, setErr := applyUDPSocketBuffers(conn, DefaultUDPSocketBufferBytes)
	if setErr != nil {
		t.Fatalf("applyUDPSocketBuffers: %v", setErr)
	}
	if gotRead <= before {
		t.Fatalf("getsockopt SO_RCVBUF did not rise: before=%d after=%d", before, gotRead)
	}
	if gotWrite <= 0 {
		t.Fatalf("getsockopt SO_SNDBUF is %d", gotWrite)
	}
	again, err := udpSockoptInt(conn, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	if again != gotRead {
		t.Fatalf("applyUDPSocketBuffers returned read=%d but a second getsockopt is %d", gotRead, again)
	}
}

func TestSocketBufferGrantComparisonUsesRequestUnits(t *testing.T) {
	const requested = 8 << 20
	for _, goos := range []string{"linux", "android", "darwin", "ios", "windows"} {
		t.Run(goos, func(t *testing.T) {
			factor := 1
			if goos == "linux" || goos == "android" {
				factor = 2
			}
			for _, granted := range []int{0, requested / 2, requested - 1, requested, requested * 2} {
				if got := socketBufferRequestUnits(goos, granted*factor); got != granted {
					t.Fatalf("raw %d normalized to %d, want %d", granted*factor, got, granted)
				}
			}
		})
	}
	factor := 1
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		factor = 2
	}
	for _, pair := range [][2]int{{requested / 2, requested}, {requested, requested / 2}, {requested - 1, requested}} {
		if !shortUDPSocketGrant(requested, pair[0]*factor, pair[1]*factor) {
			t.Fatalf("clamped grant was not reported: %v", pair)
		}
	}
	if shortUDPSocketGrant(requested, requested*factor, requested*factor) {
		t.Fatal("full grant was reported as clamped")
	}
}
