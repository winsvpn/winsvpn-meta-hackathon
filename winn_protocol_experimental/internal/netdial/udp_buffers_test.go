package netdial

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestDefaultQUICSocketBufferBytesMatchesTheV3ClientRequest(t *testing.T) {
	if DefaultQUICSocketBufferBytes != 8<<20 {
		t.Fatalf("DefaultQUICSocketBufferBytes is %d, want 8 MiB", DefaultQUICSocketBufferBytes)
	}
}

func TestListenHappyUDPRaisesKernelBuffers(t *testing.T) {
	baseline, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer baseline.Close()
	beforeRead, err := happyUDPSockoptInt(baseline, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	beforeWrite, err := happyUDPSockoptInt(baseline, syscall.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	if beforeRead >= DefaultQUICSocketBufferBytes {
		t.Fatalf("kernel default SO_RCVBUF is %d, already >= %d; skipping SetReadBuffer would not be visible",
			beforeRead, DefaultQUICSocketBufferBytes)
	}
	if beforeWrite >= DefaultQUICSocketBufferBytes {
		t.Fatalf("kernel default SO_SNDBUF is %d, already >= %d; skipping SetWriteBuffer would not be visible",
			beforeWrite, DefaultQUICSocketBufferBytes)
	}

	socket, err := listenHappyUDP("udp4", net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	afterRead, err := happyUDPSockoptInt(socket, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	afterWrite, err := happyUDPSockoptInt(socket, syscall.SO_SNDBUF)
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
	t.Logf("SO_RCVBUF %d -> %d; SO_SNDBUF %d -> %d; requested %d",
		beforeRead, afterRead, beforeWrite, afterWrite, DefaultQUICSocketBufferBytes)
}

func TestDialQUICPathOpensUDPThroughListenHappyUDP(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "happy.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "net.ListenUDP") {
		t.Fatal("happy.go contains net.ListenUDP; DialQUICPath must go through listenHappyUDP")
	}
	if !strings.Contains(text, "listenHappyUDP(network, local)") {
		t.Fatal("DialQUICPath does not call listenHappyUDP(network, local)")
	}
}
