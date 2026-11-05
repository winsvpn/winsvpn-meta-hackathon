package stagebreflector

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoopbackAddressStrictLiteralAllowlist(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:65535"} {
		parsed, err := ParseLoopbackUDPAddress(address)
		if err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		if parsed.Port < 0 {
			t.Fatalf("%s: invalid port", address)
		}
	}
	for _, address := range []string{
		"localhost:0",
		"0.0.0.0:0",
		"[::]:0",
		"192.0.2.1:0",
		"224.0.0.1:0",
		"[ff02::1]:0",
		"[::ffff:127.0.0.1]:0",
		"[::1%lo0]:0",
		"127.0.0.1",
		"",
	} {
		if _, err := ParseLoopbackUDPAddress(address); !errors.Is(err, ErrLoopbackAddress) {
			t.Fatalf("%q accepted or wrong error: %v", address, err)
		}
	}
}

func TestLoopbackUDPServeOneRoundTrip(t *testing.T) {
	request := deterministicRequest()
	clock := &sequenceClock{
		values: []uint64{
			request.IssuedAtUnixMilliseconds + 1,
			request.IssuedAtUnixMilliseconds + 2,
		},
	}
	server, err := ListenLoopbackUDP("127.0.0.1:0", publicKey(), 4, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.LocalAddr().Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("bound address = %s", server.LocalAddr())
	}
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	served := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { served <- server.ServeOne(ctx) }()
	if _, err := client.WriteToUDP(encoded, net.UDPAddrFromAddrPort(server.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, ResponseLength+1)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if n != ResponseLength {
		t.Fatalf("response length = %d", n)
	}
	verifiedRequest, err := VerifyRequest(
		encoded,
		publicKey(),
		request.IssuedAtUnixMilliseconds+1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyResponseCodec(
		buffer[:n],
		publicKey(),
		request,
		verifiedRequest.Tag,
	); err != nil {
		t.Fatal(err)
	}
}

func TestIPv6LoopbackUDPServeOneRoundTrip(t *testing.T) {
	request := deterministicRequest()
	clock := &sequenceClock{
		values: []uint64{
			request.IssuedAtUnixMilliseconds + 1,
			request.IssuedAtUnixMilliseconds + 2,
		},
	}
	server, err := ListenLoopbackUDP("[::1]:0", publicKey(), 4, clock.now)
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	if server.LocalAddr().Addr() != netip.IPv6Loopback() {
		t.Fatalf("bound address = %s", server.LocalAddr())
	}
	client, err := net.ListenUDP(
		"udp6",
		&net.UDPAddr{IP: net.IPv6loopback},
	)
	if err != nil {
		t.Skipf("IPv6 loopback client unavailable: %v", err)
	}
	defer client.Close()
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { served <- server.ServeOne(ctx) }()
	if _, err := client.WriteToUDP(
		encoded,
		net.UDPAddrFromAddrPort(server.LocalAddr()),
	); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, ResponseLength+1)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if n != ResponseLength {
		t.Fatalf("response length = %d", n)
	}
}

func TestServeOneCancellationWithoutDeadlineLeavesServerReusable(t *testing.T) {
	request := deterministicRequest()
	clock := &sequenceClock{
		values: []uint64{
			request.IssuedAtUnixMilliseconds + 1,
			request.IssuedAtUnixMilliseconds + 2,
		},
	}
	server, err := ListenLoopbackUDP("127.0.0.1:0", publicKey(), 4, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for iteration := 0; iteration < 16; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() { served <- server.ServeOne(ctx) }()
		cancel()
		select {
		case err := <-served:
			if !errors.Is(err, ErrCancelled) {
				t.Fatalf("cancel %d: %v", iteration, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("cancel %d did not unblock", iteration)
		}
	}

	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.ServeOne(ctx) }()
	if _, err := client.WriteToUDP(
		encoded,
		net.UDPAddrFromAddrPort(server.LocalAddr()),
	); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, ResponseLength+1)
	n, _, err := client.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	if n != ResponseLength {
		t.Fatalf("response length = %d", n)
	}
	if err := <-served; err != nil {
		t.Fatalf("reused server: %v", err)
	}
}

func TestServeOneQueuedAdmissionHonorsOwnCancellation(t *testing.T) {
	request := deterministicRequest()
	server, err := ListenLoopbackUDP(
		"127.0.0.1:0",
		publicKey(),
		4,
		func() uint64 { return request.IssuedAtUnixMilliseconds },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	activeContext, cancelActive := context.WithCancel(context.Background())
	activeResult := make(chan error, 1)
	go func() { activeResult <- server.ServeOne(activeContext) }()
	admissionDeadline := time.Now().Add(2 * time.Second)
	for len(server.admission) != 0 && time.Now().Before(admissionDeadline) {
		time.Sleep(time.Millisecond)
	}
	if len(server.admission) != 0 {
		t.Fatal("active caller did not acquire admission")
	}

	queuedContext, cancelQueued := context.WithCancel(context.Background())
	cancelQueued()
	started := time.Now()
	if err := server.ServeOne(queuedContext); !errors.Is(err, ErrCancelled) {
		t.Fatalf("queued cancellation: %v", err)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("queued cancellation waited for active caller")
	}

	cancelActive()
	select {
	case err := <-activeResult:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("active cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active caller did not exit")
	}
}

func TestLoopbackUDPRejectsTrailingDatagramWithoutResponse(t *testing.T) {
	request := deterministicRequest()
	clock := func() uint64 { return request.IssuedAtUnixMilliseconds }
	server, err := ListenLoopbackUDP("127.0.0.1:0", publicKey(), 1, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	encoded, _ := EncodeRequest(publicKey(), request)
	encoded = append(encoded, 0)
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	served := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { served <- server.ServeOne(ctx) }()
	if _, err := client.WriteToUDP(encoded, net.UDPAddrFromAddrPort(server.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, ErrDatagramLength) {
		t.Fatalf("serve error: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, ResponseLength)
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		t.Fatal("invalid datagram received a response")
	}
}

func TestServerErrorsDoNotContainClientAddressOrBody(t *testing.T) {
	request := deterministicRequest()
	server, err := ListenLoopbackUDP(
		"127.0.0.1:0",
		publicKey(),
		1,
		func() uint64 { return request.IssuedAtUnixMilliseconds },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	body := []byte("APPLE-IDENTIFIER-sensitive-packet-body")
	sourceAddress := client.LocalAddr().String()
	served := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { served <- server.ServeOne(ctx) }()
	if _, err := client.WriteToUDP(body, net.UDPAddrFromAddrPort(server.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	err = <-served
	if err == nil {
		t.Fatal("invalid packet accepted")
	}
	if strings.Contains(err.Error(), sourceAddress) ||
		strings.Contains(err.Error(), string(body)) ||
		strings.Contains(err.Error(), "APPLE-IDENTIFIER") {
		t.Fatalf("sensitive error: %q", err)
	}
}

func TestNilClockAndClosedServerFailClosed(t *testing.T) {
	if _, err := ListenLoopbackUDP("127.0.0.1:0", publicKey(), 1, nil); !errors.Is(err, ErrClock) {
		t.Fatalf("nil clock: %v", err)
	}
	var server *UDPServer
	if err := server.ServeOne(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil server: %v", err)
	}
	request := deterministicRequest()
	live, err := ListenLoopbackUDP(
		"127.0.0.1:0",
		publicKey(),
		1,
		func() uint64 { return request.IssuedAtUnixMilliseconds },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	var nilContext context.Context
	if err := live.ServeOne(nilContext); !errors.Is(err, ErrCancelled) {
		t.Fatalf("nil context: %v", err)
	}
}

type sequenceClock struct {
	mu     sync.Mutex
	values []uint64
	index  int
}

func (clock *sequenceClock) now() uint64 {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.index >= len(clock.values) {
		return clock.values[len(clock.values)-1]
	}
	value := clock.values[clock.index]
	clock.index++
	return value
}
