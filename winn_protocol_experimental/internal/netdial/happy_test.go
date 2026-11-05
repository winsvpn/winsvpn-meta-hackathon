package netdial

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolverMap map[string][]netip.Addr

func (resolver resolverMap) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	addresses, ok := resolver[network+"|"+host]
	if !ok {
		addresses, ok = resolver["ip|"+host]
	}
	if !ok {
		return nil, errors.New("not found")
	}
	return addresses, nil
}

func TestResolvePrefersIPv6AndUsesHintsWithoutDuplicates(t *testing.T) {
	happy := HappyEyeballs{
		Resolver: resolverMap{"ip|gateway.example": {
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"),
		}},
		IPv6Hints: []netip.Addr{netip.MustParseAddr("2001:db8::20")},
		IPv4Hints: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}
	addresses, err := happy.Resolve(context.Background(), "gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("2001:db8::20"),
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("192.0.2.10"),
	}
	if len(addresses) != len(want) {
		t.Fatalf("addresses = %v", addresses)
	}
	for index := range want {
		if addresses[index] != want[index] {
			t.Fatalf("addresses = %v, want %v", addresses, want)
		}
	}
}

func TestIPv4LiteralGetsNAT64Candidate(t *testing.T) {
	happy := HappyEyeballs{
		Resolver: resolverMap{"ip6|ipv4only.arpa": {
			netip.MustParseAddr("64:ff9b::c000:00aa"),
			netip.MustParseAddr("64:ff9b::c000:00ab"),
		}},
	}
	addresses, err := happy.Resolve(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 ||
		addresses[0] != netip.MustParseAddr("64:ff9b::c633:6407") ||
		addresses[1] != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("NAT64 candidates = %v", addresses)
	}
}

func TestRaceStartsFallbackImmediatelyAfterFailure(t *testing.T) {
	candidates := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}
	started := make(chan netip.Addr, 2)
	begin := time.Now()
	value, err := race(
		context.Background(), candidates, time.Second,
		func(_ context.Context, address netip.Addr) (string, error) {
			started <- address
			if address.Is6() {
				return "", errors.New("IPv6 unavailable")
			}
			return "ipv4", nil
		},
		func(string) {},
	)
	if err != nil || value != "ipv4" {
		t.Fatalf("race = %q, %v", value, err)
	}
	if time.Since(begin) > 250*time.Millisecond {
		t.Fatalf("fallback waited despite immediate IPv6 failure: %v", time.Since(begin))
	}
	if first, second := <-started, <-started; first.Is4() || !second.Is4() {
		t.Fatalf("attempt order = %v, %v", first, second)
	}
}

func TestSynthesizeNAT64RejectsUnsupportedPrefix(t *testing.T) {
	if _, ok := SynthesizeNAT64(
		netip.MustParsePrefix("2001:db8:64::/64"),
		netip.MustParseAddr("192.0.2.1"),
	); ok {
		t.Fatal("unsupported /64 synthesis was accepted")
	}
}

func TestResolveRejectsEmptyHost(t *testing.T) {
	_, err := HappyEyeballs{}.Resolve(context.Background(), "")
	if err == nil {
		t.Fatal("empty host returned addresses")
	}
	if err.Error() != "host is required" {
		t.Fatalf("empty host error = %q", err)
	}
}

func TestIPv4LiteralKeepsIPv4WhenNAT64DiscoveryFails(t *testing.T) {
	happy := HappyEyeballs{Resolver: resolverMap{}}
	addresses, err := happy.Resolve(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("discovery-fail candidates = %v", addresses)
	}
}

func TestDisableNAT64LeavesIPv4LiteralAlone(t *testing.T) {
	happy := HappyEyeballs{
		DisableNAT64: true,
		NAT64Prefix:  netip.MustParsePrefix("64:ff9b::/96"),
	}
	addresses, err := happy.Resolve(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("DisableNAT64 candidates = %v", addresses)
	}
}

func TestExplicitNAT64PrefixDoesNotNeedDiscovery(t *testing.T) {
	happy := HappyEyeballs{
		Resolver:    resolverMap{},
		NAT64Prefix: netip.MustParsePrefix("64:ff9b::/96"),
	}
	addresses, err := happy.Resolve(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 ||
		addresses[0] != netip.MustParseAddr("64:ff9b::c633:6407") ||
		addresses[1] != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("explicit prefix candidates = %v", addresses)
	}
}

func TestHostnameIPv4IsNotSynthesizedToNAT64(t *testing.T) {
	happy := HappyEyeballs{
		Resolver: resolverMap{"ip|gateway.example": {
			netip.MustParseAddr("192.0.2.10"),
		}},
		NAT64Prefix: netip.MustParsePrefix("64:ff9b::/96"),
	}
	addresses, err := happy.Resolve(context.Background(), "gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("hostname NAT64 candidates = %v (synthesis should only apply to IPv4 literals)", addresses)
	}
}

func TestWrongFamilyHintsAreDroppedWithoutError(t *testing.T) {
	happy := HappyEyeballs{
		Resolver: resolverMap{"ip|gateway.example": {
			netip.MustParseAddr("2001:db8::10"),
		}},
		IPv6Hints: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		IPv4Hints: []netip.Addr{netip.MustParseAddr("2001:db8::20")},
	}
	addresses, err := happy.Resolve(context.Background(), "gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("2001:db8::10") {
		t.Fatalf("wrong-family hints were not dropped silently: %v", addresses)
	}
}

func TestResolverEmptyAnswerIsAnError(t *testing.T) {
	happy := HappyEyeballs{
		Resolver: resolverMap{"ip|gateway.example": {}},
	}
	_, err := happy.Resolve(context.Background(), "gateway.example")
	if err == nil {
		t.Fatal("empty resolver answer returned success")
	}
	if err.Error() != "resolver returned no usable IPv4 or IPv6 addresses" {
		t.Fatalf("empty resolver error = %q", err)
	}
}

func TestResolveAddressRejectsPortZeroAndOutOfRange(t *testing.T) {
	happy := HappyEyeballs{DisableNAT64: true}
	for _, address := range []string{"192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:abc"} {
		_, _, _, err := happy.resolveAddress(context.Background(), address)
		if err == nil {
			t.Fatalf("%s: invalid port was accepted", address)
		}
		if err.Error() != "invalid endpoint port" {
			t.Fatalf("%s: error = %q", address, err)
		}
	}
}

func TestRaceAllCandidatesFailJoinsErrors(t *testing.T) {
	candidates := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}
	_, err := race(
		context.Background(), candidates, time.Millisecond,
		func(_ context.Context, address netip.Addr) (string, error) {
			return "", errors.New(address.String() + " failed")
		},
		func(string) {},
	)
	if err == nil {
		t.Fatal("all-fail race returned success")
	}
	text := err.Error()
	if !strings.Contains(text, "2001:db8::1 failed") || !strings.Contains(text, "192.0.2.1 failed") {
		t.Fatalf("joined error missing a candidate: %q", text)
	}
}

func TestRaceRejectsEmptyCandidates(t *testing.T) {
	_, err := race(
		context.Background(), nil, time.Millisecond,
		func(context.Context, netip.Addr) (string, error) { return "", nil },
		func(string) {},
	)
	if err == nil {
		t.Fatal("empty candidate list returned success")
	}
}

func TestDialQUICRequiresConfigs(t *testing.T) {
	happy := HappyEyeballs{DisableNAT64: true}
	_, err := happy.DialQUIC(context.Background(), "192.0.2.1:443", nil, nil)
	if err == nil {
		t.Fatal("nil QUIC configs returned success")
	}
	if err.Error() != "QUIC TLS and transport configurations are required" {
		t.Fatalf("nil QUIC configs error = %q", err)
	}
	_, _, err = happy.DialQUICPath(context.Background(), "192.0.2.1:443", nil, nil)
	if err == nil {
		t.Fatal("nil QUIC path configs returned success")
	}
}

func TestDialContextConnectsOverLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- connection
	}()
	happy := HappyEyeballs{DisableNAT64: true, AttemptTimeout: 2 * time.Second}
	connection, err := happy.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case peer := <-accepted:
		defer peer.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not accept the dial")
	}
}

func TestDialContextRefusedIsNotSilent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	happy := HappyEyeballs{DisableNAT64: true, AttemptTimeout: 2 * time.Second}
	connection, err := happy.DialContext(context.Background(), "tcp", address)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("refused dial returned a connection")
	}
	if err == nil {
		t.Fatal("refused dial returned success")
	}
	text := err.Error()
	if !strings.Contains(text, "dial tcp via") || !strings.Contains(text, "127.0.0.1") {
		t.Fatalf("refused dial error does not name the attempt: %q", text)
	}
}

func TestDialContextInvalidPortIsNotSilent(t *testing.T) {
	_, err := HappyEyeballs{DisableNAT64: true}.DialContext(
		context.Background(), "tcp", "127.0.0.1:0",
	)
	if err == nil {
		t.Fatal("port 0 returned success")
	}
	if err.Error() != "invalid endpoint port" {
		t.Fatalf("port 0 error = %q", err)
	}
}

func TestRaceDoesNotDialWhenContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var dialed atomic.Int32
	_, err := race(
		ctx,
		[]netip.Addr{netip.MustParseAddr("192.0.2.1")},
		time.Second,
		func(context.Context, netip.Addr) (string, error) {
			dialed.Add(1)
			return "x", nil
		},
		func(string) {},
	)
	time.Sleep(50 * time.Millisecond)
	if err == nil {
		t.Fatal("cancelled context returned success")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("already-cancelled error = %v", err)
	}
	if n := dialed.Load(); n != 0 {
		t.Fatalf("already-cancelled context still dialed %d time(s)", n)
	}
}

func TestRaceDoesNotLeakWhenParentCancelsAfterResultIsQueued(t *testing.T) {
	t.Cleanup(func() {
		setRaceAfterResultSent(nil)
		setRaceBeforeWait(nil)
	})
	sawCancelPath := 0
	for i := 0; i < 40; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		closed := make(chan struct{}, 4)
		queued := make(chan struct{})
		setRaceAfterResultSent(func() {
			close(queued)
		})
		setRaceBeforeWait(func() {
			<-queued
			cancel()
		})
		value, err := race(
			ctx,
			[]netip.Addr{netip.MustParseAddr("192.0.2.1")},
			time.Hour,
			func(context.Context, netip.Addr) (io.Closer, error) {
				return nopCloser{}, nil
			},
			func(c io.Closer) {
				_ = c.Close()
				closed <- struct{}{}
			},
		)
		setRaceAfterResultSent(nil)
		setRaceBeforeWait(nil)
		if err == nil {
			if value == nil {
				cancel()
				t.Fatal("success with nil connection")
			}
			_ = value.Close()
			cancel()
			continue
		}
		sawCancelPath++
		select {
		case <-closed:
		case <-time.After(200 * time.Millisecond):
			cancel()
			t.Fatalf("iteration %d: parent cancel returned %v but the queued successful dial was neither returned nor closed", i, err)
		}
		cancel()
	}
	if sawCancelPath == 0 {
		t.Fatal("select never took ctx.Done; the leak path was not exercised")
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
