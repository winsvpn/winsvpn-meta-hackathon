// Package netdial provides Winn's IPv6/IPv4 racing and IPv4-literal NAT64
// synthesis. Hostname resolution remains under the operating system resolver
// so DNS64-provided AAAA records are used naturally.
package netdial

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const DefaultFallbackDelay = 250 * time.Millisecond

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type HappyEyeballs struct {
	Resolver       Resolver
	FallbackDelay  time.Duration
	IPv4Hints      []netip.Addr
	IPv6Hints      []netip.Addr
	NAT64Prefix    netip.Prefix
	DisableNAT64   bool
	AttemptTimeout time.Duration
}

func (h HappyEyeballs) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, candidates, err := h.resolveAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	timeout := h.AttemptTimeout
	return race(ctx, candidates, h.delay(), func(attempt context.Context, candidate netip.Addr) (net.Conn, error) {
		attemptContext := attempt
		var cancel context.CancelFunc
		if timeout > 0 {
			attemptContext, cancel = context.WithTimeout(attempt, timeout)
			defer cancel()
		}
		candidateNetwork := network
		switch network {
		case "tcp":
			if candidate.Is4() {
				candidateNetwork = "tcp4"
			} else {
				candidateNetwork = "tcp6"
			}
		case "udp":
			if candidate.Is4() {
				candidateNetwork = "udp4"
			} else {
				candidateNetwork = "udp6"
			}
		}
		connection, dialErr := dialer.DialContext(
			attemptContext, candidateNetwork,
			net.JoinHostPort(candidate.String(), strconv.Itoa(port)),
		)
		if dialErr != nil {
			return nil, fmt.Errorf("dial %s via %s for %s: %w", network, candidate, host, dialErr)
		}
		return connection, nil
	}, func(connection net.Conn) {
		_ = connection.Close()
	})
}

func (h HappyEyeballs) DialQUIC(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	if tlsConfig == nil || quicConfig == nil {
		return nil, errors.New("QUIC TLS and transport configurations are required")
	}
	host, port, candidates, err := h.resolveAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	timeout := h.AttemptTimeout
	return race(ctx, candidates, h.delay(), func(attempt context.Context, candidate netip.Addr) (*quic.Conn, error) {
		attemptContext := attempt
		var cancel context.CancelFunc
		if timeout > 0 {
			attemptContext, cancel = context.WithTimeout(attempt, timeout)
			defer cancel()
		}
		configuration := tlsConfig.Clone()
		if configuration.ServerName == "" {
			configuration.ServerName = host
		}
		connection, dialErr := quic.DialAddr(
			attemptContext,
			net.JoinHostPort(candidate.String(), strconv.Itoa(port)),
			configuration,
			quicConfig.Clone(),
		)
		if dialErr != nil {
			return nil, fmt.Errorf("dial QUIC via %s for %s: %w", candidate, host, dialErr)
		}
		return connection, nil
	}, func(connection *quic.Conn) {
		_ = connection.CloseWithError(0, "Happy Eyeballs alternate path won")
	})
}

type quicPath struct {
	connection *quic.Conn
	transport  *quic.Transport
}

// DialQUICPath is the migration-capable Happy Eyeballs variant. It uses an
// explicit QUIC transport with non-zero connection IDs and returns transport
// ownership to the caller.
func (h HappyEyeballs) DialQUICPath(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, *quic.Transport, error) {
	if tlsConfig == nil || quicConfig == nil {
		return nil, nil, errors.New("QUIC TLS and transport configurations are required")
	}
	host, port, candidates, err := h.resolveAddress(ctx, address)
	if err != nil {
		return nil, nil, err
	}
	timeout := h.AttemptTimeout
	selected, err := race(ctx, candidates, h.delay(), func(attempt context.Context, candidate netip.Addr) (quicPath, error) {
		attemptContext := attempt
		var cancel context.CancelFunc
		if timeout > 0 {
			attemptContext, cancel = context.WithTimeout(attempt, timeout)
			defer cancel()
		}
		network := "udp4"
		local := net.IPv4zero
		if candidate.Is6() {
			network = "udp6"
			local = net.IPv6unspecified
		}
		socket, listenErr := listenHappyUDP(network, local)
		if listenErr != nil {
			return quicPath{}, listenErr
		}
		transport := &quic.Transport{
			Conn:               socket,
			ConnectionIDLength: 8,
		}
		configuration := tlsConfig.Clone()
		if configuration.ServerName == "" {
			configuration.ServerName = host
		}
		remote := &net.UDPAddr{
			IP: candidate.AsSlice(), Port: port,
		}
		connection, dialErr := transport.Dial(
			attemptContext, remote, configuration, quicConfig.Clone(),
		)
		if dialErr != nil {
			_ = transport.Close()
			_ = socket.Close()
			return quicPath{}, fmt.Errorf("dial QUIC via %s for %s: %w", candidate, host, dialErr)
		}
		return quicPath{connection: connection, transport: transport}, nil
	}, func(path quicPath) {
		_ = path.connection.CloseWithError(0, "Happy Eyeballs alternate path won")
		_ = path.transport.Close()
		if path.transport.Conn != nil {
			_ = path.transport.Conn.Close()
		}
	})
	if err != nil {
		return nil, nil, err
	}
	return selected.connection, selected.transport, nil
}

func (h HappyEyeballs) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, errors.New("host is required")
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		result := []netip.Addr{literal.Unmap()}
		if literal.Is4() && !h.DisableNAT64 {
			prefix := h.NAT64Prefix
			if !prefix.IsValid() {
				prefix, _ = h.discoverNAT64(ctx)
			}
			if synthesized, ok := SynthesizeNAT64(prefix, literal); ok {
				result = append([]netip.Addr{synthesized}, result...)
			}
		}
		return uniqueAddresses(result), nil
	}
	resolver := h.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	resolved, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	candidates := make([]netip.Addr, 0, len(h.IPv6Hints)+len(h.IPv4Hints)+len(resolved))
	candidates = append(candidates, validHints(h.IPv6Hints, false)...)
	for _, address := range resolved {
		if address.Is6() && !address.Is4In6() {
			candidates = append(candidates, address)
		}
	}
	candidates = append(candidates, validHints(h.IPv4Hints, true)...)
	for _, address := range resolved {
		if address.Is4() || address.Is4In6() {
			candidates = append(candidates, address.Unmap())
		}
	}
	candidates = uniqueAddresses(candidates)
	if len(candidates) == 0 {
		return nil, errors.New("resolver returned no usable IPv4 or IPv6 addresses")
	}
	return candidates, nil
}

func (h HappyEyeballs) resolveAddress(ctx context.Context, address string) (string, int, []netip.Addr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, nil, errors.New("invalid endpoint port")
	}
	candidates, err := h.Resolve(ctx, host)
	return host, port, candidates, err
}

func (h HappyEyeballs) discoverNAT64(ctx context.Context) (netip.Prefix, error) {
	resolver := h.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, address := range addresses {
		if !address.Is6() || address.Is4In6() {
			continue
		}
		bytes := address.As16()
		suffix := [4]byte{bytes[12], bytes[13], bytes[14], bytes[15]}
		if suffix == [4]byte{192, 0, 0, 170} || suffix == [4]byte{192, 0, 0, 171} {
			for index := 12; index < 16; index++ {
				bytes[index] = 0
			}
			return netip.PrefixFrom(netip.AddrFrom16(bytes), 96).Masked(), nil
		}
	}
	return netip.Prefix{}, errors.New("no /96 NAT64 prefix discovered")
}

// SynthesizeNAT64 supports the widely deployed /96 RFC 6052 form. Hostnames
// on other prefix lengths remain supported through DNS64 resolver answers.
func SynthesizeNAT64(prefix netip.Prefix, ipv4 netip.Addr) (netip.Addr, bool) {
	if !prefix.IsValid() || prefix.Bits() != 96 || !ipv4.Is4() {
		return netip.Addr{}, false
	}
	result := prefix.Masked().Addr().As16()
	address := ipv4.As4()
	copy(result[12:], address[:])
	return netip.AddrFrom16(result), true
}

func (h HappyEyeballs) delay() time.Duration {
	if h.FallbackDelay <= 0 {
		return DefaultFallbackDelay
	}
	return h.FallbackDelay
}

type dialResult[T any] struct {
	value T
	err   error
}

// raceAfterResultSent runs after a dial result is queued on the race
// channel. Production leaves it nil.
var (
	raceHooksMu sync.RWMutex
	raceAfterResultSent func()
	raceBeforeWait  func()
)

// setRaceAfterResultSent swaps the hook under the lock.
func setRaceAfterResultSent(f func()) {
	raceHooksMu.Lock()
	defer raceHooksMu.Unlock()
	raceAfterResultSent = f
}

// setRaceBeforeWait swaps the hook under the lock.
func setRaceBeforeWait(f func()) {
	raceHooksMu.Lock()
	defer raceHooksMu.Unlock()
	raceBeforeWait = f
}

func race[T any](
	ctx context.Context,
	candidates []netip.Addr,
	delay time.Duration,
	dial func(context.Context, netip.Addr) (T, error),
	closeLoser func(T),
) (T, error) {
	var zero T
	if ctx == nil || len(candidates) == 0 || dial == nil || closeLoser == nil {
		return zero, errors.New("happy Eyeballs race is not configured")
	}
	if err := ctx.Err(); err != nil {
		return zero, context.Cause(ctx)
	}
	raceContext, cancel := context.WithCancel(ctx)
	results := make(chan dialResult[T], len(candidates))
	start := func(candidate netip.Addr) {
		go func() {
			value, err := dial(raceContext, candidate)
			if err == nil && raceContext.Err() != nil {
				closeLoser(value)
				err = context.Cause(raceContext)
			}
			results <- dialResult[T]{value: value, err: err}
			raceHooksMu.RLock()
			hook := raceAfterResultSent
			raceHooksMu.RUnlock()
			if hook != nil {
				hook()
			}
		}()
	}
	started := 1
	completed := 0
	start(candidates[0])
	timer := time.NewTimer(delay)
	defer timer.Stop()
	raceHooksMu.RLock()
	beforeWait := raceBeforeWait
	raceHooksMu.RUnlock()
	if beforeWait != nil {
		beforeWait()
	}
	var failures []error
	for {
		select {
		case <-ctx.Done():
			cancel()
			drainRaceResults(started-completed, results, closeLoser)
			return zero, context.Cause(ctx)
		case result := <-results:
			completed++
			if result.err == nil {
				cancel()
				drainRaceResults(started-completed, results, closeLoser)
				return result.value, nil
			}
			failures = append(failures, result.err)
			if started < len(candidates) {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				start(candidates[started])
				started++
				timer.Reset(delay)
			} else if completed == started {
				cancel()
				return zero, errors.Join(failures...)
			}
		case <-timer.C:
			if started < len(candidates) {
				start(candidates[started])
				started++
				timer.Reset(delay)
			}
		}
	}
}

func drainRaceResults[T any](remaining int, results <-chan dialResult[T], closeLoser func(T)) {
	if remaining <= 0 {
		return
	}
	go func() {
		for range remaining {
			loser := <-results
			if loser.err == nil {
				closeLoser(loser.value)
			}
		}
	}()
}

func validHints(hints []netip.Addr, wantIPv4 bool) []netip.Addr {
	result := make([]netip.Addr, 0, len(hints))
	for _, address := range hints {
		address = address.Unmap()
		if address.IsValid() && address.Is4() == wantIPv4 {
			result = append(result, address)
		}
	}
	return result
}

func uniqueAddresses(addresses []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return slices.Clip(result)
}
