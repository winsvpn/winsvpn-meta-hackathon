// Package connlimit bounds connections before anything has authenticated.
//
// The carrier's token-bucket limiter is keyed on principal|IP and therefore
// cannot run until ML-DSA verification has already succeeded. Everything
// before that point - the TCP accept, the TLS handshake, the certificate
// exchange - is unmetered, so a single unauthenticated source can park
// thousands of connections at no cost. This package supplies the missing
// pre-authentication bound: a total concurrency cap and a per-source-IP cap,
// both applied at Accept, before a single handshake byte is read.
//
// It is deliberately not a rate limiter. Counting concurrent connections needs
// no history and no per-peer state beyond the live set, so it cannot itself be
// turned into a memory-exhaustion lever.
package connlimit

import (
	"errors"
	"net"
	"sync"
)

// Options bounds a listener.
type Options struct {
	// MaxTotal is the ceiling on concurrent accepted connections. Zero
	// disables the total cap.
	MaxTotal int

	// MaxPerIP is the ceiling on concurrent connections from any one source
	// address. Zero disables the per-source cap.
	MaxPerIP int

	// OnRejected, if set, is called each time a connection is dropped for
	// exceeding MaxPerIP. It receives no peer address: recording who was
	// rejected would recreate the enumeration artifact the operational log
	// was just fixed to avoid.
	OnRejected func()
}

// Listen wraps a listener with pre-handshake connection bounds.
func Listen(inner net.Listener, options Options) (net.Listener, error) {
	if inner == nil {
		return nil, errors.New("listener is required")
	}
	if options.MaxTotal < 0 || options.MaxPerIP < 0 {
		return nil, errors.New("connection limits must not be negative")
	}
	if options.MaxTotal == 0 && options.MaxPerIP == 0 {
		return inner, nil
	}
	limited := &listener{
		Listener: inner,
		perIP:    make(map[string]int),
		options:  options,
		closed:   make(chan struct{}),
	}
	if options.MaxTotal > 0 {
		limited.total = make(chan struct{}, options.MaxTotal)
	}
	return limited, nil
}

type listener struct {
	net.Listener
	options Options

	total chan struct{}

	mu    sync.Mutex
	perIP map[string]int

	closed    chan struct{}
	closeOnce sync.Once
}

// Close unblocks Accept even when every MaxTotal slot is occupied. Without
// this, Accept waits on a channel send that inner Close cannot wake.
func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return l.Listener.Close()
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		// Acquire the total slot first, so that at capacity the accept loop
		// simply stops taking work rather than accepting and dropping.
		if l.total != nil {
			select {
			case l.total <- struct{}{}:
			case <-l.closed:
				return nil, net.ErrClosed
			}
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			l.releaseTotal()
			return nil, err
		}
		host := sourceHost(conn.RemoteAddr())
		if !l.acquireIP(host) {
			// Over the per-source ceiling. Close immediately and without a
			// reply; an ordinary server under load does the same, and any
			// distinguishable refusal would be a signal of its own.
			_ = conn.Close()
			l.releaseTotal()
			if l.options.OnRejected != nil {
				l.options.OnRejected()
			}
			continue
		}
		return &countedConn{Conn: conn, listener: l, host: host}, nil
	}
}

func (l *listener) acquireIP(host string) bool {
	if l.options.MaxPerIP <= 0 || host == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP[host] >= l.options.MaxPerIP {
		return false
	}
	l.perIP[host]++
	return true
}

func (l *listener) releaseIP(host string) {
	if l.options.MaxPerIP <= 0 || host == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if remaining := l.perIP[host] - 1; remaining > 0 {
		l.perIP[host] = remaining
	} else {
		// Drop the key entirely so the map tracks only live connections.
		delete(l.perIP, host)
	}
}

func (l *listener) releaseTotal() {
	if l.total == nil {
		return
	}
	select {
	case <-l.total:
	default:
	}
}

func sourceHost(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	return host
}

// countedConn returns its slots exactly once, whoever closes it.
type countedConn struct {
	net.Conn
	listener *listener
	host     string
	once     sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.listener.releaseIP(c.host)
		c.listener.releaseTotal()
	})
	return err
}
