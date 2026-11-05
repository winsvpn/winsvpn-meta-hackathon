package decoy

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// tlsRecordHandshake is the first byte of any TLS ClientHello record.
const tlsRecordHandshake byte = 0x16

// The body returned for cleartext HTTP on the TLS port comes from the
// deployment's Origin, and used to be a package constant here.
//
// The constant was right about the first problem and wrong about the second.
// Go's net/http answers this case with "Client sent an HTTP request to an
// HTTPS server." - a string unique to the Go standard library, which narrows
// an endpoint to a Go server on one probe and costs the censor nothing. Every
// ordinary server answers with a 400 here, so answering with an ordinary 400
// was the fix, and it stays. No Server header is sent, because claiming to be
// software this endpoint is not would be a fingerprint in the other direction.
//
// What the constant missed is that a fixed 400 body is a fleet-wide identifier
// in its own right, obtainable by exactly the probe bulk scanners already
// perform - a cleartext GET at port 443 - and matched the same way: hash the
// body, ask the corpus who else returns it. Fixing the HTTPS cover site and
// leaving this constant would have sold the same list of gateways at the same
// price over a different request. So it is generated per deployment alongside
// the site, and the listener is given it.

// TLSOnlyListener classifies each accepted connection by its first byte and
// keeps non-TLS traffic away from net/http's TLS error path.
//
// Classification runs off the accept path so that a peer which connects and
// then says nothing cannot stall the listener. Connections whose first byte
// never arrives are passed through untouched, so their behaviour is exactly
// what it was before.
// origin supplies this deployment's 400 body. A nil origin is a programming
// error rather than a configuration one, so it is not refused - it falls back
// to a freshly seeded site, which is uncorrelated across deployments even
// though nothing else on that listener is.
func TLSOnlyListener(
	inner net.Listener, peekTimeout time.Duration, origin *Origin,
) net.Listener {
	if peekTimeout <= 0 {
		peekTimeout = 5 * time.Second
	}
	var badRequest []byte
	if origin != nil {
		badRequest = origin.PlaintextBadRequest()
	} else {
		seed, _ := deploymentSeed(nil)
		badRequest = newStaticOrigin(seed).plaintext
	}
	listener := &tlsOnlyListener{
		Listener:   inner,
		ready:      make(chan net.Conn),
		failed:     make(chan error, 1),
		done:       make(chan struct{}),
		timeout:    peekTimeout,
		badRequest: badRequest,
	}
	go listener.pump()
	return listener
}

type tlsOnlyListener struct {
	net.Listener
	ready      chan net.Conn
	failed     chan error
	done       chan struct{}
	closeOnce  sync.Once
	timeout    time.Duration
	badRequest []byte
}

func (l *tlsOnlyListener) pump() {
	// Mirror net/http.Server.Serve: a temporary accept error (EMFILE, ENFILE)
	// is retried with bounded backoff. Returning on it used to end this
	// goroutine for good, after which Accept blocked forever: net/http
	// retried the one surfaced error and then waited on a channel nobody fed,
	// so one exhausted descriptor table silently took the cover listener
	// down while the process kept running.
	var tempDelay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				select {
				case <-time.After(tempDelay):
					continue
				case <-l.done:
					return
				}
			}
			select {
			case l.failed <- err:
			default:
			}
			return
		}
		tempDelay = 0
		go l.classify(conn)
	}
}

func (l *tlsOnlyListener) classify(conn net.Conn) {
	deadline := time.Now().Add(l.timeout)
	_ = conn.SetReadDeadline(deadline)
	var first [1]byte
	n, err := conn.Read(first[:])
	// Clear the classification deadline; from here the connection behaves
	// exactly as it would have without this listener.
	_ = conn.SetReadDeadline(time.Time{})

	if n == 0 {
		if err != nil {
			// Never spoke, or went away. Hand it on unchanged so the timeout
			// and teardown behaviour is the server's, not ours.
			l.deliver(conn)
			return
		}
		l.deliver(conn)
		return
	}
	replayed := &prefixConn{Conn: conn, prefix: []byte{first[0]}}
	if first[0] == tlsRecordHandshake {
		l.deliver(replayed)
		return
	}
	// Cleartext on the TLS port. Answer the way an ordinary server does and
	// close; do not hand it to net/http, whose reply identifies the stack.
	_ = conn.SetWriteDeadline(time.Now().Add(l.timeout))
	_, _ = conn.Write(plaintextResponse(l.badRequest))
	_ = conn.Close()
}

func plaintextResponse(body []byte) []byte {
	// http.TimeFormat, not time.RFC1123. They differ in exactly one place and
	// it is the place that matters: RFC1123 renders the zone abbreviation, so
	// a UTC clock produced "... 18:49:01 UTC" where RFC 9110 requires "GMT".
	// Every ordinary server sends GMT, so sending UTC was a one-byte-pattern
	// discriminator sitting in the response whose whole job was to look
	// unremarkable.
	header := "HTTP/1.1 400 Bad Request\r\n" +
		"Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n"
	return append([]byte(header), body...)
}

func (l *tlsOnlyListener) deliver(conn net.Conn) {
	select {
	case l.ready <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *tlsOnlyListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case err := <-l.failed:
		// Keep the fatal error for every later Accept: the pump has stopped,
		// so a caller that retries must get the error again, not block.
		l.closeOnce.Do(func() { close(l.done) })
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *tlsOnlyListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	err := l.Listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// prefixConn replays bytes consumed during classification.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(buffer []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(buffer, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(buffer)
}
