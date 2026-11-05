// Package reality closes the gap between "answers every prober convincingly"
// and "presents nothing a prober can catch."
//
// internal/coverlisten and internal/decoy already give an unauthenticated
// peer a real, ACME-issued certificate (never the Winn leaf) and a real
// website's content (when -decoy-origin is set). That defeats naive
// probing - no self-signed certificate, no obviously-synthetic TLS
// fingerprint. It does not defeat a prober that inspects what is actually
// behind the certificate: the certificate and the website are both this
// deployment's own, procured specifically to be cover, for a domain that
// exists for no other reason. A censor correlating registration data,
// hosting patterns, or simply "does this site have any of the traffic,
// backlinks or search presence a domain this certificate's age would have"
// can, in principle, tell a purpose-built cover apart from an ordinary
// site that happens to run a VPN carrier behind it too.
//
// The V2Ray/Xray ecosystem's answer to that - VLESS + Vision + REALITY - is
// the precedent named in internal/decoy's and internal/tlsconfig's own doc
// comments as one of the designs Winn's cover profile "converges on." REALITY
// goes one step further than a cover certificate: an unauthenticated peer is
// not given any certificate this deployment holds a private key for. It is
// transparently relayed, at the raw byte level, to a real, independent third
// party's TLS server, and receives that party's own genuine, unmodified
// handshake and certificate. There is no forged certificate anywhere in the
// system for a prober to catch, because no certificate belonging to this
// deployment is ever on that wire.
//
// # What this package does and does not change
//
// A connection that presents the Winn profile - the exact ECH-inner-SNI
// classification internal/coverlisten's own GetConfigForClient already
// performs, reused here verbatim rather than reimplemented - is completely
// unaffected: same bytes, same certificate, same mTLS/ML-DSA/carrierauth
// enforcement, same latency budget. This package adds behaviour only for
// connections that do not, which today receive Options.Cover's own
// certificate. Reality relaying does not touch, weaken, or duplicate any of
// Winn's authentication: mTLS client certificates, ML-DSA controller
// signing, carrierauth's replay/rate/revocation checks, and ECH all remain
// exactly as internal/carrierauth, internal/pqauth and internal/echconfig
// already implement them. The relay path is deliberately zero-crypto: it is
// a raw TCP byte pump, because the entire point is that the peer's own
// ClientHello reaches the real target unmodified and the real target's own
// response returns unmodified.
//
// # Scope: the TCP/H2 carrier listener only
//
// This package wraps a net.Listener, which is a TCP abstraction. It does not
// cover the HTTP/3 (QUIC/UDP) carrier listener. quic-go/http3.Server owns
// the UDP socket and completes the QUIC handshake, including TLS, before any
// connection object becomes observable to this process, and QUIC's
// connection-ID, retry-token and address-validation machinery would have to
// be reimplemented, not just relayed, to give an unauthenticated QUIC peer a
// live third party's genuine handshake. That is a materially larger project
// than this package and is not attempted here. cmd/winn-carrier-server's H3
// listener keeps internal/coverlisten's and internal/decoy's existing
// behaviour unconditionally, regardless of whether this package is wired up
// for H2. See docs/handoff for the dated design note this is implemented
// against, which states this boundary as a known limitation rather than
// something silently unhandled.
//
// # Relationship to connectivity.CarrierRealityXHTTP
//
// internal/connectivity defines a Carrier value named CarrierRealityXHTTP
// ("reality-xhttp"). That is an unrelated, unimplemented CLIENT-side
// transport shape: internal/carrier/supplied_socket.go and datapath/doc.go
// both say explicitly that it "has no dialer in internal/carrier at all and
// stays refused." This package does not implement, wire up, or advance that
// carrier type in any way. An authenticated Winn client continues to use
// exactly the H2 or H3 carrier it uses today; only what an unauthenticated
// connection to the existing H2 listener receives changes.
//
// # Why this is an operator decision, not a default
//
// Relaying to a real third party's server means that server receives, and
// answers, connections it did not agree to receive and was never asked
// about. There is no agreement being breached - nothing was promised - but
// silently picking a well-known site on the operator's behalf would make
// that choice this package's rather than a deliberate, informed one, which
// is precisely the property the REALITY design in the wider ecosystem treats
// as a real, documented point of controversy rather than a free lunch. So
// Options.Target has no default: Listen refuses to build a listener for an
// empty target, and cmd/winn-carrier-server's -reality-relay-target flag
// defaults to empty and states the tradeoff in its own help text. See that
// flag's help text and docs/handoff for the fuller discussion.
package reality

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// defaultHandshakeTimeout bounds how long a connection has to either
	// present the Winn profile or be recognised as not doing so. It matches
	// this deployment's other pre-application read bounds: decoy's
	// TLSOnlyListener peek timeout and net/http's own ReadHeaderTimeout in
	// cmd/winn-carrier-server, both 8s. A genuine handshake - one round trip
	// - finishes in a small fraction of this even on a slow mobile network;
	// this bound exists for a peer that sends a partial ClientHello and then
	// goes quiet, not for a peer behaving normally.
	defaultHandshakeTimeout = 8 * time.Second

	// defaultDialTimeout bounds both Target.Validate's startup dial and every
	// runtime relay dial to Target.Address.
	defaultDialTimeout = 8 * time.Second

	// maxCapturedPrefix bounds how much of a not-yet-classified connection's
	// input this package retains for possible replay to a relay target. A
	// TLS 1.3 ClientHello, even a padded one, is a small fraction of this;
	// the bound exists so a peer cannot force unbounded memory use during
	// classification. If it is ever reached, further bytes are read (so the
	// connection is not stalled) but not retained, which would truncate a
	// relay in the - not currently reachable - case of an oversized
	// ClientHello; see shimConn.Read.
	maxCapturedPrefix = 64 << 10
)

// Outcome values passed to Options.OnOutcome. There is deliberately no value
// for "presented the Winn profile": that path is unchanged from today and is
// not this package's event to report, so as not to give an operator a metric
// that looks like it measures something new when it does not.
const (
	// OutcomeRelayed is reported once a relayed connection's byte pump to
	// Options.Target has finished (in either direction, for any reason -
	// this reports that a relay was attempted and ran, not how it ended).
	OutcomeRelayed = "relayed"

	// OutcomeRelayFailed is reported when a connection was classified as not
	// presenting the Winn profile but dialing Options.Target itself failed
	// (the target became unreachable after startup validation succeeded).
	// The peer's connection is closed; nothing falls back to Options.Cover's
	// certificate or to any other locally-held identity.
	OutcomeRelayFailed = "relay_failed"
)

// errNotWinnClient is returned from the classification GetConfigForClient
// wrapper whenever internal/coverlisten's own decision would, today, fall
// back to serving Options.Cover's certificate. Returning an error here -
// instead of nil, nil, which is what would make crypto/tls actually serve
// that certificate - aborts the local handshake before crypto/tls
// constructs a ServerHello, which is what makes relaying instead possible:
// nothing has reached the peer yet for this connection to relay `over`.
var errNotWinnClient = errors.New(
	"reality: connection did not present the Winn profile",
)

// Target names the operator-chosen real third party a connection that does
// not present the Winn profile is relayed to.
//
// Constructing a non-empty Target is a deliberate operator choice - see the
// package doc - and Validate is how that choice is checked before anything
// depends on it: it requires a real, live, WebPKI-verifiable TLS server,
// because the entire property this package exists to provide is that there
// is nothing for a prober to catch, which is not true of a target this
// process cannot itself verify.
type Target struct {
	// Address is the "host:port" TCP address of a real, independent TLS
	// server. It is never dialed with TLS verification disabled: Validate
	// and every runtime relay both expect an ordinary, publicly-trusted
	// certificate to be waiting on the other end, exactly as an ordinary TLS
	// client would.
	Address string

	// DialTimeout bounds both Validate's dial and every runtime relay dial.
	// Zero uses a default (8s).
	DialTimeout time.Duration

	// RootCAs overrides the system trust store Validate verifies Address's
	// certificate against. Production callers must leave this nil - a
	// relay target's whole purpose is to be verifiable by an ordinary
	// client's ordinary trust store, and overriding it would validate
	// something other than what a real prober will themselves check. It
	// exists so tests can point Validate at a fixture server signed by a
	// test-only CA without either reaching the real internet or disabling
	// verification - RootCAs is still a real, checked trust anchor, just not
	// the system one.
	RootCAs *x509.CertPool
}

func (target Target) dialTimeout() time.Duration {
	if target.DialTimeout > 0 {
		return target.DialTimeout
	}
	return defaultDialTimeout
}

// Validate dials Address for real and requires a real, WebPKI-style
// verified TLS handshake - exactly what an ordinary TLS client, including a
// censor's probing tool, will itself require - before returning success.
//
// It is meant to be called once, at startup, with its caller refusing to
// start the whole process on any error - matching every other
// misconfiguration gate in cmd/winn-carrier-server. A target that is
// unreachable, that is not speaking TLS, or that presents a certificate this
// process cannot verify must never be discovered at the moment a real prober
// connects; it must stop the server from starting at all.
func (target Target) Validate(ctx context.Context) error {
	address := strings.TrimSpace(target.Address)
	if address == "" {
		return errors.New("reality: target address is required")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("reality: target address %q: %w", address, err)
	}
	if host == "" {
		return fmt.Errorf("reality: target address %q has no host", address)
	}
	dialCtx, cancel := context.WithTimeout(ctx, target.dialTimeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: target.dialTimeout()}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return fmt.Errorf(
			"reality: dial target %q: %w - a REALITY relay target must be a "+
				"live, reachable TLS server; see -reality-relay-target's help "+
				"text before retrying",
			address, err,
		)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		RootCAs:    target.RootCAs,
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(target.dialTimeout()))
	}
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf(
			"reality: target %q did not complete a verifiable TLS handshake: "+
				"%w - a REALITY relay target must present a real, "+
				"publicly-trusted certificate for its own name, because the "+
				"whole point of this feature is that there is nothing for a "+
				"prober to catch, which is not true of a target this process "+
				"cannot itself verify",
			address, err,
		)
	}
	if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		return fmt.Errorf(
			"reality: target %q completed a handshake but presented no "+
				"certificate", address,
		)
	}
	return nil
}

// Options configures Listen.
type Options struct {
	// Cover is the *tls.Config internal/coverlisten.Apply already built and
	// internal/coverlisten.Verify already checked for this listener - the
	// configuration an unauthenticated peer reaches today. Required. Listen
	// reads its GetConfigForClient and its ECH keys; it never modifies Cover
	// itself.
	Cover *tls.Config

	// Target is where a connection that does not present the Winn profile is
	// relayed. Required: Listen refuses to build a listener for an empty
	// Target; the caller (cmd/winn-carrier-server) is expected not to call
	// Listen at all when the operator has not configured a target, so that
	// "the feature is off" and "Listen was never called" are the same state
	// and today's behaviour is unchanged in the only way that is actually
	// convincing - by not running different code.
	Target Target

	// HandshakeTimeout bounds the classification attempt. Zero uses a
	// default (8s).
	HandshakeTimeout time.Duration

	// Logf receives operator notices and warnings. Nil discards them.
	Logf func(format string, args ...any)

	// OnOutcome, if set, is called once per connection that is relayed, with
	// a coarse outcome (OutcomeRelayed or OutcomeRelayFailed) and nothing
	// else - never an address, never anything derived from the peer,
	// matching every other metrics hook in this tree (decoy.Guard.OnDiverted,
	// knock.GateConfig.OnKnockAccepted/OnKnockRejected). It is not called
	// for a connection that presents the Winn profile.
	OnOutcome func(outcome string)
}

// Listen wraps inner so that a connection which does not present the Winn
// profile - internal/coverlisten's own classification, reused unmodified -
// is transparently relayed to Options.Target instead of being handed
// Options.Cover's own certificate.
//
// A connection that does present the Winn profile is unaffected in every
// observable way. Accept only ever returns such connections, and only once
// they have already completed a real handshake; net/http's own later
// HandshakeContext call on them is Go's documented no-op for an
// already-complete handshake. A connection that is relayed is never returned
// from Accept - net/http has no use for one, since it is not carrying
// HTTP/2 or HTTP/1.1 at all once relayed - it is driven to completion
// inside this package on its own goroutine, and Accept simply continues to
// the next inbound connection.
func Listen(inner net.Listener, options Options) (net.Listener, error) {
	if inner == nil {
		return nil, errors.New("reality: inner listener is required")
	}
	if options.Cover == nil {
		return nil, errors.New("reality: cover TLS configuration is required")
	}
	if strings.TrimSpace(options.Target.Address) == "" {
		return nil, errors.New(
			"reality: a target is required; Listen must not be called when " +
				"the operator has not configured -reality-relay-target",
		)
	}
	logf := options.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	onOutcome := options.OnOutcome
	if onOutcome == nil {
		onOutcome = func(string) {}
	}
	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	logf(
		"NOTICE: REALITY-style probe relay is ENABLED on this listener. Any "+
			"connection that does not present the Winn profile will be "+
			"transparently relayed to %s and will see that party's own real "+
			"TLS handshake and certificate, never this deployment's. This "+
			"does not apply to the HTTP/3 (QUIC/UDP) listener, which keeps "+
			"serving the configured cover certificate as before.",
		options.Target.Address,
	)
	built := &listener{
		inner:            inner,
		cover:            options.Cover,
		target:           options.Target,
		handshakeTimeout: handshakeTimeout,
		logf:             logf,
		onOutcome:        onOutcome,
		ready:            make(chan net.Conn),
		failed:           make(chan error, 1),
		done:             make(chan struct{}),
	}
	go built.pump()
	return built, nil
}

type listener struct {
	inner            net.Listener
	cover            *tls.Config
	target           Target
	handshakeTimeout time.Duration
	logf             func(string, ...any)
	onOutcome        func(string)

	ready     chan net.Conn
	failed    chan error
	done      chan struct{}
	closeOnce sync.Once
}

// pump accepts continuously and classifies each connection on its own
// goroutine, so one slow or adversarial peer can never delay another
// connection's classification or relay. This mirrors
// internal/decoy.tlsOnlyListener's pump, which solves the identical problem
// for the classification step immediately below this one in the same
// listener chain.
func (l *listener) pump() {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			select {
			case l.failed <- err:
			default:
			}
			return
		}
		go l.handle(conn)
	}
}

// handle classifies one connection and either delivers it (Winn profile) or
// relays it (everything else). It never returns a relayed connection to
// Accept.
func (l *listener) handle(raw net.Conn) {
	shim := newShimConn(raw)
	classifyConfig := classificationConfig(l.cover, shim)
	_ = raw.SetDeadline(time.Now().Add(l.handshakeTimeout))
	tlsConn := tls.Server(shim, classifyConfig)
	err := tlsConn.HandshakeContext(context.Background())
	// Clear the classification deadline either way. On the Winn path, from
	// here the connection behaves exactly as it would have without this
	// listener - the same pattern internal/decoy.tlsOnlyListener.classify
	// uses for its own peek deadline. On the relay path, the relay imposes
	// no deadline of its own; see the package doc's resource-bound note.
	_ = raw.SetDeadline(time.Time{})
	if err == nil {
		l.deliver(tlsConn)
		return
	}
	if shim.committed() {
		// The Winn profile was selected and its ServerHello (and now an
		// alert) already reached the peer, so there is nothing left to
		// relay "under": splicing this stream onto the third party would
		// only hand that party a dead Winn handshake. Close it, exactly as
		// the listener would without this package.
		_ = raw.Close()
		return
	}
	prefix := shim.capturedPrefix()
	if relayErr := l.relay(raw, prefix); relayErr != nil {
		l.onOutcome(OutcomeRelayFailed)
	} else {
		l.onOutcome(OutcomeRelayed)
	}
}

// relay dials Target fresh, replays the bytes already read from client
// during classification, and then splices the two connections until either
// side is done. client is always closed by the time relay returns.
func (l *listener) relay(client net.Conn, prefix []byte) error {
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), l.target.dialTimeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: l.target.dialTimeout()}
	upstream, err := dialer.DialContext(ctx, "tcp", l.target.Address)
	if err != nil {
		return fmt.Errorf("reality: dial relay target: %w", err)
	}
	defer upstream.Close()
	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			return fmt.Errorf("reality: replay captured prefix to relay target: %w", err)
		}
	}
	// Once the dial succeeded the relay ran; how the byte pump ended is not a
	// relay failure (OutcomeRelayFailed means the target could not be
	// reached). With the inbound wrappers this listener sits on, the first
	// direction to finish fully closes the client, so the other direction
	// routinely ends in a closed-connection error.
	_ = pipe(client, upstream)
	return nil
}

func (l *listener) deliver(conn net.Conn) {
	select {
	case l.ready <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case err := <-l.failed:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	err := l.inner.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (l *listener) Addr() net.Addr {
	return l.inner.Addr()
}

// classificationConfig builds the *tls.Config Listen actually hands to
// crypto/tls for the classification attempt. It reuses cover's own
// GetConfigForClient - internal/coverlisten's decision, byte for byte,
// never reimplemented - and changes exactly one thing about it: where that
// decision would today return nil, nil (crypto/tls's documented signal to
// fall back to cover's own certificate), this instead returns
// errNotWinnClient, which aborts the handshake before crypto/tls
// constructs a ServerHello. shim is told the moment the real decision is
// "yes" - synchronously, inside this callback, before crypto/tls proceeds -
// so a genuine Winn connection's ServerHello is written the instant it
// otherwise would be, not delayed by any of this.
func classificationConfig(cover *tls.Config, shim *shimConn) *tls.Config {
	wrapped := cover.Clone()
	original := cover.GetConfigForClient
	wrapped.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if original == nil {
			// No way for any peer to reach the Winn profile at all (see
			// tlsconfig.ApplyCoverProfile's early return for when this
			// happens). Every connection is then, correctly, "not Winn".
			return nil, errNotWinnClient
		}
		selected, err := original(hello)
		if err != nil {
			return nil, err
		}
		if selected == nil {
			return nil, errNotWinnClient
		}
		shim.commitLive()
		return selected, nil
	}
	return wrapped
}

// pipe splices a and b bidirectionally until both directions have finished,
// and returns the first non-nil error either direction produced (nil if
// both ended cleanly). Each direction half-closes its destination when its
// source is exhausted, so one side finishing does not immediately truncate
// data the other side still has in flight, wherever the underlying
// connection supports half-close.
func pipe(a, b net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan error, 2)
	copyDirection := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		_ = closeWrite(dst)
		results <- err
	}
	go copyDirection(b, a)
	go copyDirection(a, b)
	wg.Wait()
	close(results)
	var first error
	for err := range results {
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

type halfCloser interface {
	CloseWrite() error
}

// closeWrite half-closes conn's write side when the concrete type supports
// it (a real *net.TCPConn, which the relay target side always is) and falls
// back to a full close otherwise - some of this listener's own inbound
// wrapping layers (internal/decoy, internal/connlimit, internal/knock) embed
// net.Conn as an interface field, which does not promote CloseWrite even
// when the value underneath has it, so the client-facing side of the pipe
// degrades to a full close on the first direction to finish. That is a
// minor loss of proxy politeness on traffic that, by construction, only
// ever reaches a peer who has not proven they are a Winn client - not a
// correctness or security issue - and is not specific to this package.
func closeWrite(conn net.Conn) error {
	if closer, ok := conn.(halfCloser); ok {
		return closer.CloseWrite()
	}
	return conn.Close()
}

// shimConn sits between a freshly accepted connection and the classification
// attempt in listener.handle. While classification is undecided (live is
// false), every byte read is retained, bounded by maxCapturedPrefix, so it
// can be replayed to a relay target, and every byte written is held back
// rather than reaching the peer, so that if the connection turns out not to
// be a genuine Winn client the peer has received nothing from this process
// at all - a live relay to the real target can then proceed as though this
// process had never touched the connection. commitLive ends that: from the
// moment it is called, shimConn behaves as a completely ordinary net.Conn.
type shimConn struct {
	net.Conn

	mu       sync.Mutex
	live     bool
	writeBuf bytes.Buffer
	readBuf  bytes.Buffer
}

func newShimConn(inner net.Conn) *shimConn {
	return &shimConn{Conn: inner}
}

func (s *shimConn) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if n > 0 {
		s.mu.Lock()
		if !s.live && s.readBuf.Len() < maxCapturedPrefix {
			room := maxCapturedPrefix - s.readBuf.Len()
			captured := n
			if captured > room {
				captured = room
			}
			s.readBuf.Write(p[:captured])
		}
		s.mu.Unlock()
	}
	return n, err
}

func (s *shimConn) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.live {
		s.mu.Unlock()
		return s.Conn.Write(p)
	}
	// bytes.Buffer.Write's own contract: it always returns len(p), nil.
	n, _ := s.writeBuf.Write(p)
	s.mu.Unlock()
	return n, nil
}

// commitLive flushes anything buffered - in practice nothing, since the
// classifier commits before crypto/tls ever constructs a ServerHello - and
// switches to live passthrough. Safe to call more than once; only the first
// call has an effect.
func (s *shimConn) commitLive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live {
		return
	}
	s.live = true
	if s.writeBuf.Len() > 0 {
		_, _ = s.Conn.Write(s.writeBuf.Bytes())
		s.writeBuf.Reset()
	}
	s.readBuf.Reset()
}

// committed reports whether commitLive ran, i.e. the connection was
// classified as presenting the Winn profile.
func (s *shimConn) committed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live
}

// capturedPrefix returns every byte read so far. Meaningful only when
// commitLive was never called for this connection - once it has been,
// classification is over and the buffer has already been cleared.
func (s *shimConn) capturedPrefix() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.readBuf.Bytes()...)
}
