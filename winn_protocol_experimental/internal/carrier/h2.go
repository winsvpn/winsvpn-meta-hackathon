package carrier

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const (
	H2Path      = "/winn/v2/udp-stream"
	H2MediaType = "application/vnd.winn.udp-stream;version=2"

	// h2CoverFallbackALPN is advertised alongside h2 so the ALPN list matches
	// what an ordinary browser sends over TCP. It is never negotiated: the
	// dialer's VerifyConnection requires http2.NextProtoTLS and fails closed
	// otherwise. Purely a fingerprinting measure, not a protocol fallback.
	h2CoverFallbackALPN = "http/1.1"
)

type H2Server struct {
	PublicTarget     string
	Backend          *net.UDPAddr
	Suite            tlsconfig.Suite
	RequestVerifier  *carrierauth.RequestVerifier
	ControllerSigner *pqauth.Signer
	ControllerID     string
	Metrics          *observability.Registry
	Audit            audit.Sink
	Limiter          ratelimit.Limiter
	Concurrency      chan struct{}
	MaxDatagram      int
	MaxOuterDatagram int
	Deduplicator     *SessionDeduplicator
	PrivacyTokens    *PrivacyTokenVerifier
	DialBackend      func(context.Context, *net.UDPAddr) (*net.UDPConn, error)
}

func NewH2Server(publicTarget, backend string, suite tlsconfig.Suite, verifier *carrierauth.RequestVerifier, controllerSigner *pqauth.Signer, controllerID string) (*H2Server, error) {
	if err := validateTarget(publicTarget); err != nil {
		return nil, fmt.Errorf("public H2 target: %w", err)
	}
	backendAddress, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		return nil, fmt.Errorf("resolve fixed AWG backend: %w", err)
	}
	if verifier == nil || controllerSigner == nil || controllerID == "" {
		return nil, errors.New("H2 carrier authentication is not configured")
	}
	deduplicator, err := NewSessionDeduplicator(defaultSessionLimit, defaultSequenceWindow)
	if err != nil {
		return nil, err
	}
	return &H2Server{
		PublicTarget:     publicTarget,
		Backend:          backendAddress,
		Suite:            suite,
		RequestVerifier:  verifier,
		ControllerSigner: controllerSigner,
		ControllerID:     controllerID,
		MaxDatagram:      DefaultMaxDatagram,
		MaxOuterDatagram: DefaultMaxDatagram + envelopeHeaderSize,
		Deduplicator:     deduplicator,
	}, nil
}

func (s *H2Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if s.Audit != nil && !s.Audit.Healthy() {
		s.rejectH2(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if s.Concurrency != nil {
		select {
		case s.Concurrency <- struct{}{}:
			defer func() { <-s.Concurrency }()
		default:
			s.rejectH2(writer, http.StatusServiceUnavailable, "carrier_capacity_rejected")
			return
		}
	}
	if request.URL.Path != H2Path || request.URL.RawQuery != "" {
		s.rejectH2(writer, http.StatusNotFound, "h2_not_found")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		s.rejectH2(writer, http.StatusMethodNotAllowed, "h2_method_rejected")
		return
	}
	if request.ProtoMajor != 2 {
		s.rejectH2(writer, http.StatusHTTPVersionNotSupported, "h2_protocol_required")
		return
	}
	if request.Header.Get("Content-Type") != H2MediaType ||
		request.Header.Get("Content-Encoding") != "" {
		s.rejectH2(writer, http.StatusUnsupportedMediaType, "h2_media_type_rejected")
		return
	}
	if err := tlsconfig.ValidateStateForALPN(request.TLS, s.Suite, http2.NextProtoTLS); err != nil {
		s.rejectH2(writer, http.StatusUpgradeRequired, "h2_tls_profile_rejected")
		return
	}
	claims, principal, err := authenticateCarrierRequest(
		request, string(mobility.HTTP2), s.PublicTarget,
		s.RequestVerifier, s.PrivacyTokens,
	)
	if err != nil {
		s.rejectH2(writer, http.StatusUnauthorized, "carrier_auth_rejected")
		return
	}
	// Record the cryptographic authentication boundary immediately after
	// single-use token redemption, exactly as the H3 carrier does. Every exit
	// below seals one mutually exclusive terminal class against this request's
	// correlation identity, so a request that fails after redemption cannot
	// vanish from the sealed audit trail.
	trace := newCarrierTrace(claims)
	if !s.recordH2(
		EventH2Authenticated,
		principal,
		trace.correlation,
		trace.detail(TerminalClassAuthenticated, AbortReasonNone),
	) {
		// The redemption is already durable but unrecorded; the conservation
		// equation must invalidate the run rather than let it pass unseen.
		s.rejectH2(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if s.Limiter != nil {
		if allowed, retry := s.Limiter.Allow(principal + "|" + carrierRemoteHost(request.RemoteAddr)); !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
			s.abortAuthenticatedH2(
				writer, trace, principal,
				http.StatusTooManyRequests, AbortReasonRateLimited,
			)
			return
		}
	}
	backend, err := s.dialH2Backend(request.Context())
	if err != nil {
		s.abortAuthenticatedH2(
			writer, trace, principal,
			http.StatusBadGateway, AbortReasonBackendUnavailable,
		)
		return
	}
	defer backend.Close()
	maxDatagram := s.MaxDatagram
	if maxDatagram <= 0 {
		maxDatagram = DefaultMaxDatagram
	}
	maxDatagram = min(maxDatagram, claims.MaxDatagram)
	maxOuter := s.MaxOuterDatagram
	if maxOuter <= 0 {
		maxOuter = maxDatagram + envelopeHeaderSize
	}
	if maxOuter < maxDatagram+envelopeHeaderSize ||
		maxOuter > AbsoluteMaxCarrierEnvelope {
		s.abortAuthenticatedH2(
			writer, trace, principal,
			http.StatusInternalServerError, AbortReasonInvalidCarrierMTU,
		)
		return
	}
	responseClaims, err := carrierauth.NewResponseClaimsWithMaximum(
		http.StatusOK,
		string(mobility.HTTP2),
		s.ControllerID,
		s.Suite.Name,
		claims,
		s.ControllerSigner,
		time.Now().UTC(),
		maxDatagram,
	)
	if err != nil {
		s.abortAuthenticatedH2(
			writer, trace, principal,
			http.StatusInternalServerError, AbortReasonResponseAuthFailed,
		)
		return
	}
	if err := carrierauth.SignResponse(writer.Header(), responseClaims, s.ControllerSigner); err != nil {
		s.abortAuthenticatedH2(
			writer, trace, principal,
			http.StatusInternalServerError, AbortReasonResponseAuthFailed,
		)
		return
	}
	if !s.sealTerminalH2(
		trace, principal, EventH2Open, TerminalClassOpen, AbortReasonNone,
	) {
		s.abortAuthenticatedH2(
			writer, trace, principal,
			http.StatusServiceUnavailable, AbortReasonAuditUnavailable,
		)
		return
	}
	writer.Header().Set("Content-Type", H2MediaType)
	writer.WriteHeader(http.StatusOK)
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
	s.incH2("h2_authenticated")

	framedWriter := &synchronizedFrameWriter{writer: writer}
	var sequence atomic.Uint64
	results := make(chan error, 2)
	go func() {
		results <- h2EnvelopesToUDP(
			request.Body, framedWriter, backend,
			claims.SessionID+"|"+claims.SequenceEpoch,
			maxDatagram, maxOuter, s.Deduplicator,
		)
	}()
	go func() {
		results <- udpToH2Envelopes(
			framedWriter, backend, maxDatagram, maxOuter, &sequence,
			claims.Privacy == carrierauth.PrivacyHighRisk,
		)
	}()
	first := <-results
	_ = backend.Close()
	second := <-results
	if unexpectedRelayError(first) || unexpectedRelayError(second) {
		s.incH2("h2_proxy_error")
	}
	s.recordH2(
		EventH2Closed,
		principal,
		trace.correlation,
		trace.detail(TerminalClassClosed, AbortReasonNone),
	)
}

func (s *H2Server) dialH2Backend(ctx context.Context) (*net.UDPConn, error) {
	if s.DialBackend != nil {
		return s.DialBackend(ctx, s.Backend)
	}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "udp", s.Backend.String())
	if err != nil {
		return nil, err
	}
	udpConnection, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("fixed backend dial did not return UDP")
	}
	return udpConnection, nil
}

func (s *H2Server) rejectH2(writer http.ResponseWriter, status int, event string) {
	s.incH2(event)
	http.Error(writer, http.StatusText(status), status)
}

// abortAuthenticatedH2 is the only rejection path permitted after a durable
// token redemption on the H2 carrier. See H3Server.abortAuthenticated.
func (s *H2Server) abortAuthenticatedH2(
	writer http.ResponseWriter,
	trace *carrierTrace,
	principal string,
	status int,
	reason string,
) {
	if !ValidAbortReason(reason) {
		s.incH2("carrier_abort_reason_unknown")
	}
	s.sealTerminalH2(
		trace, principal, EventH2Aborted, TerminalClassAborted, reason,
	)
	s.rejectH2(writer, status, reason)
}

// sealTerminalH2 records one mutually exclusive terminal class for an
// authenticated H2 request. See H3Server.sealTerminal.
func (s *H2Server) sealTerminalH2(
	trace *carrierTrace,
	principal string,
	event string,
	class string,
	reason string,
) bool {
	if trace.terminalized() {
		s.incH2("carrier_terminal_duplicate")
		return false
	}
	if !s.recordH2(
		event, principal, trace.correlation, trace.detail(class, reason),
	) {
		s.incH2("carrier_terminal_unrecorded")
		return false
	}
	trace.markTerminal()
	return true
}

func (s *H2Server) incH2(event string) {
	if s.Metrics != nil {
		s.Metrics.Inc(event)
	}
}

// recordH2 appends one carrier audit record. correlationID is the per-request
// correlation identity minted at the redemption boundary; the session identity
// travels inside detail. See H3Server.record.
func (s *H2Server) recordH2(event, deviceID, correlationID, detail string) bool {
	if s.Audit == nil {
		return true
	}
	if err := s.Audit.Record(event, deviceID, correlationID, detail); err != nil {
		s.incH2("audit_write_failed")
		return false
	}
	return true
}

type H2Dialer struct {
	URL              string
	PublicTarget     string
	DeviceID         string
	SessionID        string
	Suite            tlsconfig.Suite
	TLSConfig        *tls.Config
	DeviceSigner     *pqauth.Signer
	ResponseVerifier *carrierauth.ResponseVerifier
	DialContext      func(context.Context, string, string) (net.Conn, error)

	// TransportConn is a caller-supplied, already-protected, already-connected
	// plaintext TCP connection. When it is set the dialer hands that connection
	// to net/http instead of letting it dial, and TLS is negotiated on top of
	// it as usual. See supplied_socket.go. Set it with UseSuppliedSocket.
	//
	// Leaving it nil preserves the original behaviour exactly.
	TransportConn *SuppliedStreamSocket

	MaxDatagram      int
	MaxOuterDatagram int
	// DisableLengthPadding leaks inner datagram lengths one-to-one. See
	// EnvelopeConfig.DisableLengthPadding: the zero value pads.
	DisableLengthPadding bool
	ManifestDigest       string
	AuthorizationMode    string
	PrivacyToken         *privacytoken.Token
	SequenceEpoch        string
	AnonymousCredentials AnonymousCredentialSource
}

func NewH2Dialer(serverURL, publicTarget, deviceID, sessionID string, suite tlsconfig.Suite, tlsConfig *tls.Config, deviceSigner *pqauth.Signer, responseVerifier *carrierauth.ResponseVerifier) (*H2Dialer, error) {
	request, err := http.NewRequest(http.MethodPost, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("parse H2 carrier URL: %w", err)
	}
	if request.URL.Scheme != "https" || request.URL.Host == "" ||
		request.URL.Path != H2Path || request.URL.RawQuery != "" {
		return nil, fmt.Errorf("H2 carrier URL must be an absolute HTTPS %s URL without query", H2Path)
	}
	if err := validateTarget(publicTarget); err != nil {
		return nil, err
	}
	if tlsConfig == nil || deviceSigner == nil || responseVerifier == nil ||
		deviceID == "" || !mobility.ValidSessionID(sessionID) {
		return nil, errors.New("H2 carrier client authentication is not configured")
	}
	configuration := tlsConfig.Clone()
	// ALPN is sent in the clear in the outer ClientHello even under ECH, so the
	// offer itself is a fingerprint. Every browser dialing TCP advertises h2 and
	// http/1.1 together; advertising h2 alone is a single-protocol list no
	// ordinary client sends.
	//
	// Offering http/1.1 does NOT make it reachable. The VerifyConnection
	// installed immediately below calls ValidatePeerProfile with
	// http2.NextProtoTLS and fails closed on anything else, so a server that
	// selects http/1.1 gets the connection torn down at the same handshake
	// position as before. The offer widened; the requirement did not.
	configuration.NextProtos = []string{http2.NextProtoTLS, h2CoverFallbackALPN}
	previousVerify := configuration.VerifyConnection
	configuration.VerifyConnection = func(state tls.ConnectionState) error {
		if previousVerify != nil {
			if err := previousVerify(state); err != nil {
				return err
			}
		}
		return tlsconfig.ValidatePeerProfile(&state, suite, http2.NextProtoTLS)
	}
	return &H2Dialer{
		URL:               serverURL,
		PublicTarget:      publicTarget,
		DeviceID:          deviceID,
		SessionID:         sessionID,
		Suite:             suite,
		TLSConfig:         configuration,
		DeviceSigner:      deviceSigner,
		ResponseVerifier:  responseVerifier,
		MaxDatagram:       DefaultMaxDatagram,
		MaxOuterDatagram:  DefaultMaxDatagram + envelopeHeaderSize,
		ManifestDigest:    carrierauth.LabManifestDigest,
		AuthorizationMode: carrierauth.AuthModeIdentity,
		SequenceEpoch:     sessionID,
	}, nil
}

// defaultStreamDialContext is the ONE place this package opens a TCP
// connection for itself. net/http would happily do it with its own private
// dialer if DialContext were left nil, which would make "the carrier opened its
// own socket" unobservable. Naming it keeps that path to a single interceptable
// call, so a test can prove the caller-supplied-socket path never reaches it.
//
// The timeouts mirror http.DefaultTransport's dialer, so behaviour on the
// dial-it-yourself path is unchanged. Production never replaces this.
var defaultStreamDialContext = func(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, address)
}

// UseSuppliedSocket builds this dialer around a caller-supplied, connected,
// plaintext TCP connection instead of one it dials itself. The dialer takes
// ownership: the carrier returned by Dial closes it.
//
// The connection must NOT already be TLS: the carrier negotiates TLS 1.3 with
// the configured suite and ALPN over it, and hands nothing to net/http that has
// skipped that check.
func (d *H2Dialer) UseSuppliedSocket(conn net.Conn) error {
	if d == nil {
		return errors.New("H2 dialer is nil")
	}
	if d.DialContext != nil {
		return ErrSuppliedSocketConflict
	}
	supplied, err := NewSuppliedStreamSocket(conn)
	if err != nil {
		return err
	}
	d.TransportConn = supplied
	return nil
}

// SuppliedSocketKind reports that HTTP/2 rides a TCP connection.
func (d *H2Dialer) SuppliedSocketKind() SocketKind { return SocketKindStream }

func (d *H2Dialer) envelopeConfig(maxInner, maxOuter int) EnvelopeConfig {
	return carrierEnvelopeConfig(maxInner, maxOuter, d.DisableLengthPadding)
}

// HasSuppliedSocket reports whether a caller-supplied connection is installed.
func (d *H2Dialer) HasSuppliedSocket() bool {
	return d != nil && d.TransportConn != nil
}

// transportDialContext resolves which underlay net/http may use. It never
// returns nil, so http.Transport can never fall back to its own private dialer.
func (d *H2Dialer) transportDialContext() (
	func(context.Context, string, string) (net.Conn, error),
	error,
) {
	if d.TransportConn == nil {
		if d.DialContext != nil {
			return d.DialContext, nil
		}
		return defaultStreamDialContext, nil
	}
	if d.DialContext != nil {
		return nil, ErrSuppliedSocketConflict
	}
	supplied := d.TransportConn
	// One-shot. http.Transport re-dials on a dropped connection; with a
	// supplied socket the second attempt must fail closed rather than open an
	// unprotected replacement.
	return func(_ context.Context, network, address string) (net.Conn, error) {
		return supplied.take(network, address)
	}, nil
}

func (d *H2Dialer) Dial(ctx context.Context) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("dial context is required")
	}
	dialContext, err := d.transportDialContext()
	if err != nil {
		return nil, err
	}
	deviceID, signer, token, destroyCredential, err :=
		resolveClientCredential(
			d.AuthorizationMode, d.DeviceID, d.DeviceSigner,
			d.PrivacyToken, d.AnonymousCredentials,
		)
	if err != nil {
		return nil, err
	}
	defer destroyCredential()
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", H2MediaType)
	request.Header.Set("Accept", H2MediaType)
	claims, err := carrierauth.NewRequestClaimsWithOptions(
		request,
		string(mobility.HTTP2),
		d.PublicTarget,
		deviceID,
		d.SessionID,
		d.Suite.Name,
		signer,
		time.Now().UTC(),
		carrierauth.RequestOptions{
			AuthorizationMode: d.AuthorizationMode,
			ManifestDigest:    d.ManifestDigest,
			MaxInnerDatagram:  d.MaxDatagram,
			PrivacyProfile: func() string {
				if d.DisableLengthPadding {
					return carrierauth.PrivacyStandard
				}
				return carrierauth.PrivacyHighRisk
			}(),
			SequenceEpoch: d.SequenceEpoch,
		},
	)
	if err != nil {
		_ = writer.CloseWithError(err)
		return nil, err
	}
	if err := carrierauth.SignRequest(request.Header, claims, signer); err != nil {
		_ = writer.CloseWithError(err)
		return nil, err
	}
	if err := addPrivacyTokenHeader(
		request.Header, d.AuthorizationMode, token,
	); err != nil {
		_ = writer.CloseWithError(err)
		return nil, err
	}
	destroyCredential()
	transport := &http.Transport{
		TLSClientConfig:    d.TLSConfig,
		DialContext:        dialContext,
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		MaxConnsPerHost:    1,
		IdleConnTimeout:    30 * time.Second,
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		_ = writer.CloseWithError(err)
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("dial authenticated HTTP/2 carrier: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("H2 carrier returned status %d", response.StatusCode)
	}
	if response.ProtoMajor != 2 || response.TLS == nil {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, errors.New("H2 carrier did not negotiate authenticated HTTP/2")
	}
	if err := tlsconfig.ValidateStateForALPN(response.TLS, d.Suite, http2.NextProtoTLS); err != nil {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	if response.Header.Get("Content-Type") != H2MediaType {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, errors.New("H2 carrier response media type mismatch")
	}
	responseClaims, err := d.ResponseVerifier.Verify(response, claims, string(mobility.HTTP2))
	if err != nil {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("verify H2 carrier response: %w", err)
	}
	maxDatagram := min(d.MaxDatagram, responseClaims.MaxDatagram)
	if maxDatagram <= 0 {
		maxDatagram = DefaultMaxDatagram
	}
	if maxDatagram > AbsoluteMaxDatagram {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, errors.New("carrier datagram limit exceeds 1500 bytes")
	}
	maxOuter := d.MaxOuterDatagram
	if maxOuter <= 0 {
		maxOuter = maxDatagram + envelopeHeaderSize
	}
	rawConnection := &h2PacketConn{
		writer:      writer,
		reader:      response.Body,
		transport:   transport,
		local:       fixedAddr("h2-client"),
		remote:      fixedAddr(request.URL.Host),
		maxDatagram: maxOuter,
	}
	connection, err := newEnvelopePacketConn(
		rawConnection, d.envelopeConfig(maxDatagram, maxOuter),
	)
	if err != nil {
		_ = rawConnection.Close()
		return nil, err
	}
	// The HTTP/2 carrier still exchanges one full-size envelope here, and still
	// fails closed if it is not acknowledged. Both halves of that need saying,
	// because the HTTP/3 carrier now does neither.
	//
	// Why it still exchanges one: TCP has no path MTU to discover and no
	// handshake-derived datagram size to read, so nothing about this carrier
	// proves the tunnel is wired end to end at full size until something
	// traverses it. The datagram limit is negotiated in the controller-signed
	// response above, but a signed number is a claim about intent, not evidence
	// that the request-body pipe, the server's relay loop, and the response
	// body are all live.
	//
	// Why it still aborts: the inner AWG interface MTU is controller-signed and
	// fixed for the session, so there is no smaller MTU to degrade to. Carrying
	// on with a lower carrier MTU would accept every readiness packet and then
	// reject ordinary AWG datagrams once the user's traffic started, which is a
	// worse failure and a later one. The coordinator's answer to a carrier that
	// cannot carry the signed size is to use the other carrier, not to shrink.
	//
	// What changed is the shape of the failure. It is one datagram and then a
	// closed HTTP/2 request, not a burst of same-size datagrams on a retry
	// schedule -- see ProbeMTU. Over a reliable ordered stream the retries
	// could not have delivered anything TCP had not already delivered; all they
	// did was let a censor induce a distinctive pattern by dropping one size
	// class.
	probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := connection.ProbeMTU(probeContext); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

type h2PacketConn struct {
	writer      *io.PipeWriter
	reader      io.ReadCloser
	transport   *http.Transport
	local       net.Addr
	remote      net.Addr
	maxDatagram int

	readMu  sync.Mutex
	writeMu sync.Mutex
	closeMu sync.Mutex
	timer   *time.Timer
	closed  atomic.Bool
	expired atomic.Bool

	deadlineGeneration       uint64
	deadlineCallbackStarted  func()
	deadlineCallbackFinished func()
}

func (c *h2PacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, nil, c.closedError()
	}
	count, err := readFrameInto(c.reader, buffer, c.maxDatagram)
	if err != nil {
		return 0, nil, c.translateError(err)
	}
	return count, c.remote, nil
}

func (c *h2PacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, c.closedError()
	}
	if len(packet) > c.maxDatagram {
		return 0, ErrDatagramTooLarge
	}
	if err := writeFrame(c.writer, packet, c.maxDatagram); err != nil {
		return 0, c.translateError(err)
	}
	return len(packet), nil
}

func (c *h2PacketConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	c.deadlineGeneration++
	return c.closeLocked(false)
}

func (c *h2PacketConn) closeLocked(expired bool) error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	if expired {
		c.expired.Store(true)
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	writerError := c.writer.Close()
	readerError := c.reader.Close()
	c.transport.CloseIdleConnections()
	return errors.Join(writerError, readerError)
}

func (c *h2PacketConn) LocalAddr() net.Addr  { return c.local }
func (c *h2PacketConn) RemoteAddr() net.Addr { return c.remote }

func (c *h2PacketConn) SetDeadline(deadline time.Time) error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed.Load() {
		return c.closedError()
	}
	c.deadlineGeneration++
	generation := c.deadlineGeneration
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if deadline.IsZero() {
		return nil
	}
	if !deadline.After(time.Now()) {
		_ = c.closeLocked(true)
		return nil
	}
	c.timer = time.AfterFunc(time.Until(deadline), func() {
		if c.deadlineCallbackStarted != nil {
			c.deadlineCallbackStarted()
		}
		if c.deadlineCallbackFinished != nil {
			defer c.deadlineCallbackFinished()
		}
		c.expireDeadline(generation)
	})
	return nil
}

func (c *h2PacketConn) expireDeadline(generation uint64) {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed.Load() || c.deadlineGeneration != generation {
		return
	}
	c.timer = nil
	_ = c.closeLocked(true)
}

func (c *h2PacketConn) SetReadDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

func (c *h2PacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

func (c *h2PacketConn) closedError() error {
	if c.expired.Load() {
		return os.ErrDeadlineExceeded
	}
	return net.ErrClosed
}

func (c *h2PacketConn) translateError(err error) error {
	if c.expired.Load() {
		return os.ErrDeadlineExceeded
	}
	return err
}

func readFrame(reader io.Reader, maxDatagram int) ([]byte, error) {
	packet := make([]byte, maxDatagram)
	count, err := readFrameInto(reader, packet, maxDatagram)
	if err != nil {
		clear(packet)
		return nil, err
	}
	return packet[:count], nil
}

func readFrameInto(reader io.Reader, buffer []byte, maxDatagram int) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 || length > maxDatagram {
		return 0, errors.New("invalid H2 carrier datagram length")
	}
	toRead := min(length, len(buffer))
	if _, err := io.ReadFull(reader, buffer[:toRead]); err != nil {
		return 0, err
	}
	if remaining := length - toRead; remaining > 0 {
		if _, err := io.CopyN(io.Discard, reader, int64(remaining)); err != nil {
			return 0, err
		}
	}
	return toRead, nil
}

func writeFrame(writer io.Writer, packet []byte, maxDatagram int) error {
	if len(packet) == 0 || len(packet) > maxDatagram || len(packet) > int(^uint16(0)) {
		return ErrDatagramTooLarge
	}
	var header [2]byte
	// #nosec G115 -- the preceding bound rejects lengths above uint16.
	binary.BigEndian.PutUint16(header[:], uint16(len(packet)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := writer.Write(packet)
	return err
}

func unexpectedRelayError(err error) bool {
	return err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, net.ErrClosed)
}
