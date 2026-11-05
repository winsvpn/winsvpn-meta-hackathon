package carrier

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/masque"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

type H3Server struct {
	Template         *uritemplate.Template
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
	DialBackend      func(context.Context, *net.UDPAddr) (*net.UDPConn, error)
	MaxDatagram      int
	MaxOuterDatagram int
	Deduplicator     *SessionDeduplicator
	PrivacyTokens    *PrivacyTokenVerifier
}

func NewH3Server(template, publicTarget, backend string, suite tlsconfig.Suite, verifier *carrierauth.RequestVerifier, controllerSigner *pqauth.Signer, controllerID string) (*H3Server, error) {
	parsedTemplate, err := uritemplate.New(template)
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE URI template: %w", err)
	}
	if err := validateTemplate(parsedTemplate); err != nil {
		return nil, err
	}
	if err := validateTarget(publicTarget); err != nil {
		return nil, fmt.Errorf("public MASQUE target: %w", err)
	}
	backendAddress, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		return nil, fmt.Errorf("resolve fixed AWG backend: %w", err)
	}
	if verifier == nil || controllerSigner == nil || controllerID == "" {
		return nil, errors.New("H3 carrier authentication is not configured")
	}
	deduplicator, err := NewSessionDeduplicator(defaultSessionLimit, defaultSequenceWindow)
	if err != nil {
		return nil, err
	}
	return &H3Server{
		Template:         parsedTemplate,
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

func (s *H3Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if s.Audit != nil && !s.Audit.Healthy() {
		s.reject(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if s.Concurrency != nil {
		select {
		case s.Concurrency <- struct{}{}:
			defer func() { <-s.Concurrency }()
		default:
			s.reject(writer, http.StatusServiceUnavailable, "carrier_capacity_rejected")
			return
		}
	}
	if request.ProtoMajor != 3 {
		s.reject(writer, http.StatusHTTPVersionNotSupported, "h3_protocol_required")
		return
	}
	if err := tlsconfig.ValidateStateForALPN(request.TLS, s.Suite, http3.NextProtoH3); err != nil {
		s.reject(writer, http.StatusUpgradeRequired, "h3_tls_profile_rejected")
		return
	}
	proxyRequest, err := masque.ParseProxyRequest(request, s.Template)
	if err != nil {
		var parseError *masque.ProxyRequestParseError
		if errors.As(err, &parseError) {
			s.reject(writer, parseError.HTTPStatus, "invalid_connect_udp")
		} else {
			s.reject(writer, http.StatusBadRequest, "invalid_connect_udp")
		}
		return
	}
	if proxyRequest.Target != s.PublicTarget {
		s.reject(writer, http.StatusForbidden, "fixed_target_required")
		return
	}
	claims, principal, err := authenticateCarrierRequest(
		request, string(mobility.HTTP3), s.PublicTarget,
		s.RequestVerifier, s.PrivacyTokens,
	)
	if err != nil {
		s.reject(writer, http.StatusUnauthorized, "carrier_auth_rejected")
		return
	}
	// Record the cryptographic authentication boundary immediately after
	// single-use token redemption. Later capacity, rate, backend, or response
	// failures must not make a durable redemption disappear from the audit
	// denominator: from here to the end of the handler every exit seals exactly
	// one terminal class against this request's correlation identity.
	trace := newCarrierTrace(claims)
	if !s.record(
		EventH3Authenticated,
		principal,
		trace.correlation,
		trace.detail(TerminalClassAuthenticated, AbortReasonNone),
	) {
		// The redemption is already durable but the sealed trail cannot account
		// for it. Nothing here can repair that; the conservation equation must
		// invalidate the run rather than let an unrecorded redemption pass.
		s.reject(writer, http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if s.Limiter != nil {
		if allowed, retry := s.Limiter.Allow(principal + "|" + carrierRemoteHost(request.RemoteAddr)); !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
			s.abortAuthenticated(
				writer, trace, principal,
				http.StatusTooManyRequests, AbortReasonRateLimited,
			)
			return
		}
	}
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
		s.abortAuthenticated(
			writer, trace, principal,
			http.StatusInternalServerError, AbortReasonInvalidCarrierMTU,
		)
		return
	}
	if claims.Purpose == carrierauth.PurposeAuthenticateOnly {
		responseClaims, responseErr := carrierauth.NewResponseClaimsWithMaximum(
			http.StatusOK,
			string(mobility.HTTP3),
			s.ControllerID,
			s.Suite.Name,
			claims,
			s.ControllerSigner,
			time.Now().UTC(),
			maxDatagram,
		)
		if responseErr != nil {
			s.abortAuthenticated(
				writer, trace, principal,
				http.StatusInternalServerError, AbortReasonResponseAuthFailed,
			)
			return
		}
		if responseErr = carrierauth.SignResponse(
			writer.Header(), responseClaims, s.ControllerSigner,
		); responseErr != nil {
			s.abortAuthenticated(
				writer, trace, principal,
				http.StatusInternalServerError, AbortReasonResponseAuthFailed,
			)
			return
		}
		writer.Header().Set(http3.CapsuleProtocolHeader, "?1")
		if !s.sealTerminal(
			trace, principal, EventH3AuthOnly,
			TerminalClassAuthOnly, AbortReasonNone,
		) {
			s.abortAuthenticated(
				writer, trace, principal,
				http.StatusServiceUnavailable, AbortReasonAuditUnavailable,
			)
			return
		}
		s.inc("h3_authenticated_only")
		writer.WriteHeader(http.StatusOK)
		return
	}
	connection, err := s.dialBackend(request.Context())
	if err != nil {
		s.abortAuthenticated(
			writer, trace, principal,
			http.StatusBadGateway, AbortReasonBackendUnavailable,
		)
		return
	}
	responseClaims, err := carrierauth.NewResponseClaimsWithMaximum(
		http.StatusOK,
		string(mobility.HTTP3),
		s.ControllerID,
		s.Suite.Name,
		claims,
		s.ControllerSigner,
		time.Now().UTC(),
		maxDatagram,
	)
	if err != nil {
		_ = connection.Close()
		s.abortAuthenticated(
			writer, trace, principal,
			http.StatusInternalServerError, AbortReasonResponseAuthFailed,
		)
		return
	}
	if err := carrierauth.SignResponse(writer.Header(), responseClaims, s.ControllerSigner); err != nil {
		_ = connection.Close()
		s.abortAuthenticated(
			writer, trace, principal,
			http.StatusInternalServerError, AbortReasonResponseAuthFailed,
		)
		return
	}
	if !s.sealTerminal(
		trace, principal, EventH3Open, TerminalClassOpen, AbortReasonNone,
	) {
		_ = connection.Close()
		s.abortAuthenticated(
			writer, trace, principal,
			http.StatusServiceUnavailable, AbortReasonAuditUnavailable,
		)
		return
	}
	s.inc("h3_authenticated")
	if err := proxyH3Envelopes(
		writer, connection, claims, maxDatagram, maxOuter, s.Deduplicator,
	); !normalH3RelayClosure(err) {
		s.inc("h3_proxy_error")
		log.Printf("Winn HTTP/3 carrier relay failed: %v", err)
	}
	s.record(
		EventH3Closed,
		principal,
		trace.correlation,
		trace.detail(TerminalClassClosed, AbortReasonNone),
	)
}

func normalH3RelayClosure(err error) bool {
	if err == nil ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) {
		return true
	}
	var streamError *quic.StreamError
	return errors.As(err, &streamError) &&
		streamError.ErrorCode ==
			quic.StreamErrorCode(http3.ErrCodeNoError)
}

func (s *H3Server) Close() error {
	return nil
}

func (s *H3Server) dialBackend(ctx context.Context) (*net.UDPConn, error) {
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

func (s *H3Server) reject(writer http.ResponseWriter, status int, event string) {
	s.inc(event)
	http.Error(writer, http.StatusText(status), status)
}

// abortAuthenticated is the only rejection path permitted after a durable
// token redemption. It seals the post-authentication abort terminal class
// before answering the peer, so a request that fails after redemption still
// reaches exactly one terminal class in the sealed trail.
//
// The metric name is unchanged from the pre-conservation code: the abort
// reason enum reuses the metric identifiers the same paths already emitted, so
// the sealed trail and the metrics registry cannot disagree about why a
// request ended.
func (s *H3Server) abortAuthenticated(
	writer http.ResponseWriter,
	trace *carrierTrace,
	principal string,
	status int,
	reason string,
) {
	if !ValidAbortReason(reason) {
		// Never rewrite an unrecognised reason into a known one. The unknown
		// value has to reach the sealed evidence so the verifier fails closed
		// on it instead of accepting a class it cannot interpret.
		s.inc("carrier_abort_reason_unknown")
	}
	s.sealTerminal(trace, principal, EventH3Aborted, TerminalClassAborted, reason)
	s.reject(writer, status, reason)
}

// sealTerminal records one mutually exclusive terminal class for an
// authenticated request. The trace is marked only after the record is durable,
// so a rejected write leaves the request free to seal its real terminal class
// rather than silently consuming it.
func (s *H3Server) sealTerminal(
	trace *carrierTrace,
	principal string,
	event string,
	class string,
	reason string,
) bool {
	if trace.terminalized() {
		s.inc("carrier_terminal_duplicate")
		return false
	}
	if !s.record(event, principal, trace.correlation, trace.detail(class, reason)) {
		// The denominator now has no terminal class. The equation
		// authenticated == auth_only + open + aborted fails at verification,
		// which is the intended outcome for an evidence sink that stopped
		// accepting records mid-run.
		s.inc("carrier_terminal_unrecorded")
		return false
	}
	trace.markTerminal()
	return true
}

func (s *H3Server) inc(event string) {
	if s.Metrics != nil {
		s.Metrics.Inc(event)
	}
}

// record appends one carrier audit record. correlationID is the per-request
// correlation identity minted at the redemption boundary, not the session
// identity: the session identity is stable across several requests and cannot
// separate two redemptions, so it is carried inside detail instead.
func (s *H3Server) record(event, deviceID, correlationID, detail string) bool {
	if s.Audit == nil {
		return true
	}
	if err := s.Audit.Record(event, deviceID, correlationID, detail); err != nil {
		s.inc("audit_write_failed")
		return false
	}
	return true
}

type H3Dialer struct {
	Template         *uritemplate.Template
	PublicTarget     string
	DeviceID         string
	SessionID        string
	Suite            tlsconfig.Suite
	TLSConfig        *tls.Config
	DeviceSigner     *pqauth.Signer
	ResponseVerifier *carrierauth.ResponseVerifier
	QUICConfig       *quic.Config
	DialQUIC         func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	DialQUICPath     func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, *quic.Transport, error)

	// TransportSocket is a caller-supplied, already-protected UDP socket. When
	// it is set the dialer builds its QUIC transport around that socket and
	// never opens one of its own; see supplied_socket.go for why the ordering
	// matters on Android. Set it with UseSuppliedSocket rather than by hand.
	//
	// Leaving it nil preserves the original behaviour exactly: the dialer opens
	// its own socket, which is correct on desktop, Linux and Apple.
	TransportSocket *SuppliedPacketSocket

	MaxDatagram      int
	MaxOuterDatagram int
	// DisableLengthPadding leaks inner datagram lengths one-to-one. See
	// EnvelopeConfig.DisableLengthPadding: the zero value pads, so a host that
	// builds this dialer and says nothing about padding still gets the defence.
	DisableLengthPadding bool
	ManifestDigest       string
	AuthorizationMode    string
	PrivacyToken         *privacytoken.Token
	SequenceEpoch        string
	AnonymousCredentials AnonymousCredentialSource
	// confirmCapacity is a test seam for the zero-packet check that replaced
	// this carrier's MTU probe. Production leaves it nil.
	confirmCapacity func(DatagramCapacityConfirmer) (int, error)
}

// ValidateAnonymousClientTLS rejects stable client identity and resumption
// state before an anonymous-token carrier can create any TLS connection.
func ValidateAnonymousClientTLS(config *tls.Config) error {
	if config == nil {
		return errors.New("anonymous H3 TLS config is required")
	}
	if len(config.Certificates) != 0 ||
		config.GetClientCertificate != nil ||
		config.GetCertificate != nil ||
		config.GetConfigForClient != nil ||
		config.ClientSessionCache != nil ||
		!config.SessionTicketsDisabled ||
		config.WrapSession != nil ||
		config.UnwrapSession != nil ||
		config.KeyLogWriter != nil ||
		config.Rand != nil {
		return errors.New(
			"anonymous H3 TLS config contains stable client identity or resumption state",
		)
	}
	return nil
}

// ValidateAnonymousQUICConfig rejects address-validation token persistence and
// 0-RTT for anonymous-token carrier paths. A nil config uses Winn's safe,
// non-persistent defaults.
func ValidateAnonymousQUICConfig(config *quic.Config) error {
	if config == nil {
		return nil
	}
	if config.Allow0RTT || config.TokenStore != nil {
		return errors.New(
			"anonymous H3 QUIC config permits resumption or persistent address tokens",
		)
	}
	return nil
}

func (d *H3Dialer) envelopeConfig(maxInner, maxOuter int) EnvelopeConfig {
	return carrierEnvelopeConfig(maxInner, maxOuter, d.DisableLengthPadding)
}

func (d *H3Dialer) validateAnonymousTransportProfile() error {
	if d == nil {
		return errors.New("H3 dialer is nil")
	}
	if d.AuthorizationMode != carrierauth.AuthModeAnonymousToken {
		return nil
	}
	if err := ValidateAnonymousClientTLS(d.TLSConfig); err != nil {
		return err
	}
	return ValidateAnonymousQUICConfig(d.QUICConfig)
}

func NewH3Dialer(template, publicTarget, deviceID, sessionID string, suite tlsconfig.Suite, tlsConfig *tls.Config, deviceSigner *pqauth.Signer, responseVerifier *carrierauth.ResponseVerifier) (*H3Dialer, error) {
	parsedTemplate, err := uritemplate.New(template)
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE URI template: %w", err)
	}
	if err := validateTemplate(parsedTemplate); err != nil {
		return nil, err
	}
	if err := validateTarget(publicTarget); err != nil {
		return nil, err
	}
	if tlsConfig == nil || deviceSigner == nil || responseVerifier == nil ||
		deviceID == "" || !mobility.ValidSessionID(sessionID) {
		return nil, errors.New("H3 carrier client authentication is not configured")
	}
	configuration := tlsConfig.Clone()
	configuration.NextProtos = []string{http3.NextProtoH3}
	previousVerify := configuration.VerifyConnection
	configuration.VerifyConnection = func(state tls.ConnectionState) error {
		if previousVerify != nil {
			if err := previousVerify(state); err != nil {
				return err
			}
		}
		return tlsconfig.ValidatePeerProfile(&state, suite, http3.NextProtoH3)
	}
	return &H3Dialer{
		Template:          parsedTemplate,
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

func (d *H3Dialer) Dial(ctx context.Context) (net.PacketConn, error) {
	return d.dial(ctx, nil)
}

// PreparedH3Path owns a completed TLS 1.3 / QUIC handshake but no CONNECT-UDP
// request, anonymous credential, or Winn session binding. It is single-use.
type PreparedH3Path struct {
	mu             sync.Mutex
	connection     *quic.Conn
	transport      *quic.Transport
	client         *masque.ClientConn
	quicConfig     *quic.Config
	host           string
	profile        [sha256.Size]byte
	authenticating bool
	authenticated  bool
	used           bool
	closed         bool
}

// PrepareH3Path completes the expensive QUIC/TLS handshake without sending an
// authenticated CONNECT request or consuming an anonymous credential.
func (d *H3Dialer) PrepareH3Path(
	ctx context.Context,
) (*PreparedH3Path, error) {
	if ctx == nil {
		return nil, errors.New("dial context is required")
	}
	if d == nil || d.Template == nil || d.TLSConfig == nil {
		return nil, errors.New("H3 transport preparation is incomplete")
	}
	if err := d.validateAnonymousTransportProfile(); err != nil {
		return nil, err
	}
	shadowRequest, err := expandedRequest(ctx, d.Template, d.PublicTarget)
	if err != nil {
		return nil, err
	}
	quicConfig := d.h3QUICConfig()
	connection, transport, err := d.dialH3QUIC(
		ctx, shadowRequest.URL.Host, quicConfig,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"prepare authenticated HTTP/3 carrier underlay: %w", err,
		)
	}
	if connection == nil {
		if transport != nil {
			_ = closeOwnedQUICTransport(transport)
		}
		return nil, errors.New("prepared H3 underlay returned no QUIC connection")
	}
	return &PreparedH3Path{
		connection: connection,
		transport:  transport,
		quicConfig: quicConfig,
		host:       shadowRequest.URL.Host,
		profile:    h3PathProfile(d, shadowRequest.URL.Host),
	}, nil
}

// DialPrepared consumes one live prepared path and performs the click-bound
// anonymous CONNECT authentication on it.
func (d *H3Dialer) DialPrepared(
	ctx context.Context,
	prepared *PreparedH3Path,
) (net.PacketConn, error) {
	if prepared == nil {
		return nil, errors.New("prepared H3 path is required")
	}
	return d.dial(ctx, prepared)
}

func (d *H3Dialer) dial(
	ctx context.Context,
	prepared *PreparedH3Path,
) (net.PacketConn, error) {
	if ctx == nil {
		return nil, errors.New("dial context is required")
	}
	if d == nil || d.Template == nil || d.TLSConfig == nil ||
		d.ResponseVerifier == nil {
		return nil, errors.New("H3 dialer is incomplete")
	}
	if err := d.validateAnonymousTransportProfile(); err != nil {
		return nil, err
	}
	var authentication h3Authentication
	var quicConnection *quic.Conn
	var initialTransport *quic.Transport
	var clientConnection *masque.ClientConn
	var quicConfig *quic.Config
	var err error
	if prepared == nil {
		authentication, err = d.newH3Authentication(ctx)
		if err != nil {
			return nil, err
		}
		quicConfig = d.h3QUICConfig()
		quicConnection, initialTransport, err = d.dialH3QUIC(
			ctx, authentication.shadow.URL.Host, quicConfig,
		)
	} else {
		// Reserve and validate the single-use prepared path before asking the
		// credential source for the click credential. A duplicate click or a
		// stale/mismatched path must not burn an anonymous token.
		shadow, shadowErr := expandedRequest(
			ctx, d.Template, d.PublicTarget,
		)
		if shadowErr != nil {
			return nil, shadowErr
		}
		quicConnection, initialTransport, clientConnection, quicConfig, err =
			prepared.take(d, shadow.URL.Host)
		if err == nil {
			authentication, err = d.newH3Authentication(ctx)
			if err != nil {
				_ = quicConnection.CloseWithError(
					0, "click authentication unavailable",
				)
				if initialTransport != nil {
					_ = closeOwnedQUICTransport(initialTransport)
				}
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("dial authenticated HTTP/3 carrier underlay: %w", err)
	}
	transport := masque.Transport{
		TLSClientConfig: d.TLSConfig,
		QUICConfig:      quicConfig,
		DialAddr:        d.DialQUIC,
	}
	if clientConnection == nil {
		clientConnection, err = transport.NewClientConn(quicConnection)
		if err != nil {
			_ = quicConnection.CloseWithError(0, "invalid MASQUE connection")
			if initialTransport != nil {
				_ = closeOwnedQUICTransport(initialTransport)
			}
			return nil, err
		}
	}
	connection, maxDatagram, err := d.openAuthenticatedH3(
		clientConnection, authentication,
	)
	if err != nil {
		_ = quicConnection.CloseWithError(0, "CONNECT-UDP failed")
		if initialTransport != nil {
			_ = closeOwnedQUICTransport(initialTransport)
		}
		return nil, err
	}
	maxOuter := d.MaxOuterDatagram
	if maxOuter <= 0 {
		maxOuter = maxDatagram + envelopeHeaderSize
	}
	owned := newMigratableH3PacketConn(
		connection, quicConnection, initialTransport,
	)
	limited, err := newEnvelopePacketConn(
		owned, d.envelopeConfig(maxDatagram, maxOuter),
	)
	if err != nil {
		_ = owned.Close()
		return nil, err
	}
	// The HTTP/3 carrier sends no MTU probe.
	//
	// h3QUICConfig pins InitialPacketSize to H3InitialPacketSize(maxOuter),
	// quic-go pads every client Initial packet to that size, and quic-go
	// documents that the handshake times out when the path cannot carry it. The
	// server pins the same floor and its own first flight is padded to it too.
	// So by the time this line runs, a completed handshake has already proven
	// the path carries a datagram larger than a full-size Winn envelope in both
	// directions. TestQUICHandshakeAlreadyProvesTheCarrierPath measures that
	// against the vendored quic-go rather than asserting it from the docs.
	//
	// What the probe uniquely contributed was its failure mode: an adversary
	// who dropped the client's datagrams of the envelope's size class could
	// induce a burst of same-size datagrams followed by a teardown, on demand,
	// on every connection. Confirming the capacity that QUIC already
	// established keeps the fail-closed property and puts nothing on the wire.
	confirmCapacity := func(
		confirmer DatagramCapacityConfirmer,
	) (int, error) {
		return confirmer.ConfirmDatagramCapacity()
	}
	if d.confirmCapacity != nil {
		confirmCapacity = d.confirmCapacity
	}
	if _, err := confirmCapacity(limited); err != nil {
		_ = limited.Close()
		return nil, err
	}
	return limited, nil
}

type h3Authentication struct {
	request *masque.Request
	shadow  *http.Request
	claims  carrierauth.RequestClaims
}

func (d *H3Dialer) newH3Authentication(
	ctx context.Context,
) (h3Authentication, error) {
	return d.newH3AuthenticationForPurpose(
		ctx,
		carrierauth.PurposeData,
	)
}

func (d *H3Dialer) newH3AuthenticationForPurpose(
	ctx context.Context,
	purpose string,
) (h3Authentication, error) {
	if ctx == nil {
		return h3Authentication{}, errors.New(
			"H3 authentication context is required",
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return h3Authentication{}, cause
	}
	if err := d.validateAnonymousTransportProfile(); err != nil {
		return h3Authentication{}, err
	}
	deviceID, signer, token, destroyCredential, err :=
		resolveClientCredential(
			d.AuthorizationMode, d.DeviceID, d.DeviceSigner,
			d.PrivacyToken, d.AnonymousCredentials,
		)
	if err != nil {
		return h3Authentication{}, err
	}
	defer destroyCredential()
	request, err := masque.NewRequest(ctx, d.Template, d.PublicTarget)
	if err != nil {
		return h3Authentication{},
			fmt.Errorf("create CONNECT-UDP request: %w", err)
	}
	shadowRequest, err := expandedRequest(
		ctx, d.Template, d.PublicTarget,
	)
	if err != nil {
		return h3Authentication{}, err
	}
	privacyProfile := carrierauth.PrivacyHighRisk
	if d.DisableLengthPadding {
		privacyProfile = carrierauth.PrivacyStandard
	}
	claims, err := carrierauth.NewRequestClaimsWithOptions(
		shadowRequest,
		string(mobility.HTTP3),
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
			PrivacyProfile:    privacyProfile,
			SequenceEpoch:     d.SequenceEpoch,
			Purpose:           purpose,
		},
	)
	if err != nil {
		return h3Authentication{}, err
	}
	if err := carrierauth.SignRequest(
		request.Header(), claims, signer,
	); err != nil {
		return h3Authentication{}, err
	}
	if err := addPrivacyTokenHeader(
		request.Header(), d.AuthorizationMode, token,
	); err != nil {
		return h3Authentication{}, err
	}
	destroyCredential()
	return h3Authentication{
		request: request,
		shadow:  shadowRequest,
		claims:  claims,
	}, nil
}

func (d *H3Dialer) openAuthenticatedH3(
	client *masque.ClientConn,
	authentication h3Authentication,
) (*masque.Conn, int, error) {
	connection, response, err := client.Dial(authentication.request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if connection != nil {
			_ = connection.Close()
		}
		return nil, 0, fmt.Errorf(
			"dial authenticated HTTP/3 CONNECT-UDP carrier: %w", err,
		)
	}
	responseClaims, err := d.ResponseVerifier.Verify(
		response, authentication.claims, string(mobility.HTTP3),
	)
	if err != nil {
		_ = connection.Close()
		return nil, 0,
			fmt.Errorf("verify H3 carrier response: %w", err)
	}
	return connection, min(d.MaxDatagram, responseClaims.MaxDatagram), nil
}

// AuthenticatePreparedH3Path proves that the warm QUIC/TLS connection accepts
// a signed authentication-only CONNECT-UDP request whose controller-signed
// response verifies. The carrier terminates this request without allocating an
// AWG backend. The separate click-bound data CONNECT consumes a new credential
// and retains its mandatory full-envelope capacity check before DialPrepared
// returns -- a check the established QUIC connection answers locally, with no
// datagram on the wire.
func (d *H3Dialer) AuthenticatePreparedH3Path(
	ctx context.Context,
	prepared *PreparedH3Path,
) error {
	if ctx == nil {
		return errors.New("prepared H3 authentication context is required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if prepared == nil {
		return errors.New("prepared H3 path is required")
	}
	if d == nil || d.Template == nil || d.TLSConfig == nil ||
		d.ResponseVerifier == nil {
		return errors.New("H3 dialer is incomplete")
	}
	if err := d.validateAnonymousTransportProfile(); err != nil {
		return err
	}
	shadow, err := expandedRequest(ctx, d.Template, d.PublicTarget)
	if err != nil {
		return err
	}
	connection, quicConfig, err := prepared.beginAuthentication(
		d, shadow.URL.Host,
	)
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		return prepared.abortAuthentication(cause)
	}
	transport := masque.Transport{
		TLSClientConfig: d.TLSConfig,
		QUICConfig:      quicConfig,
		DialAddr:        d.DialQUIC,
	}
	client, err := transport.NewClientConn(connection)
	if err != nil {
		return fail(fmt.Errorf(
			"prepare authenticated HTTP/3 client connection: %w", err,
		))
	}
	authentication, err := d.newH3AuthenticationForPurpose(
		ctx,
		carrierauth.PurposeAuthenticateOnly,
	)
	if err != nil {
		return fail(err)
	}
	probe, _, err := d.openAuthenticatedH3(
		client, authentication,
	)
	if err != nil {
		return fail(err)
	}
	if closeErr := probe.Close(); closeErr != nil {
		return fail(closeErr)
	}
	return prepared.finishAuthentication(client)
}

// Authenticated reports whether the unused path passed a signed
// authentication-only exchange with a verified controller-signed response. It
// does not mean the later click binding or its MTU-verified data path is online.
func (prepared *PreparedH3Path) Authenticated() bool {
	if prepared == nil {
		return false
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	return prepared.authenticated &&
		!prepared.authenticating &&
		!prepared.used &&
		!prepared.closed &&
		prepared.client != nil &&
		prepared.connection != nil &&
		prepared.connection.Context().Err() == nil
}

// Ready reports only whether the unused prepared QUIC connection remains
// live. A true value never substitutes for click-time CONNECT, AWG, DNS, or
// canary verification.
func (prepared *PreparedH3Path) Ready() bool {
	if prepared == nil {
		return false
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.used || prepared.closed || prepared.connection == nil {
		return false
	}
	return prepared.connection.Context().Err() == nil
}

// Close releases an unused path. Once DialPrepared consumes the path, the
// returned PacketConn owns QUIC and transport teardown.
func (prepared *PreparedH3Path) Close() error {
	if prepared == nil {
		return nil
	}
	prepared.mu.Lock()
	if prepared.used || prepared.closed {
		prepared.mu.Unlock()
		return nil
	}
	prepared.closed = true
	connection := prepared.connection
	transport := prepared.transport
	prepared.connection = nil
	prepared.transport = nil
	prepared.client = nil
	prepared.quicConfig = nil
	prepared.mu.Unlock()
	var closeErr error
	if connection != nil {
		closeErr = errors.Join(
			closeErr,
			connection.CloseWithError(0, "prepared H3 path closed"),
		)
	}
	if transport != nil {
		closeErr = errors.Join(
			closeErr,
			closeOwnedQUICTransport(transport),
		)
	}
	return closeErr
}

func (prepared *PreparedH3Path) take(
	dialer *H3Dialer,
	host string,
) (*quic.Conn, *quic.Transport, *masque.ClientConn, *quic.Config, error) {
	prepared.mu.Lock()
	if prepared.used || prepared.closed || prepared.connection == nil ||
		prepared.quicConfig == nil || !prepared.authenticated ||
		prepared.authenticating || prepared.client == nil {
		prepared.mu.Unlock()
		return nil, nil, nil, nil, errors.New(
			"prepared H3 path is unauthenticated, closed, or already consumed",
		)
	}
	if prepared.host != host ||
		prepared.profile != h3PathProfile(dialer, host) {
		prepared.mu.Unlock()
		return nil, nil, nil, nil, errors.New(
			"prepared H3 path differs from the click-time transport profile",
		)
	}
	if err := prepared.connection.Context().Err(); err != nil {
		connection := prepared.connection
		transport := prepared.transport
		prepared.closed = true
		prepared.connection = nil
		prepared.transport = nil
		prepared.client = nil
		prepared.quicConfig = nil
		prepared.mu.Unlock()
		_ = connection.CloseWithError(0, "prepared H3 path lost")
		if transport != nil {
			_ = closeOwnedQUICTransport(transport)
		}
		return nil, nil, nil, nil, fmt.Errorf(
			"prepared H3 path is no longer live: %w", err,
		)
	}
	prepared.used = true
	connection := prepared.connection
	transport := prepared.transport
	client := prepared.client
	quicConfig := prepared.quicConfig.Clone()
	prepared.connection = nil
	prepared.transport = nil
	prepared.client = nil
	prepared.quicConfig = nil
	prepared.mu.Unlock()
	return connection, transport, client, quicConfig, nil
}

func (prepared *PreparedH3Path) beginAuthentication(
	dialer *H3Dialer,
	host string,
) (*quic.Conn, *quic.Config, error) {
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.used || prepared.closed || prepared.authenticating ||
		prepared.authenticated || prepared.connection == nil ||
		prepared.quicConfig == nil {
		return nil, nil, errors.New(
			"prepared H3 path cannot begin authentication",
		)
	}
	if prepared.host != host ||
		prepared.profile != h3PathProfile(dialer, host) {
		return nil, nil, errors.New(
			"prepared H3 path differs from the authentication profile",
		)
	}
	if err := prepared.connection.Context().Err(); err != nil {
		return nil, nil, fmt.Errorf(
			"prepared H3 path is no longer live: %w", err,
		)
	}
	prepared.authenticating = true
	return prepared.connection, prepared.quicConfig.Clone(), nil
}

func (prepared *PreparedH3Path) finishAuthentication(
	client *masque.ClientConn,
) error {
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if !prepared.authenticating || prepared.closed ||
		prepared.used || client == nil ||
		prepared.connection == nil ||
		prepared.connection.Context().Err() != nil {
		return errors.New(
			"prepared H3 path closed during authentication",
		)
	}
	prepared.client = client
	prepared.authenticating = false
	prepared.authenticated = true
	return nil
}

func (prepared *PreparedH3Path) abortAuthentication(cause error) error {
	prepared.mu.Lock()
	connection := prepared.connection
	transport := prepared.transport
	prepared.authenticating = false
	prepared.authenticated = false
	prepared.closed = true
	prepared.connection = nil
	prepared.transport = nil
	prepared.client = nil
	prepared.quicConfig = nil
	prepared.mu.Unlock()
	var closeErr error
	if connection != nil {
		closeErr = errors.Join(
			closeErr,
			connection.CloseWithError(0, "prepared H3 authentication failed"),
		)
	}
	if transport != nil {
		closeErr = errors.Join(
			closeErr,
			closeOwnedQUICTransport(transport),
		)
	}
	return errors.Join(cause, closeErr)
}

const (
	clientInitialStreamReceiveWindow     uint64 = 128 * 1024
	clientMaxStreamReceiveWindow         uint64 = 512 * 1024
	clientInitialConnectionReceiveWindow uint64 = 256 * 1024
	clientMaxConnectionReceiveWindow     uint64 = 2 * 1024 * 1024
)

func applyClientReceiveWindowLimits(config *quic.Config) {
	config.InitialStreamReceiveWindow = clientInitialStreamReceiveWindow
	config.MaxStreamReceiveWindow = clientMaxStreamReceiveWindow
	config.InitialConnectionReceiveWindow = clientInitialConnectionReceiveWindow
	config.MaxConnectionReceiveWindow = clientMaxConnectionReceiveWindow
}

func (d *H3Dialer) h3QUICConfig() *quic.Config {
	requiredInitialPacketSize := H3InitialPacketSize(d.MaxOuterDatagram)
	quicConfig := d.QUICConfig
	if quicConfig == nil {
		keepAlive := 15 * time.Second
		if !d.DisableLengthPadding {
			keepAlive = 12*time.Second + secureJitter(6*time.Second)
		}
		quicConfig = &quic.Config{
			EnableDatagrams:         true,
			InitialPacketSize:       requiredInitialPacketSize,
			DisablePathMTUDiscovery: false,
			HandshakeIdleTimeout:    8 * time.Second,
			MaxIdleTimeout:          45 * time.Second,
			KeepAlivePeriod:         keepAlive,
			Allow0RTT:               false,
		}
	}
	if d.QUICConfig != nil {
		quicConfig = quicConfig.Clone()
	}
	applyClientReceiveWindowLimits(quicConfig)
	quicConfig.EnableDatagrams = true
	quicConfig.Allow0RTT = false
	if quicConfig.InitialPacketSize < requiredInitialPacketSize {
		quicConfig.InitialPacketSize = requiredInitialPacketSize
	}
	return quicConfig
}

// H3InitialPacketSize returns the minimum QUIC packet size that leaves
// conservative room for one complete Winn envelope. Client and server must
// use the same floor so the same-sized MTU acknowledgement proves both path
// directions. quic-go's current maximum packet buffer is 1,452 bytes.
func H3InitialPacketSize(maxOuterDatagram int) uint16 {
	const (
		minimumQUICPacketSize = 1200
		maximumQUICPacketSize = 1452
		quicPacketHeadroom    = 64
	)
	initialPacketSize := maximumQUICPacketSize
	if maxOuterDatagram <= maximumQUICPacketSize-quicPacketHeadroom {
		initialPacketSize = maxOuterDatagram + quicPacketHeadroom
	}
	initialPacketSize = max(initialPacketSize, minimumQUICPacketSize)
	initialPacketSize = min(initialPacketSize, maximumQUICPacketSize)
	// #nosec G115 -- the value is explicitly clamped to 1,200..1,452.
	return uint16(initialPacketSize)
}

// UseSuppliedSocket builds this dialer around a caller-supplied, unconnected
// UDP socket instead of one it opens itself. The dialer takes ownership: the
// carrier returned by Dial closes the socket when it closes.
//
// It refuses if a custom QUIC dial hook is already installed, because the two
// disagree about who owns the transport and silently picking one is exactly the
// failure this seam exists to prevent.
func (d *H3Dialer) UseSuppliedSocket(conn net.PacketConn) error {
	if d == nil {
		return errors.New("H3 dialer is nil")
	}
	if d.DialQUIC != nil || d.DialQUICPath != nil {
		return ErrSuppliedSocketConflict
	}
	supplied, err := NewSuppliedPacketSocket(conn)
	if err != nil {
		return err
	}
	d.TransportSocket = supplied
	return nil
}

// SuppliedSocketKind reports that HTTP/3 CONNECT-UDP — the MASQUE carrier —
// rides a UDP socket.
func (d *H3Dialer) SuppliedSocketKind() SocketKind { return SocketKindPacket }

// HasSuppliedSocket reports whether a caller-supplied socket is installed.
func (d *H3Dialer) HasSuppliedSocket() bool {
	return d != nil && d.TransportSocket != nil
}

func (d *H3Dialer) dialH3QUIC(
	ctx context.Context,
	host string,
	quicConfig *quic.Config,
) (*quic.Conn, *quic.Transport, error) {
	if d.TransportSocket != nil {
		// The supplied socket is the one the host protected, so it outranks
		// every other path. A custom hook alongside it is a contradiction, not
		// a fallback.
		if d.DialQUICPath != nil || d.DialQUIC != nil {
			return nil, nil, ErrSuppliedSocketConflict
		}
		return dialSuppliedQUIC(
			ctx, host, d.TLSConfig, quicConfig, d.TransportSocket,
		)
	}
	switch {
	case d.DialQUICPath != nil:
		return d.DialQUICPath(
			ctx, host, d.TLSConfig, quicConfig,
		)
	case d.DialQUIC != nil:
		connection, err := d.DialQUIC(
			ctx, host, d.TLSConfig, quicConfig,
		)
		return connection, nil, err
	default:
		return dialMigratableQUIC(
			ctx, host, d.TLSConfig, quicConfig,
		)
	}
}

func h3PathProfile(d *H3Dialer, host string) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = fmt.Fprintf(
		hash,
		"%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%t\x00",
		d.Template.Raw(),
		d.PublicTarget,
		host,
		d.Suite.Name,
		d.MaxDatagram,
		d.MaxOuterDatagram,
		d.TLSConfig.MinVersion,
		d.DisableLengthPadding,
	)
	_, _ = fmt.Fprintf(
		hash,
		"%s\x00%d\x00",
		d.TLSConfig.ServerName,
		d.TLSConfig.MaxVersion,
	)
	for _, protocol := range d.TLSConfig.NextProtos {
		_, _ = fmt.Fprintf(hash, "%s\x00", protocol)
	}
	for _, curve := range d.TLSConfig.CurvePreferences {
		_, _ = fmt.Fprintf(hash, "%d\x00", curve)
	}
	_, _ = hash.Write(d.TLSConfig.EncryptedClientHelloConfigList)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func expandedRequest(ctx context.Context, template *uritemplate.Template, target string) (*http.Request, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("parse public UDP target: %w", err)
	}
	expanded, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
	if err != nil {
		return nil, fmt.Errorf("expand MASQUE URI template: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, expanded, nil)
	if err != nil {
		return nil, fmt.Errorf("create carrier binding request: %w", err)
	}
	request.Host = request.URL.Host
	return request, nil
}

func validateTemplate(template *uritemplate.Template) error {
	if template == nil {
		return errors.New("MASQUE URI template is nil")
	}
	parsed, err := url.Parse(template.Raw())
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("MASQUE URI template must use an absolute HTTPS URL")
	}
	if !containsTemplateVariable(template.Raw(), "target_host") ||
		!containsTemplateVariable(template.Raw(), "target_port") {
		return errors.New("MASQUE URI template must contain target_host and target_port")
	}
	return nil
}

func validateTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return errors.New("UDP target must be host:port")
	}
	numericPort, err := strconv.Atoi(port)
	if err != nil || numericPort < 1 || numericPort > 65535 {
		return errors.New("UDP target port is invalid")
	}
	return nil
}

func containsTemplateVariable(template, variable string) bool {
	return len(template) > 0 &&
		(url.QueryEscape(variable) == variable) &&
		(stringContains(template, "{"+variable+"}") ||
			stringContains(template, "{/"+variable+"}") ||
			stringContains(template, "{?"+variable) ||
			stringContains(template, ","+variable))
}

func stringContains(value, fragment string) bool {
	return strings.Contains(value, fragment)
}

func carrierRemoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil && host != "" {
		return host
	}
	if address == "" {
		return "unknown"
	}
	return address
}
