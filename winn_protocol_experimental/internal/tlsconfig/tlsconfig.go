package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"winsvpn.local/winnprotocol/internal/securefile"
)

// extensionEncryptedClientHello is the RFC 9849 ECH extension code point. Go
// hands GetConfigForClient the decrypted *inner* ClientHello when ECH is
// accepted, and that inner hello still carries this extension - but so does
// the *outer* hello Go falls back to when ECH is GREASE or undecryptable, so
// its presence ALONE does not separate a genuine ECH client from a prober.
// ApplyCoverProfile therefore also requires the inner/outer name split only
// a decrypted inner hello can show; see outerECHNames.
const extensionEncryptedClientHello uint16 = 0xfe0d

// outerECHNames records, per connection, the SNI of the OUTER ClientHello
// that GetEncryptedClientHelloKeys was called with, so GetConfigForClient
// can tell a decrypted inner hello from the outer hello Go falls back to
// when ECH is not accepted. The two are otherwise indistinguishable from
// ClientHelloInfo: both carry the ECH extension code point, and no field
// reports acceptance at that point. They differ in exactly one way a
// fallback cannot fake: a genuine client's outer SNI is the ECH public
// name while its inner SNI is the private name (deployments must keep
// those different - see coverlisten), whereas a rejected outer hello
// presents the same name twice. Entries are consumed by
// GetConfigForClient on the same connection, before any of its early
// returns. Handshakes that die between the two callbacks (an ECH extension
// Go cannot parse, an inner hello it cannot decode) leave residue; the
// ring evicts the oldest record once maxOuterECHNames newer ones exist, so
// residue ages out instead of filling the table and failing every later
// genuine client closed to the cover profile. Go runs both callbacks back
// to back in readClientHello with no network read between them, so a live
// record is never anywhere near that old.
type outerECHNames struct {
	mu     sync.Mutex
	byConn map[net.Conn]outerECHEntry
	ring   []net.Conn
	seq    uint64
}

type outerECHEntry struct {
	name string
	seq  uint64
}

const maxOuterECHNames = 8192

func (o *outerECHNames) record(conn net.Conn, name string) {
	if conn == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.byConn == nil {
		o.byConn = make(map[net.Conn]outerECHEntry)
		o.ring = make([]net.Conn, maxOuterECHNames)
	}
	slot := o.seq % maxOuterECHNames
	if old := o.ring[slot]; old != nil {
		// The slot last held the record made maxOuterECHNames records
		// ago; evict it unless it was consumed or recorded again since.
		if entry, ok := o.byConn[old]; ok && entry.seq == o.seq-maxOuterECHNames {
			delete(o.byConn, old)
		}
	}
	o.ring[slot] = conn
	o.byConn[conn] = outerECHEntry{name: name, seq: o.seq}
	o.seq++
}

func (o *outerECHNames) consume(conn net.Conn) (string, bool) {
	if conn == nil {
		return "", false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	entry, ok := o.byConn[conn]
	if ok {
		delete(o.byConn, conn)
		if slot := entry.seq % maxOuterECHNames; o.ring[slot] == conn {
			o.ring[slot] = nil
		}
	}
	return entry.name, ok
}

type Suite struct {
	Name  string
	Curve tls.CurveID
}

func ParseSuite(name string) (Suite, error) {
	switch name {
	case "x25519-mlkem768":
		return Suite{Name: name, Curve: tls.X25519MLKEM768}, nil
	case "p256-mlkem768":
		return Suite{Name: name, Curve: tls.SecP256r1MLKEM768}, nil
	case "p384-mlkem1024":
		return Suite{Name: name, Curve: tls.SecP384r1MLKEM1024}, nil
	default:
		return Suite{}, fmt.Errorf("unsupported cryptographic suite %q", name)
	}
}

func Server(certPath, keyPath, clientCAPath string, suite Suite) (*tls.Config, error) {
	return ServerForALPN(certPath, keyPath, clientCAPath, suite, "http/1.1")
}

func ServerForALPN(certPath, keyPath, clientCAPath string, suite Suite, alpn ...string) (*tls.Config, error) {
	return serverForALPN(
		certPath, keyPath, clientCAPath, suite,
		tls.RequireAndVerifyClientCert, alpn...,
	)
}

// ServerAnonymousForALPN authenticates only the carrier endpoint. Anonymous
// clients prove authorization with a blind token at the HTTP layer and must
// not present a stable client certificate.
func ServerAnonymousForALPN(certPath, keyPath string, suite Suite, alpn ...string) (*tls.Config, error) {
	return serverForALPN(certPath, keyPath, "", suite, tls.NoClientCert, alpn...)
}

// ServerEitherForALPN supports a transition listener that accepts either
// verified mTLS or no client certificate. The HTTP authentication layer still
// requires exactly one corresponding authorization mode.
func ServerEitherForALPN(certPath, keyPath, clientCAPath string, suite Suite, alpn ...string) (*tls.Config, error) {
	return serverForALPN(
		certPath, keyPath, clientCAPath, suite,
		tls.VerifyClientCertIfGiven, alpn...,
	)
}

func serverForALPN(certPath, keyPath, clientCAPath string, suite Suite, clientAuth tls.ClientAuthType, alpn ...string) (*tls.Config, error) {
	if err := validateALPN(alpn); err != nil {
		return nil, err
	}
	if err := validatePublicFile(certPath); err != nil {
		return nil, err
	}
	if err := validatePrivateKeyFile(keyPath); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}
	var clientCAs *x509.CertPool
	if clientAuth != tls.NoClientCert {
		var err error
		clientCAs, err = loadCertPool(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{certificate},
		ClientAuth:               clientAuth,
		ClientCAs:                clientCAs,
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{suite.Curve},
		SessionTicketsDisabled:   true,
		Renegotiation:            tls.RenegotiateNever,
		NextProtos:               append([]string(nil), alpn...),
		PreferServerCipherSuites: true,
	}, nil
}

// CoverProfile describes how a listener presents itself to peers that have not
// demonstrated they are Winn clients.
//
// The Winn TLS profile is, by itself, a reliable single-probe identifier: one
// named group, TLS 1.3 only, mandatory ECH, and - in identity mode - a
// CertificateRequest whose certificate_authorities field names the Winn CA.
// Any one of those confirms the endpoint to anyone who connects. A censorship
// -resistant endpoint must instead answer an unauthenticated peer the way an
// ordinary web server would, which is the pattern Trojan, VLESS-REALITY and
// Hysteria all converge on.
//
// So the listener runs two profiles. The cover profile is a stock web-server
// configuration and is what every unrecognised peer negotiates. The Winn
// profile is the strict configuration and is selected only for a ClientHello
// that both carries an ECH extension and names the deployment's private
// server name - knowledge a prober does not have and cannot derive from the
// wire.
type CoverProfile struct {
	// PrivateServerName is the ECH-inner SNI a genuine Winn client presents.
	// When empty, no peer reaches the Winn profile unless
	// AllowUnnamedWinnClients is set.
	PrivateServerName string

	// CoverALPN is what the cover profile negotiates. It should be whatever an
	// ordinary server on this port would offer - {"h2","http/1.1"} for TCP,
	// {"h3"} for QUIC.
	CoverALPN []string

	// Certificate is what the cover profile presents to unauthenticated peers.
	//
	// This matters as much as withholding certificate_authorities. Winn
	// clients pin the Winn CA, so the gateway's own leaf is issued by it, and
	// a leaf carries its issuer's Distinguished Name in the clear. Serving
	// that leaf to every prober re-broadcasts exactly the CA identity the
	// CertificateRequest was just stopped from disclosing - and links every
	// deployment under the same CA. An operator should supply an ordinary
	// certificate for the cover name here, ideally one from a public CA.
	//
	// It is required. Leaving it nil would reuse the Winn leaf and re-open the
	// disclosure, so ApplyCoverProfile refuses unless AllowWinnLeafAsCover
	// says the caller meant it.
	Certificate *tls.Certificate

	// AllowWinnLeafAsCover permits the cover profile to serve the Winn leaf to
	// unauthenticated peers when Certificate is nil.
	//
	// This is a lab escape hatch and nothing else. It leaves the deployment
	// identifiable on one unauthenticated connection - the prober simply reads
	// the issuer Distinguished Name off the leaf - and correlates it with every
	// other deployment under the same CA. It exists so a harness on a loopback
	// address does not need a second PKI, not so a production listener can come
	// up without a cover certificate.
	//
	// It is an explicit field rather than a nil default because the previous
	// arrangement - nil silently falling back to the Winn leaf, with a warning
	// on the service's stderr - is how a release blocker survives to a release.
	// A warning is not a gate.
	AllowWinnLeafAsCover bool

	// AllowUnnamedWinnClients selects the Winn profile on the ECH marker alone,
	// without a matching server name.
	//
	// It exists for deployments whose certificate carries only an IP address:
	// RFC 6066 forbids IP literals in SNI, so those clients present no server
	// name and there is nothing to match. The trade-off is explicit. With a
	// name, a peer must know the deployment's private server name to draw a
	// CertificateRequest. Without one, any peer willing to construct an ECH
	// extension can, so the CA Distinguished Name is withheld from ordinary
	// probers but not from a targeted one. Deployments that can use a DNS name
	// should, and internet-facing carriers should prefer anonymous-token mode,
	// which requests no client certificate at all.
	AllowUnnamedWinnClients bool
}

// ApplyCoverProfile returns a listener configuration that is indistinguishable
// from an ordinary web server to anything that has not proven it is a Winn
// client, while still routing genuine Winn clients to the strict profile.
//
// The returned configuration is what the listener must use. The strict
// configuration passed in is retained and handed out by GetConfigForClient; it
// is not modified.
//
// Note that the cover profile sets no CipherSuites and no CurvePreferences.
// That is deliberate: the Go defaults are exactly what a stock Go web server
// offers, so the accepted set cannot itself be a fingerprint. It also leaves
// ClientAuth at NoClientCert, so no CertificateRequest is sent and no
// certificate_authorities extension - and therefore no CA Distinguished Name -
// ever reaches an unauthenticated peer.
func ApplyCoverProfile(winn *tls.Config, cover CoverProfile) (*tls.Config, error) {
	if winn == nil {
		return nil, errors.New("winn tls configuration is required")
	}
	if len(cover.CoverALPN) == 0 {
		return nil, errors.New("cover profile requires at least one ALPN protocol")
	}
	if err := validateALPN(cover.CoverALPN); err != nil {
		return nil, err
	}
	if len(winn.Certificates) == 0 && winn.GetCertificate == nil {
		return nil, errors.New("cover profile requires a server certificate")
	}
	if cover.Certificate == nil && !cover.AllowWinnLeafAsCover {
		return nil, errors.New(
			"cover profile requires its own certificate: reusing the Winn leaf " +
				"discloses the issuing CA's Distinguished Name to every " +
				"unauthenticated prober and links this deployment to every other " +
				"under the same CA",
		)
	}
	coverCertificates := append([]tls.Certificate(nil), winn.Certificates...)
	coverGetCertificate := winn.GetCertificate
	if cover.Certificate != nil {
		coverCertificates = []tls.Certificate{*cover.Certificate}
		coverGetCertificate = nil
	}
	profile := &tls.Config{
		Certificates:   coverCertificates,
		GetCertificate: coverGetCertificate,

		// An ordinary server has not refused TLS 1.2 for years, and refusing
		// it is a single-probe discriminator on its own.
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// No client certificate is requested, so an unauthenticated peer never
		// sees a CertificateRequest and never learns the client CA's name.
		ClientAuth: tls.NoClientCert,
		ClientCAs:  nil,

		NextProtos:    append([]string(nil), cover.CoverALPN...),
		Renegotiation: tls.RenegotiateNever,

		// Left at the zero value on purpose: ordinary TLS 1.3 servers issue
		// NewSessionTicket, and a server that never does stands out.
		SessionTicketsDisabled: false,
	}
	private := cover.PrivateServerName
	if private == "" && !cover.AllowUnnamedWinnClients {
		// Nothing can select the Winn profile, so every peer stays on the
		// cover profile. Correct for anonymous-token mode, which requests no
		// client certificate and so has no CA name to protect.
		return profile, nil
	}
	outerNames := &outerECHNames{}
	// Go calls this with the OUTER hello, before ECH processing, whenever
	// the client offered the ECH extension. Recording its SNI is the only
	// way GetConfigForClient below can distinguish the decrypted inner
	// hello from the outer fallback (see outerECHNames). The keys are the
	// profile's own, read at call time so the caller's later
	// ConfigureServerCover installation is honoured.
	profile.GetEncryptedClientHelloKeys = func(hello *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		if hello != nil {
			outerNames.record(hello.Conn, hello.ServerName)
		}
		return profile.EncryptedClientHelloKeys, nil
	}
	profile.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil {
			return nil, nil
		}
		// Consume this connection's outer-name record before any early
		// return below: every ordinary browser offers GREASE ECH to the
		// cover name and returns at the SNI check, and a record left
		// behind would only age out of the table.
		outerName, recorded := outerNames.consume(hello.Conn)
		// Go hands this callback the decrypted inner ClientHello when ECH is
		// accepted, and that hello still carries the ECH extension. A peer
		// that offered no ECH at all cannot be a Winn client.
		//
		// LIMIT. When the extension is present but the server could NOT
		// decrypt it (a key it does not hold, or GREASE), Go hands this
		// callback the OUTER ClientHello instead, and that hello carries the
		// same extension code point plus whatever SNI the peer put in the
		// clear. ClientHelloInfo exposes no "ECH accepted" signal, so this
		// check cannot tell the two apart: the private server name is the
		// only thing standing between a prober and the strict profile, and a
		// prober that knows it is served the Winn leaf before the strict
		// profile's VerifyConnection runs. A listener with nothing to serve on
		// the strict profile must therefore not have one (coverlisten
		// Options.CoverOnly); a listener that needs it must treat the private
		// name as a secret with fleet-wide blast radius.
		if !hasExtension(hello.Extensions, extensionEncryptedClientHello) {
			return nil, nil
		}
		if private != "" && !strings.EqualFold(hello.ServerName, private) {
			return nil, nil
		}
		// The extension is also present on the outer hello Go falls back
		// to when ECH is GREASE or undecryptable, and that hello's SNI is
		// whatever the peer put in the clear - so a prober that merely
		// knows the private name and adds a GREASE ECH extension would
		// otherwise be handed the strict profile, Winn leaf and client-CA
		// names included. Require the split only decryption produces:
		// the outer hello (recorded above) named a different server than
		// this one. A fallback presents the same name twice.
		if !recorded || strings.EqualFold(outerName, hello.ServerName) {
			return nil, nil
		}
		return winn, nil
	}
	return profile, nil
}

// LoadCoverCertificate reads the certificate the cover profile presents to
// unauthenticated peers. It is validated with the same file-permission checks
// as any other server key material.
func LoadCoverCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("cover certificate requires both a certificate and a key")
	}
	if err := validatePublicFile(certPath); err != nil {
		return nil, err
	}
	if err := validatePrivateKeyFile(keyPath); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cover key pair: %w", err)
	}
	return &certificate, nil
}

// CertificateIssuerName reports the issuer Distinguished Name a peer sees on
// the leaf a configuration serves. Callers use it to warn when the cover
// profile would hand an unauthenticated prober a certificate whose issuer
// identifies the deployment.
func CertificateIssuerName(config *tls.Config) (string, error) {
	if config == nil || len(config.Certificates) == 0 ||
		len(config.Certificates[0].Certificate) == 0 {
		return "", errors.New("no certificate is configured")
	}
	leaf := config.Certificates[0].Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
		if err != nil {
			return "", fmt.Errorf("parse certificate: %w", err)
		}
		leaf = parsed
	}
	return leaf.Issuer.String(), nil
}

func hasExtension(extensions []uint16, wanted uint16) bool {
	for _, extension := range extensions {
		if extension == wanted {
			return true
		}
	}
	return false
}

// PrivateServerNameFromCertificate recovers the name a Winn client presents as
// its ECH-inner SNI from the server's own leaf certificate, so the cover
// profile does not need a separate, drift-prone configuration flag.
func PrivateServerNameFromCertificate(config *tls.Config) (string, error) {
	if config == nil || len(config.Certificates) == 0 ||
		len(config.Certificates[0].Certificate) == 0 {
		return "", errors.New("no server certificate is configured")
	}
	leaf := config.Certificates[0].Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
		if err != nil {
			return "", fmt.Errorf("parse server certificate: %w", err)
		}
		leaf = parsed
	}
	for _, name := range leaf.DNSNames {
		if name != "" {
			return name, nil
		}
	}
	// Deliberately no fallback to IP SANs or the Common Name. RFC 6066 forbids
	// IP literals in SNI, so a client verifying an IP-only certificate sends
	// no server name at all and there would be nothing to match; returning the
	// address here would silently produce a rule that never fires.
	return "", errors.New(
		"server certificate carries no DNS name, so clients present no SNI to match",
	)
}

// NormalizeServerName strips any port and trailing dot so a configured server
// name compares equal to the SNI a client actually sends.
func NormalizeServerName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil && host != "" {
		value = host
	}
	return strings.TrimSuffix(value, ".")
}

// TrustAnchor names where a client's trust in the server certificate comes
// from. It exists so that CDN-fronting is EXPRESSIBLE, which it was not.
//
// # The defect this closes
//
// Until this type existed, every client configuration this package built ran
// through loadCertPool, which requires a real PEM file and errors on an empty
// path. RootCAs was therefore always a private Winn pool and never the system
// store, so the TCP connection had to terminate at a host holding a
// Winn-CA-issued certificate — the gateway node itself, real address exposed.
// A CDN in front of it would present a WebPKI certificate the client refuses.
//
// That is a censorship-resistance regression and not a small one. It is the
// same objection that shelved http3-connect-udp as a censorship transport
// (CONSOLIDATED_ROLLOUT_RUNBOOK_20260807.md), and v1's equivalent leg is CDN
// -fronted today. It converts "the censor must block a CDN" into "the censor
// must block one address", and blocking one address is free.
//
// # Why trusting the public WebPKI is sound HERE and would not be elsewhere
//
// The obvious objection to WebPKI is that the TLS chain becomes only as strong
// as the weakest public CA, and on a handset that includes anything an MDM or a
// state root program has installed. That objection is decisive when TLS is the
// only thing authenticating the peer. It is not decisive here, because on this
// carrier TLS is not the security boundary:
//
//   - The carrier RESPONSE is ML-DSA-signed and verified against PINNED
//     controller keys (carrierauth.ResponseVerifier, keys loaded by
//     pqauth.LoadVerifierSet). A MITM holding a mis-issued WebPKI certificate
//     still cannot produce a response this client accepts.
//   - The datagrams inside the envelope are independently encrypted end to end
//     by the tunnel, so a TLS-terminating intermediary — the legitimate CDN
//     included — carries ciphertext and nothing else.
//
// So the TLS layer on a fronted deployment supplies camouflage and transport;
// the pinned ML-DSA verifier supplies authentication. That division is what
// makes the trade sound, and it is why this type is safe to add here and would
// not be safe to add to a client whose only peer authentication was the chain.
//
// # There is a third deployment shape, and it needs no code
//
// A Layer-4 fronting service that forwards TCP by SNI WITHOUT terminating TLS
// keeps the handshake end to end. Such a deployment stays on TrustPrivateCA and
// works today, unchanged: the certificate the client verifies is still the
// gateway's Winn-CA leaf. TrustWebPKI is for the TLS-TERMINATING case
// specifically. A deployment that can get L4 fronting should prefer it, because
// it keeps mTLS and the private anchor and still hides the address.
type TrustAnchor string

const (
	// TrustPrivateCA verifies the server certificate against a private Winn
	// PEM pool. It is what every caller got before this type existed and what
	// every existing caller still gets, byte for byte.
	TrustPrivateCA TrustAnchor = "private-ca"

	// TrustWebPKI verifies the server certificate against the host's system
	// trust store, so a TLS-terminating CDN presenting an ordinary WebPKI
	// certificate for the fronting domain is accepted.
	TrustWebPKI TrustAnchor = "webpki"
)

var (
	// ErrTrustAnchorUnknown is returned for an unnamed or misspelled anchor.
	// There is deliberately no default: an anchor is the difference between
	// verifying against the Winn CA and verifying against the world, and a
	// caller that did not say which one it meant must be told so rather than
	// handed either.
	ErrTrustAnchorUnknown = errors.New(
		"TLS client trust anchor is unknown: use " + string(TrustPrivateCA) +
			" or " + string(TrustWebPKI),
	)

	// ErrTrustRootCARequired is returned when TrustPrivateCA names no PEM file.
	ErrTrustRootCARequired = errors.New(
		"TLS client trust anchor " + string(TrustPrivateCA) +
			" requires a root CA PEM path",
	)

	// ErrTrustRootCAConflict is returned when TrustWebPKI ALSO names a PEM
	// file. The two are refused together rather than resolved in favour of
	// either, because a deployment document that names both has not decided
	// what it trusts, and guessing would mean either silently ignoring a
	// configured private anchor or silently refusing the CDN the operator
	// asked for.
	ErrTrustRootCAConflict = errors.New(
		"TLS client trust anchor " + string(TrustWebPKI) +
			" must not also name a root CA PEM path",
	)

	// ErrTrustServerNameRequired is returned when TrustWebPKI names no server
	// name.
	//
	// This is fail-closed and not a formality. crypto/tls falls back to the
	// DIAL ADDRESS when ServerName is empty, and this carrier hands the dialer
	// a socket the host already opened, so the dial address is frequently a
	// bare IP literal. Verification against the system pool would then either
	// fail confusingly or, worse, be attempted against a name nobody chose.
	// The fronting domain is the whole point of a fronted deployment, so it is
	// required explicitly.
	ErrTrustServerNameRequired = errors.New(
		"TLS client trust anchor " + string(TrustWebPKI) +
			" requires an explicit server name: it is the fronting domain the " +
			"public certificate must match",
	)

	// ErrTrustServerNameNotADomain is returned when TrustWebPKI names an IP
	// literal, or something else that is not a DNS name.
	//
	// A fronted deployment that verifies a public certificate for an ADDRESS
	// has not been fronted: the address is back on the wire, in the SNI and in
	// the certificate, which is the exact exposure this anchor exists to
	// remove. It is also nearly unsatisfiable in practice — public CAs issue
	// for IP addresses rarely and CDNs do not front them — so an operator who
	// configured one has made a mistake that must surface at configuration
	// time rather than as a handshake failure in the field.
	ErrTrustServerNameNotADomain = errors.New(
		"TLS client trust anchor " + string(TrustWebPKI) +
			" requires a fronting DOMAIN, not an address: verifying a public " +
			"certificate for an IP literal puts the address back on the wire",
	)

	// ErrTrustWebPKIWithClientCertificate is returned when TrustWebPKI is
	// combined with a stable device client certificate.
	//
	// Two independent reasons, either of which alone is sufficient:
	//
	//  1. It cannot work. A TLS-terminating CDN is the peer of the mTLS
	//     handshake, so the ORIGIN never sees the certificate. Identity-mode
	//     authorization compares the ML-DSA claims against the certificate's
	//     device ID (carrierauth.RequestVerifier.Verify: "carrier device
	//     identity does not match mTLS certificate"), and that comparison has
	//     no input at the origin. The session would be refused after the
	//     connection succeeded, which is the worst place to discover it.
	//  2. It should not work. A stable device certificate is a persistent,
	//     unique device identifier, and presenting it to a fronting CDN hands
	//     that identifier to a third party on every connection — for a
	//     circumvention tool whose users are the people most harmed by being
	//     enumerable.
	//
	// The correct pairing for a fronted deployment is anonymous-token
	// authorization, whose one-time ML-DSA key is committed inside a blind
	// token and verified END TO END at the origin
	// (carrierauth.RequestVerifier.VerifyAnonymous, which "deliberately does
	// not consult the stable device registry or a client certificate").
	ErrTrustWebPKIWithClientCertificate = errors.New(
		"TLS client trust anchor " + string(TrustWebPKI) +
			" must not present a stable device certificate: a TLS-terminating " +
			"CDN is the mTLS peer, so the origin cannot verify it, and the " +
			"CDN would receive a persistent device identifier",
	)
)

// ClientTrust is the trust anchor a client configuration is built on.
//
// The zero value is deliberately INVALID rather than "private CA": a struct
// that arrives from a decoded deployment document with no anchor field has not
// stated what it trusts, and defaulting it either way would be a security
// decision made by an absent field. Every constructor that predates this type
// passes TrustPrivateCA explicitly, so no existing caller changes behaviour.
type ClientTrust struct {
	// Anchor selects the trust store.
	Anchor TrustAnchor

	// RootCAPath is the PEM pool for TrustPrivateCA and must be empty for
	// TrustWebPKI.
	RootCAPath string
}

// pool resolves the trust anchor to an x509 pool, or to nil for the system
// store, refusing every combination that would leave a peer unverified or a
// device identifier misdirected.
//
// It fails closed in the strict sense: there is no path from a failed private
// -CA load to the system pool. A deployment whose PEM file is missing or
// corrupt gets an error, never an unverified peer and never a silently widened
// trust store.
func (trust ClientTrust) pool(
	hasClientCertificate bool, serverName string,
) (*x509.CertPool, error) {
	switch trust.Anchor {
	case TrustPrivateCA:
		if strings.TrimSpace(trust.RootCAPath) == "" {
			return nil, ErrTrustRootCARequired
		}
		pool, err := loadCertPool(trust.RootCAPath)
		if err != nil {
			return nil, fmt.Errorf("load server CA: %w", err)
		}
		return pool, nil
	case TrustWebPKI:
		if strings.TrimSpace(trust.RootCAPath) != "" {
			return nil, ErrTrustRootCAConflict
		}
		normalized := NormalizeServerName(serverName)
		if normalized == "" {
			return nil, ErrTrustServerNameRequired
		}
		if !isFrontingDomain(normalized) {
			return nil, fmt.Errorf("%w (got %q)",
				ErrTrustServerNameNotADomain, normalized)
		}
		if hasClientCertificate {
			return nil, ErrTrustWebPKIWithClientCertificate
		}
		// nil means the host's system pool. InsecureSkipVerify stays false and
		// the chain is still verified against ServerName; see the type comment
		// for why the public WebPKI is an acceptable anchor on this carrier
		// and would not be on a client whose only peer authentication it was.
		return nil, nil
	default:
		return nil, fmt.Errorf("%w (got %q)", ErrTrustAnchorUnknown, trust.Anchor)
	}
}

// isFrontingDomain reports whether a normalized server name is a DNS name that
// a public CA could plausibly have issued for.
//
// It is deliberately a shape check and not a public-suffix check: this package
// has no business deciding which domains are legitimate, only that the operator
// named a domain rather than an address or a URL fragment. NormalizeServerName
// has already stripped a port and a trailing dot, but it leaves ":443" intact
// (net.SplitHostPort yields an empty host, which it declines to substitute), so
// the colon test below is load-bearing rather than defensive.
func isFrontingDomain(name string) bool {
	if net.ParseIP(name) != nil {
		return false
	}
	if strings.ContainsAny(name, ":/\\ \t") {
		return false
	}
	// A bare label ("localhost") is legitimate in a lab and refused here only
	// when it could not be a public name; requiring a dot is the cheapest form
	// of that, and a fronting domain always has one.
	if !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return false
		}
	}
	return true
}

// ClientAnonymousTrusted is ClientAnonymousForALPN with the trust anchor stated
// rather than assumed. It is the only constructor that can produce a
// CDN-frontable client, and it is anonymous-only by construction because
// ErrTrustWebPKIWithClientCertificate refuses the other combination.
func ClientAnonymousTrusted(trust ClientTrust, serverName string, suite Suite, alpn ...string) (*tls.Config, error) {
	return clientTrusted(trust, serverName, suite, nil, alpn...)
}

func Client(certPath, keyPath, rootCAPath, serverName string, suite Suite) (*tls.Config, error) {
	return ClientForALPN(certPath, keyPath, rootCAPath, serverName, suite, "http/1.1")
}

func ClientForALPN(certPath, keyPath, rootCAPath, serverName string, suite Suite, alpn ...string) (*tls.Config, error) {
	if err := validatePublicFile(certPath); err != nil {
		return nil, err
	}
	if err := validatePrivateKeyFile(keyPath); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load device key pair: %w", err)
	}
	return clientForALPN(
		rootCAPath, serverName, suite, []tls.Certificate{certificate}, alpn...,
	)
}

// ClientAnonymousForALPN omits stable device certificates. Carrier
// authorization is supplied by a one-time blind token and its committed
// ephemeral ML-DSA key.
func ClientAnonymousForALPN(rootCAPath, serverName string, suite Suite, alpn ...string) (*tls.Config, error) {
	return clientForALPN(rootCAPath, serverName, suite, nil, alpn...)
}

// goDefaultCurveOrder mirrors crypto/tls defaultCurvePreferences() as of Go
// 1.26 (crypto/tls/defaults.go). It is duplicated here because the order is
// load-bearing and the standard library does not export it.
//
// Config.CurvePreferences is a *filter*, not an ordering: crypto/tls starts
// from this list and deletes anything the caller did not name
// (crypto/tls/common.go, Config.curvePreferences). A client therefore cannot
// choose the order its supported_groups appear in, and cannot choose which
// group carries the key share - crypto/tls always sends a key share for the
// first surviving entry. Both facts constrain everything below.
var goDefaultCurveOrder = []tls.CurveID{
	tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024,
	tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
}

// ClientCurvePreferences returns the named groups a Winn client offers for a
// suite: the widest set crypto/tls will still key-share with the required
// group.
//
// A one-element supported_groups list is a first-flight identifier. Real
// clients advertise a spread of groups; a ClientHello naming exactly one - and
// a post-quantum one at that - matches essentially nothing else on the wire, so
// a censor can select the connection from the passive stream alone, before any
// probing. Widening the list removes that selector.
//
// The widening is bounded by two constraints, in this order:
//
//   - The required group must remain first, because crypto/tls sends a key
//     share only for the first entry. If a group Winn does not use sorted
//     ahead of the required one, every connection would draw a
//     HelloRetryRequest - a second round trip that is itself rare enough on
//     the modern web to be a stronger signature than the narrow group list it
//     replaced. So every group ahead of the required one is dropped.
//   - Offering a group is not accepting it. The negotiated group is still
//     re-verified against the suite, in-handshake, by the VerifyConnection
//     this package installs, and again post-handshake by ValidateState. A
//     server that answers with any other group - including one this list now
//     advertises - is refused before the client sends its certificate.
//
// For x25519-mlkem768 the result is byte-identical to the supported_groups and
// key_share a default-configured Go client sends. For the two SecP suites it
// cannot be: dropping X25519MLKEM768 to keep the key share correct leaves a
// post-quantum client that does not offer the one post-quantum group everything
// else offers, which is its own signature. See docs/CLIENT_TLS_FINGERPRINT.md.
func ClientCurvePreferences(suite Suite) []tls.CurveID {
	required := slices.Index(goDefaultCurveOrder, suite.Curve)
	if required < 0 {
		// An unknown suite gets the old, narrow behaviour rather than a list
		// that would silently provoke a HelloRetryRequest.
		return []tls.CurveID{suite.Curve}
	}
	return append([]tls.CurveID(nil), goDefaultCurveOrder[required:]...)
}

// ValidateKeyAgreement re-verifies that the peer negotiated exactly the
// suite's key agreement, and nothing else.
//
// This is the enforcement half of ClientCurvePreferences and must stay wired to
// it. Before the offer was widened, an unwanted group was refused by crypto/tls
// itself, because it was never advertised. Now that several groups are
// advertised, that refusal has to be explicit, and it has to happen at the same
// point in the handshake it used to: installed as VerifyConnection, this runs
// while the server's Certificate is being processed, which crypto/tls does
// before it sends the client's own certificate
// (crypto/tls/handshake_client_tls13.go: readServerCertificate precedes
// sendClientCertificate). A downgraded connection is therefore torn down before
// the client authenticates and before any application data exists.
func ValidateKeyAgreement(state *tls.ConnectionState, suite Suite) error {
	if state == nil {
		return fmt.Errorf("TLS is required")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("negotiated TLS version %x, require TLS 1.3", state.Version)
	}
	if state.CurveID != suite.Curve {
		return fmt.Errorf(
			"negotiated key exchange %s (%d), require %s",
			state.CurveID, state.CurveID, suite.Curve,
		)
	}
	return nil
}

func clientForALPN(rootCAPath, serverName string, suite Suite, certificates []tls.Certificate, alpn ...string) (*tls.Config, error) {
	return clientTrusted(
		ClientTrust{Anchor: TrustPrivateCA, RootCAPath: rootCAPath},
		serverName, suite, certificates, alpn...,
	)
}

func clientTrusted(trust ClientTrust, serverName string, suite Suite, certificates []tls.Certificate, alpn ...string) (*tls.Config, error) {
	if err := validateALPN(alpn); err != nil {
		return nil, err
	}
	rootCAs, err := trust.pool(len(certificates) > 0, serverName)
	if err != nil {
		return nil, err
	}
	if trust.Anchor == TrustWebPKI {
		// pool validated the normalized name; SNI and certificate matching
		// must use that same name, never a "host:port" spelling.
		serverName = NormalizeServerName(serverName)
	}
	return &tls.Config{
		Certificates: append([]tls.Certificate(nil), certificates...),
		// nil is the SYSTEM pool and is reached only through TrustWebPKI,
		// which trust.pool grants deliberately and never as a fallback: a
		// private-CA anchor whose PEM will not load returns the error instead.
		RootCAs:          rootCAs,
		ServerName:       serverName,
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: ClientCurvePreferences(suite),
		// Inseparable from the line above: the widened offer is only safe
		// because this refuses everything it advertises but does not want.
		// Callers that chain their own VerifyConnection must chain, not
		// replace.
		VerifyConnection: func(state tls.ConnectionState) error {
			return ValidateKeyAgreement(&state, suite)
		},
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
		NextProtos:             append([]string(nil), alpn...),
	}, nil
}

func ValidateState(state *tls.ConnectionState, suite Suite) error {
	return ValidateStateForALPN(state, suite, "http/1.1")
}

func ValidateStateForALPN(state *tls.ConnectionState, suite Suite, alpn ...string) error {
	return validateState(state, suite, true, alpn...)
}

// ValidatePeerProfile is suitable for tls.Config.VerifyConnection, whose
// ConnectionState is authenticated but not yet marked HandshakeComplete.
func ValidatePeerProfile(state *tls.ConnectionState, suite Suite, alpn ...string) error {
	return validateState(state, suite, false, alpn...)
}

func validateState(state *tls.ConnectionState, suite Suite, requireComplete bool, alpn ...string) error {
	if err := validateALPN(alpn); err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("TLS is required")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("negotiated TLS version %x, require TLS 1.3", state.Version)
	}
	if state.CurveID != suite.Curve {
		return fmt.Errorf("negotiated key exchange %s (%d), require %s", state.CurveID, state.CurveID, suite.Curve)
	}
	if requireComplete && !state.HandshakeComplete {
		return fmt.Errorf("TLS handshake is incomplete")
	}
	var matched bool
	for _, expected := range alpn {
		if state.NegotiatedProtocol == expected {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("negotiated ALPN %q, require one of %v", state.NegotiatedProtocol, alpn)
	}
	return nil
}

func validateALPN(alpn []string) error {
	if len(alpn) == 0 {
		return fmt.Errorf("at least one ALPN protocol is required")
	}
	for _, protocol := range alpn {
		if protocol == "" {
			return fmt.Errorf("ALPN protocol must not be empty")
		}
	}
	return nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pemData, err := securefile.ReadPublicIntegrity(path, 16<<20)
	if err != nil {
		return nil, err
	}
	defer clear(pemData)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func validatePrivateKeyFile(path string) error {
	data, err := securefile.ReadPrivateLimited(path, 1<<20)
	if err != nil {
		return fmt.Errorf("validate private key file: %w", err)
	}
	clear(data)
	return nil
}

func validatePublicFile(path string) error {
	data, err := securefile.ReadPublicIntegrity(path, 16<<20)
	if err != nil {
		return fmt.Errorf("validate public certificate file: %w", err)
	}
	clear(data)
	return nil
}
