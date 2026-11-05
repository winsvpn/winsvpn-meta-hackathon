// Package decoy gives a Winn listener a cover origin.
//
// The problem it solves is the one every probe-resistant transport eventually
// has to solve. A censor does not need to break Winn's cryptography to harm
// its users; it only needs to recognise a Winn endpoint. Recognition is
// cheap - one TCP connection - and permanent, because an IP that has been
// identified stays identified. Shadowsocks 2022, Trojan, VLESS-REALITY and
// Hysteria all answer this the same way: an unauthenticated peer is not
// refused, because a refusal is itself the signal. It is served a plausible
// website, and the protocol is reachable only by a peer that has already
// proven it belongs.
//
// This package supplies the website and the gate. It deliberately lives
// outside internal/carrier: the protocol handler keeps its exact current
// behaviour for authenticated clients, and the gate wraps it.
package decoy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Guard routes a request either to the Winn protocol handler or to the cover
// origin. Anything that has not proven it is a Winn client gets the website.
type Guard struct {
	// Winn is the protocol handler. It is reached only by connections that
	// satisfy every element of the Winn profile.
	Winn http.Handler

	// Origin serves the cover website to everything else.
	Origin http.Handler

	// Suite is the hybrid group a genuine Winn connection negotiates.
	Suite tls.CurveID

	// ServerName is the deployment's private ECH-inner SNI. Empty skips the
	// name check.
	ServerName string

	// RequireVerifiedClientCert is set in identity mode, where a genuine
	// client always presents a certificate the server has verified.
	RequireVerifiedClientCert bool

	// Paths are the URL path prefixes the Winn protocol actually uses. A
	// request outside them is cover traffic no matter how it authenticated.
	Paths []string

	// OnDiverted, if set, is called with a coarse reason each time a request
	// is served the cover site instead of the protocol. The reason names the
	// check that failed and never carries anything about the peer, so it is
	// safe to expose as an aggregate counter.
	OnDiverted func(reason string)
}

// Diversion reasons. These are deliberately coarse: an operator needs to know
// how much cover traffic the endpoint is serving and why, without the counter
// becoming a per-peer record.
const (
	ReasonNoTLS           = "no_tls"
	ReasonTLSVersion      = "tls_version"
	ReasonNoECH           = "no_ech"
	ReasonGroup           = "group"
	ReasonServerName      = "server_name"
	ReasonNoClientCert    = "no_verified_client_cert"
	ReasonPathNotProtocol = "path_not_protocol"
	// ReasonNoHandler is a programming error: Guard.Winn was nil. It used to
	// reuse ReasonNoTLS, which made a missing handler look like a probe that
	// never completed TLS.
	ReasonNoHandler = "no_handler"
)

func (g *Guard) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if g.Winn == nil {
		g.divert(writer, request, ReasonNoHandler)
		return
	}
	if reason := g.connectionReason(request); reason != "" {
		g.divert(writer, request, reason)
		return
	}
	if !g.winnPath(request.URL.Path) {
		g.divert(writer, request, ReasonPathNotProtocol)
		return
	}
	g.Winn.ServeHTTP(writer, request)
}

func (g *Guard) divert(writer http.ResponseWriter, request *http.Request, reason string) {
	if g.OnDiverted != nil {
		g.OnDiverted(reason)
	}
	g.serveOrigin(writer, request)
}

// connectionReason re-applies, at the application layer, exactly the profile
// the TLS layer used to select the Winn configuration, and names the first
// check that fails. Checking it twice means a misconfigured or downgraded
// listener cannot quietly expose the protocol handler to an unauthenticated
// peer. It returns "" when the connection is a genuine Winn connection.
func (g *Guard) connectionReason(request *http.Request) string {
	if request == nil || request.TLS == nil {
		return ReasonNoTLS
	}
	state := request.TLS
	if state.Version != tls.VersionTLS13 {
		return ReasonTLSVersion
	}
	if !state.ECHAccepted {
		return ReasonNoECH
	}
	if g.Suite != 0 && state.CurveID != g.Suite {
		return ReasonGroup
	}
	if g.ServerName != "" && !strings.EqualFold(state.ServerName, g.ServerName) {
		return ReasonServerName
	}
	if g.RequireVerifiedClientCert &&
		(len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0) {
		return ReasonNoClientCert
	}
	return ""
}

func (g *Guard) winnPath(path string) bool {
	if len(g.Paths) == 0 {
		return true
	}
	for _, prefix := range g.Paths {
		if prefix == "" {
			continue
		}
		if path == prefix {
			return true
		}
		// strings.HasPrefix(path, prefix) treats "/winn/v2/udp-stream" as a
		// prefix of "/winn/v2/udp-streamer". That sibling then reaches the
		// protocol handler, which answers with its own error envelope — the
		// distinguisher this gate exists to hide. A prefix that already ends
		// in "/" is a directory (MASQUE); otherwise the next byte must be "/".
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (g *Guard) serveOrigin(writer http.ResponseWriter, request *http.Request) {
	if g.Origin == nil {
		http.NotFound(writer, request)
		return
	}
	g.Origin.ServeHTTP(writer, request)
}

// Config describes one deployment's cover origin.
type Config struct {
	// Target is the -decoy-origin flag: an absolute http or https URL to
	// reverse-proxy to unauthenticated peers. Empty serves the built-in site.
	Target string

	// CoverTLS is the listener configuration a prober actually reaches - the
	// one coverlisten.Apply built and coverlisten.Verify passed. The built-in
	// site is derived from the DNS names on the leaf it presents, so it is
	// exactly as linkable as that certificate already is and no more.
	//
	// It is the whole configuration rather than a name string so that a caller
	// cannot accidentally seed the public page from a private value: what goes
	// into the seed is read off the certificate that is handed to every
	// prober, which is public by construction.
	CoverTLS *tls.Config

	// PrivateServerName is the deployment's ECH-inner SNI. It is an exclusion,
	// not an input: it is the one name that must never reach the seed, because
	// on the lab path the cover profile serves the Winn leaf and that leaf's
	// DNS name is this value.
	PrivateServerName string

	// Logf receives operator warnings. Nil discards them.
	Logf func(format string, args ...any)
}

// Origin is a deployment's cover origin: the handler unauthenticated peers
// reach, plus the other bytes this deployment shows an unauthenticated peer.
type Origin struct {
	handler http.Handler
	site    *staticOrigin
}

func (o *Origin) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	o.handler.ServeHTTP(writer, request)
}

// PlaintextBadRequest is the body TLSOnlyListener returns to a cleartext HTTP
// request on the TLS port. It comes from here, and not from a constant in
// listener.go, because it is reachable by the same single unauthenticated
// probe as the website and so has to vary with it.
func (o *Origin) PlaintextBadRequest() []byte {
	return o.site.plaintext
}

// NewOrigin builds the cover website.
//
// An empty target serves a self-contained static site from memory, which is
// the workable default: it needs no upstream, cannot fail open, and does not
// make the gateway emit traffic to a third party. A non-empty target is an
// absolute http or https URL that is reverse-proxied instead, which is the
// stronger option and the one an operator should be reaching for.
//
// The built-in site is generated per deployment (see site.go). That closes the
// exact-match correlator - every default deployment used to serve the same
// bytes and the same ETag - but it does not make the built-in site a good
// disguise, and it is not documented as one. A generated placeholder page
// clusters under structural comparison however carefully its bytes are varied.
// The defence is a real site: -decoy-origin, and something plausible actually
// behind the cover domain.
func NewOrigin(config Config) (*Origin, error) {
	logf := config.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	names := coverNames(config.CoverTLS, config.PrivateServerName)
	seed, derived := deploymentSeed(names)
	if !derived {
		logf(
			"WARNING: the certificate served to unauthenticated peers carries no " +
				"DNS name that is not the private server name, so the built-in cover " +
				"site is seeded from the CSPRNG and its content changes on every " +
				"restart. It still matches no other deployment, but supply a cover " +
				"certificate with a DNS SAN, or -decoy-origin, for a site that is " +
				"stable as well as unlinkable.",
		)
	}
	site := newStaticOrigin(seed)

	target := strings.TrimSpace(config.Target)
	if target == "" {
		logf(
			"NOTICE: no -decoy-origin was supplied, so unauthenticated peers are "+
				"served the built-in cover site. It is generated for this deployment "+
				"(cover name %q), so it does not hash-match any other Winn gateway - "+
				"but it is still a generated placeholder page, and a censor comparing "+
				"page structure rather than bytes can cluster it. Point -decoy-origin "+
				"at a real site and put a real site behind the cover domain.",
			firstName(names),
		)
		return &Origin{handler: site, site: site}, nil
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse decoy origin: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("decoy origin must be an absolute http or https URL")
	}
	if parsed.Host == "" {
		return nil, errors.New("decoy origin must include a host")
	}
	// Rewrite rather than Director: Director is deprecated as of Go 1.26, and
	// ReverseProxy requires exactly one of the two, so the single-host routing
	// NewSingleHostReverseProxy used to install is expressed here instead.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			// SetURL joins the inbound path onto the target's base path, merges
			// the target's query, and rewrites the outbound Host header to the
			// target's host - the same routing NewSingleHostReverseProxy's
			// director performed, including presenting the upstream's own host.
			request.SetURL(parsed)
			// Strip anything that would tell the upstream - or an observer -
			// that the request was relayed, and in particular anything carrying
			// the peer's address. ReverseProxy already drops these before
			// calling Rewrite, and SetXForwarded is deliberately never called;
			// deleting them here keeps that privacy property local and
			// reviewable rather than resting on behaviour a reader must go and
			// confirm elsewhere.
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			// NewSingleHostReverseProxy suppressed Go's default User-Agent when
			// the client sent none. Without this the upstream would instead see
			// "Go-http-client/1.1" on exactly those requests, which is a
			// fingerprint of the decoy in place of the one it exists to hide.
			if _, ok := request.Out.Header["User-Agent"]; !ok {
				request.Out.Header.Set("User-Agent", "")
			}
		},
	}
	proxy.FlushInterval = -1
	proxy.Transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          32,
	}
	// An upstream failure must not become a distinguisher of its own, so fall
	// back to the generated site rather than surfacing a proxy error. It is the
	// same site object the built-in path serves, so a fleet whose upstream goes
	// down does not converge on one body at the moment it goes down.
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, _ error) {
		site.ServeHTTP(writer, request)
	}
	return &Origin{handler: proxy, site: site}, nil
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
