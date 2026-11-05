package decoy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func winnState() *tls.ConnectionState {
	return &tls.ConnectionState{
		Version:        tls.VersionTLS13,
		ECHAccepted:    true,
		CurveID:        tls.X25519MLKEM768,
		ServerName:     "private.example",
		VerifiedChains: [][]*x509.Certificate{{{}}},
	}
}

type spyHandler struct{ called bool }

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.called = true
	w.WriteHeader(http.StatusTeapot)
}

func newGuard(t *testing.T, protocol http.Handler) (*Guard, *string) {
	t.Helper()
	origin, err := NewOrigin(Config{
		CoverTLS:          coverConfig(t, "www.example.test"),
		PrivateServerName: "private.example",
	})
	if err != nil {
		t.Fatalf("NewOrigin: %v", err)
	}
	reason := new(string)
	return &Guard{
		Winn:                      protocol,
		Origin:                    origin,
		Suite:                     tls.X25519MLKEM768,
		ServerName:                "private.example",
		RequireVerifiedClientCert: true,
		Paths:                     []string{"/winn/v2/udp-stream", "/.well-known/masque/udp/"},
		OnDiverted:                func(r string) { *reason = r },
	}, reason
}

// TestGuardDivertsEveryNonWinnConnection is the core contract: a censor gets a
// website, never a protocol error, whatever is wrong with its connection.
func TestGuardDivertsEveryNonWinnConnection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*tls.ConnectionState)
		want   string
	}{
		{"tls 1.2", func(s *tls.ConnectionState) { s.Version = tls.VersionTLS12 }, ReasonTLSVersion},
		{"no ECH", func(s *tls.ConnectionState) { s.ECHAccepted = false }, ReasonNoECH},
		{"wrong group", func(s *tls.ConnectionState) { s.CurveID = tls.X25519 }, ReasonGroup},
		{"wrong server name", func(s *tls.ConnectionState) { s.ServerName = "www.example.com" }, ReasonServerName},
		{"no client cert", func(s *tls.ConnectionState) { s.VerifiedChains = nil }, ReasonNoClientCert},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			protocol := &spyHandler{}
			guard, reason := newGuard(t, protocol)
			request := httptest.NewRequest(http.MethodPost, "/winn/v2/udp-stream", nil)
			state := winnState()
			testCase.mutate(state)
			request.TLS = state
			recorder := httptest.NewRecorder()
			guard.ServeHTTP(recorder, request)

			if protocol.called {
				t.Fatal("protocol handler was reached by a non-Winn connection")
			}
			if *reason != testCase.want {
				t.Fatalf("diversion reason = %q, want %q", *reason, testCase.want)
			}
			// 405 is the ordinary answer a static site gives a POST, so it
			// belongs here alongside 200 and 404. What must never appear is a
			// protocol-specific status such as 401 or 415, which would tell a
			// prober it had found an authenticating endpoint.
			switch recorder.Code {
			case http.StatusOK, http.StatusNotFound, http.StatusMethodNotAllowed:
			default:
				t.Fatalf("status %d; a prober must get an ordinary web response", recorder.Code)
			}
			if !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("content-type %q; a website serves HTML",
					recorder.Header().Get("Content-Type"))
			}
		})
	}
}

func TestGuardPassesGenuineWinnRequest(t *testing.T) {
	protocol := &spyHandler{}
	guard, reason := newGuard(t, protocol)
	request := httptest.NewRequest(http.MethodPost, "/winn/v2/udp-stream", nil)
	request.TLS = winnState()
	recorder := httptest.NewRecorder()
	guard.ServeHTTP(recorder, request)

	if !protocol.called {
		t.Fatalf("genuine Winn request was diverted (%q)", *reason)
	}
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("status %d, want the protocol handler's own response", recorder.Code)
	}
}

func TestGuardDivertsNonProtocolPathsOnWinnConnections(t *testing.T) {
	protocol := &spyHandler{}
	guard, reason := newGuard(t, protocol)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = winnState()
	guard.ServeHTTP(httptest.NewRecorder(), request)

	if protocol.called {
		t.Fatal("protocol handler served a non-protocol path")
	}
	if *reason != ReasonPathNotProtocol {
		t.Fatalf("reason = %q, want %q", *reason, ReasonPathNotProtocol)
	}
}

func TestGuardAcceptsMasquePathPrefix(t *testing.T) {
	protocol := &spyHandler{}
	guard, _ := newGuard(t, protocol)
	request := httptest.NewRequest(http.MethodConnect,
		"/.well-known/masque/udp/192.0.2.1/443/", nil)
	request.TLS = winnState()
	guard.ServeHTTP(httptest.NewRecorder(), request)
	if !protocol.called {
		t.Fatal("MASQUE CONNECT-UDP path was diverted")
	}
}

// TestStaticOriginLooksLikeAWebsite asserts the properties a censor checks:
// HTML, a real 404, and cache validators - not a bare protocol stub.
//
// The paths are read out of the generated page rather than hard-coded, because
// which paths exist is now one of the things that varies per deployment. A
// test that pinned /assets/site.css would be pinning the correlator.
func TestStaticOriginLooksLikeAWebsite(t *testing.T) {
	for _, name := range []string{"www.example.test", "static.example.invalid", "a.b.example"} {
		origin := originFor(t, name)

		for _, testCase := range []struct {
			path       string
			wantStatus int
			wantType   string
		}{
			{"/", http.StatusOK, "text/html"},
			{"/index.html", http.StatusOK, "text/html"},
			{"/does-not-exist", http.StatusNotFound, "text/html"},
		} {
			recorder := get(origin, testCase.path)
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("%s %s: status %d, want %d",
					name, testCase.path, recorder.Code, testCase.wantStatus)
			}
			if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, testCase.wantType) {
				t.Fatalf("%s %s: content-type %q, want %q",
					name, testCase.path, got, testCase.wantType)
			}
			body, _ := io.ReadAll(recorder.Body)
			if len(body) == 0 {
				t.Fatalf("%s %s: empty body", name, testCase.path)
			}
			if recorder.Header().Get("Content-Length") == "" {
				t.Fatalf("%s %s: no Content-Length", name, testCase.path)
			}
		}
		// Whatever stylesheet the page links to has to be there. A dangling
		// stylesheet is a tell that no real site has.
		if path := stylesheetPath(get(origin, "/").Body.String()); path != "" {
			recorder := get(origin, path)
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s: linked stylesheet %s returned %d", name, path, recorder.Code)
			}
			if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/css") {
				t.Fatalf("%s: stylesheet content-type %q", name, got)
			}
		}
		// robots.txt is either published or absent, and both are ordinary.
		robots := get(origin, "/robots.txt")
		switch robots.Code {
		case http.StatusOK:
			if got := robots.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
				t.Fatalf("%s: robots.txt content-type %q", name, got)
			}
		case http.StatusNotFound:
		default:
			t.Fatalf("%s: robots.txt status %d", name, robots.Code)
		}
	}
}

// TestStaticOriginNamesNoRealOrganisation guards against the cover page
// drifting into impersonating somebody. It runs over many generated sites,
// because "no page this generator can produce names anybody" is the property
// that matters now, not "this one page does not".
func TestStaticOriginNamesNoRealOrganisation(t *testing.T) {
	for index := range 200 {
		origin := newStaticOrigin(seedFor(index))
		for _, path := range []string{"/", "/does-not-exist"} {
			body := strings.ToLower(get(origin, path).Body.String())
			for _, forbidden := range []string{"winn", "vpn", "proxy", "tunnel", "carrier"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("seed %d: cover page contains %q, which identifies the service",
						index, forbidden)
				}
			}
		}
		if strings.Contains(strings.ToLower(string(origin.plaintext)), "winn") {
			t.Fatalf("seed %d: cleartext 400 body identifies the service", index)
		}
	}
}

func TestStaticOriginHonoursConditionalGet(t *testing.T) {
	origin := newStaticOrigin(seedFor(1))
	first := get(origin, "/")
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("no ETag on the cover page")
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("If-None-Match", tag)
	second := httptest.NewRecorder()
	origin.ServeHTTP(second, request)
	if second.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: status %d, want 304", second.Code)
	}
	// Last-Modified is advertised, so the other conditional form has to work
	// too: a server that offers a validator and ignores it is unusual enough
	// to be worth noticing.
	modified := first.Header().Get("Last-Modified")
	if modified == "" {
		t.Fatal("no Last-Modified on the cover page")
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("If-Modified-Since", modified)
	third := httptest.NewRecorder()
	origin.ServeHTTP(third, request)
	if third.Code != http.StatusNotModified {
		t.Fatalf("If-Modified-Since: status %d, want 304", third.Code)
	}
}

func TestNewOriginRejectsUnusableTargets(t *testing.T) {
	for _, target := range []string{"ftp://example.com", "not a url", "https://"} {
		if _, err := NewOrigin(Config{Target: target}); err == nil {
			t.Fatalf("NewOrigin(%q) accepted an unusable target", target)
		}
	}
	if _, err := NewOrigin(Config{Target: "https://example.org"}); err != nil {
		t.Fatalf("NewOrigin rejected a valid target: %v", err)
	}
}

func TestGuardWithoutProtocolHandlerStillServesSite(t *testing.T) {
	guard, reason := newGuard(t, nil)
	guard.Winn = nil
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = winnState()
	guard.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d, want a served page", recorder.Code)
	}
	if *reason != ReasonNoHandler {
		t.Fatalf("reason = %q, want %q", *reason, ReasonNoHandler)
	}
}

func TestGuardPathPrefixDoesNotMatchSibling(t *testing.T) {
	protocol := &spyHandler{}
	guard, reason := newGuard(t, protocol)
	request := httptest.NewRequest(http.MethodPost, "/winn/v2/udp-streamer", nil)
	request.TLS = winnState()
	guard.ServeHTTP(httptest.NewRecorder(), request)
	if protocol.called {
		t.Fatal("sibling path /winn/v2/udp-streamer reached the protocol handler")
	}
	if *reason != ReasonPathNotProtocol {
		t.Fatalf("reason = %q, want %q", *reason, ReasonPathNotProtocol)
	}
}

func TestGuardDivertsWhenTLSIsMissing(t *testing.T) {
	protocol := &spyHandler{}
	guard, reason := newGuard(t, protocol)
	request := httptest.NewRequest(http.MethodPost, "/winn/v2/udp-stream", nil)
	request.TLS = nil
	guard.ServeHTTP(httptest.NewRecorder(), request)
	if protocol.called {
		t.Fatal("protocol handler was reached with no TLS")
	}
	if *reason != ReasonNoTLS {
		t.Fatalf("reason = %q, want %q", *reason, ReasonNoTLS)
	}
}
