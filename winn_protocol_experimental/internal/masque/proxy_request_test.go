package masque

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/yosida95/uritemplate/v3"
)

func TestParseProxyRequestRoundTripNewRequest(t *testing.T) {
	template := uritemplate.MustNew(
		"https://proxy.example.com/masque?h={target_host}&p={target_port}",
	)
	built, err := NewRequest(context.Background(), template, "example.org:443")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	got, err := ParseProxyRequest(built.req, template)
	if err != nil {
		t.Fatalf("ParseProxyRequest rejected a NewRequest: %v", err)
	}
	if got.Target != "example.org:443" {
		t.Fatalf("Target = %q, want example.org:443", got.Target)
	}
	if got.Host != "proxy.example.com" {
		t.Fatalf("Host = %q, want proxy.example.com", got.Host)
	}
}

func TestParseProxyRequestRoundTripLiveTemplateShape(t *testing.T) {
	template := uritemplate.MustNew(
		"https://cover.example/.well-known/masque/udp/{target_host}/{target_port}/",
	)
	built, err := NewRequest(context.Background(), template, "winn.invalid:443")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	got, err := ParseProxyRequest(built.req, template)
	if err != nil {
		t.Fatalf("ParseProxyRequest rejected live template shape: %v", err)
	}
	if got.Target != "winn.invalid:443" {
		t.Fatalf("Target = %q, want winn.invalid:443", got.Target)
	}
}

// quic-go v0.63.0 and newer leave URL.Scheme and URL.Host empty on server
// requests, so a path-and-query URL is the normal server shape and must be
// accepted. What the parser still has to refuse is a request whose :authority,
// path, or (when present) URL scheme or host disagree with the template.
func TestParseProxyRequestServerShape(t *testing.T) {
	template := uritemplate.MustNew(
		"https://proxy.example.com/masque?h={target_host}&p={target_port}",
	)
	serverReq := func(host, target string) *http.Request {
		parsed, err := url.ParseRequestURI(target)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{
			Method: http.MethodConnect,
			Proto:  requestProtocol,
			Host:   host,
			URL:    parsed,
			Header: make(http.Header),
		}
	}
	plain := serverReq("proxy.example.com", "/masque?h=example.org&p=443")
	got, err := ParseProxyRequest(plain, template)
	if err != nil {
		t.Fatalf("server-shaped request rejected: %v", err)
	}
	if got.Target != "example.org:443" || got.Host != "proxy.example.com" {
		t.Fatalf("got Target=%q Host=%q", got.Target, got.Host)
	}
	if plain.URL.Scheme != "" || plain.URL.Host != "" {
		t.Fatal("parsing mutated the request URL")
	}
	// The capsule-protocol checks must still run on the server-shaped request.
	for name, value := range map[string]string{
		"false capsule protocol":     "?0",
		"malformed capsule protocol": "@",
	} {
		req := serverReq("proxy.example.com", "/masque?h=example.org&p=443")
		req.Header.Set("Capsule-Protocol", value)
		_, err := ParseProxyRequest(req, template)
		var parseErr *ProxyRequestParseError
		if !errors.As(err, &parseErr) || parseErr.HTTPStatus != http.StatusBadRequest {
			t.Fatalf("%s: err = %v, want a 400 ProxyRequestParseError", name, err)
		}
	}
	absolute := serverReq("proxy.example.com", "/masque?h=example.org&p=443")
	absolute.URL.Scheme, absolute.URL.Host = "https", "proxy.example.com"
	wrongScheme := serverReq("proxy.example.com", "/masque?h=example.org&p=443")
	wrongScheme.URL.Scheme = "http"
	wrongURLHost := serverReq("proxy.example.com", "/masque?h=example.org&p=443")
	wrongURLHost.URL.Host = "other.example.com"
	if _, err := ParseProxyRequest(absolute, template); err != nil {
		t.Fatalf("absolute request URL rejected: %v", err)
	}
	for name, req := range map[string]*http.Request{
		"authority mismatch": serverReq("other.example.com", "/masque?h=example.org&p=443"),
		"path mismatch":      serverReq("proxy.example.com", "/other?h=example.org&p=443"),
		"missing query":      serverReq("proxy.example.com", "/masque"),
		"url scheme":         wrongScheme,
		"url host":           wrongURLHost,
	} {
		_, err := ParseProxyRequest(req, template)
		if err == nil {
			t.Fatalf("%s: request was accepted", name)
		}
		var parseErr *ProxyRequestParseError
		if !errors.As(err, &parseErr) {
			t.Fatalf("%s: error type %T, want ProxyRequestParseError", name, err)
		}
		if parseErr.HTTPStatus != http.StatusBadRequest {
			t.Fatalf("%s: HTTPStatus = %d, want 400", name, parseErr.HTTPStatus)
		}
	}
}
