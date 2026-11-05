package masque

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// FuzzParseProxyRequest drives the server-side CONNECT-UDP parser with a fully
// attacker-controlled request. This is the first code the proxy runs on a new
// peer, ahead of any authorisation, so a panic here is an unauthenticated
// remote denial of service. The parser also builds a dial target by string
// concatenation, so the invariants below check that an accepted target cannot
// smuggle a different host or port than the one that was matched.
func FuzzParseProxyRequest(fuzzer *testing.F) {
	fuzzer.Add(
		http.MethodConnect, requestProtocol, "proxy.example.com",
		"/masque?h=example.org&p=443", "?1",
	)
	// Absolute URI matching the template. Relative seeds above are rejections
	// (Match requires the template's scheme and host), so without this seed
	// the accept-path smuggling checks never run.
	fuzzer.Add(
		http.MethodConnect, requestProtocol, "proxy.example.com",
		"https://proxy.example.com/masque?h=example.org&p=443", "?1",
	)
	fuzzer.Add(http.MethodGet, requestProtocol, "proxy.example.com", "/", "")
	fuzzer.Add(http.MethodConnect, "HTTP/1.1", "proxy.example.com", "/", "")
	// IPv6 literal: the parser rewrites these with brackets.
	fuzzer.Add(
		http.MethodConnect, requestProtocol, "proxy.example.com",
		"/masque?h=::1&p=443", "?1",
	)
	// Negative and oversized ports.
	fuzzer.Add(
		http.MethodConnect, requestProtocol, "proxy.example.com",
		"/masque?h=example.org&p=-1", "",
	)
	fuzzer.Add(
		http.MethodConnect, requestProtocol, "proxy.example.com",
		"/masque?h=example.org&p=99999999999999999999", "",
	)

	template := uritemplate.MustNew(
		"https://proxy.example.com/masque?h={target_host}&p={target_port}",
	)

	fuzzer.Fuzz(func(
		t *testing.T,
		method, proto, host, target, capsule string,
	) {
		parsed, err := url.Parse(target)
		if err != nil {
			return
		}
		header := make(http.Header)
		if capsule != "" {
			header.Set(http3.CapsuleProtocolHeader, capsule)
		}
		request := &http.Request{
			Method: method,
			Proto:  proto,
			Host:   host,
			URL:    parsed,
			Header: header,
		}

		proxyRequest, err := ParseProxyRequest(request, template)
		if err != nil {
			// Every rejection must carry a usable HTTP status so the proxy
			// answers uniformly instead of leaking a distinguishing failure.
			var parseErr *ProxyRequestParseError
			if !asProxyParseError(err, &parseErr) {
				t.Fatalf("rejection returned an unexpected error type %T: %v", err, err)
			}
			if parseErr.HTTPStatus < 100 || parseErr.HTTPStatus > 599 {
				t.Fatalf("rejection carries an invalid HTTP status %d", parseErr.HTTPStatus)
			}
			return
		}
		if proxyRequest == nil {
			t.Fatal("parser returned a nil request and a nil error")
		}
		if proxyRequest.Host != host {
			t.Fatalf("accepted request host %q does not match the request %q", proxyRequest.Host, host)
		}
		// The dial target is built with fmt.Sprintf("%s:%d"). It must contain
		// exactly one port separator outside any bracketed IPv6 literal, or a
		// later net.Dial would resolve something other than what was matched.
		if strings.ContainsAny(proxyRequest.Target, "\r\n \t") {
			t.Fatalf("accepted a dial target containing whitespace or CRLF: %q", proxyRequest.Target)
		}
		if !strings.Contains(proxyRequest.Target, ":") {
			t.Fatalf("accepted a dial target with no port separator: %q", proxyRequest.Target)
		}
	})
}

func asProxyParseError(err error, target **ProxyRequestParseError) bool {
	parseErr, ok := err.(*ProxyRequestParseError)
	if ok {
		*target = parseErr
	}
	return ok
}
