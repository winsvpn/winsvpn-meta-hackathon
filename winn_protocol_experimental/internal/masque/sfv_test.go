package masque

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// TestUnmarshalItemSafelyRecoversUpstreamPanic locks the wrapper against the
// httpsfv v1.1.0 index-out-of-range panic. Each value ends with the RFC 9651
// Date marker '@', which drives parseNumber past the end of the scanner buffer.
// These inputs were found by FuzzParseProxyRequest.
func TestUnmarshalItemSafelyRecoversUpstreamPanic(t *testing.T) {
	for _, value := range []string{
		"@",
		"1;a=@",
		"a;b=@",
		"?1;x=@",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := unmarshalItemSafely([]string{value})
			if err == nil {
				t.Fatalf("expected %q to be rejected", value)
			}
			if !errors.Is(err, ErrStructuredFieldPanic) {
				// A future httpsfv release may return a normal parse error
				// instead of panicking. That is still a pass: the requirement
				// is that the value is rejected without crashing.
				t.Logf("value rejected without a panic: %v", err)
			}
		})
	}
}

// TestUnmarshalItemSafelyPreservesValidParses confirms the wrapper is
// transparent for well-formed values, so hardening did not change behaviour on
// the normal path.
func TestUnmarshalItemSafelyPreservesValidParses(t *testing.T) {
	item, err := unmarshalItemSafely([]string{"?1"})
	if err != nil {
		t.Fatalf("valid capsule protocol value was rejected: %v", err)
	}
	value, ok := item.Value.(bool)
	if !ok || !value {
		t.Fatalf("expected the boolean true, got %#v", item.Value)
	}

	dated, err := unmarshalItemSafely([]string{"@1700000000"})
	if err != nil {
		t.Fatalf("valid date value was rejected: %v", err)
	}
	if dated.Value == nil {
		t.Fatal("expected a parsed date value")
	}
}

// TestParseProxyRequestSurvivesMalformedCapsuleHeader is the end-to-end
// regression for the crasher: an unauthenticated CONNECT-UDP request whose
// Capsule-Protocol header ends in '@' must be rejected with a 400, not panic
// the proxy.
func TestParseProxyRequestSurvivesMalformedCapsuleHeader(t *testing.T) {
	template := uritemplate.MustNew(
		"https://proxy.example.com/masque?h={target_host}&p={target_port}",
	)
	target, err := url.Parse("/masque?h=example.org&p=443")
	if err != nil {
		t.Fatal(err)
	}
	header := make(http.Header)
	header.Set(http3.CapsuleProtocolHeader, "@")

	request := &http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   "proxy.example.com",
		URL:    target,
		Header: header,
	}

	_, err = ParseProxyRequest(request, template)
	if err == nil {
		t.Fatal("expected the malformed capsule header to be rejected")
	}
	var parseErr *ProxyRequestParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected a ProxyRequestParseError, got %T", err)
	}
	if parseErr.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", parseErr.HTTPStatus)
	}
}

// TestNextHopAddrSurvivesMalformedProxyStatus covers the client-side call site.
// A hostile or tampered proxy response must not be able to crash the user's
// client, which under Winn's threat model would be both a denial of service and
// a fingerprint.
func TestNextHopAddrSurvivesMalformedProxyStatus(t *testing.T) {
	for _, value := range []string{"@", "proxy;next-hop=@"} {
		response := &http.Response{Header: make(http.Header)}
		response.Header.Set("Proxy-Status", value)
		if addr := nextHopAddr(response); addr != nil {
			t.Fatalf("expected no next hop from %q, got %v", value, addr)
		}
	}
}
