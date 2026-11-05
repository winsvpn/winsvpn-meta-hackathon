package carrierauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// fuzzHeaderNames is the full set of claim headers a peer can set. The verifier
// reads each one before any signature is checked, so all of them are reachable
// with zero authentication.
var fuzzHeaderNames = []string{
	HeaderVersion, HeaderCarrier, HeaderDeviceID, HeaderSessionID,
	HeaderSequenceEpoch, HeaderTimestamp, HeaderNonce, HeaderTarget,
	HeaderSuite, HeaderAuthMode, HeaderManifest, HeaderMaxDatagram,
	HeaderPrivacy, HeaderPurpose, HeaderControllerID, HeaderAuthAlgorithm,
	HeaderAuthKeyID, HeaderSignature,
}

// FuzzRequestClaimsFromHeaders drives the unauthenticated header parsing path.
// requestClaimsFromHeaders and validateRequestClaims both run before any ML-DSA
// signature verification, so a panic or an accepted-but-malformed claim here is
// reachable by any peer that can open a connection. The existing
// FuzzSignatureHeader target covers only the single signature header; this one
// covers the whole claim set plus the request line fields.
func FuzzRequestClaimsFromHeaders(fuzzer *testing.F) {
	fuzzer.Add("GET", "example.com", "/", "", "")
	fuzzer.Add("CONNECT", "", "", "", "")
	fuzzer.Add("POST", "example.com", "/winn", "3", "direct-udp")
	fuzzer.Add("GET", "example.com\r\nX-Inject: 1", "/", "3", "h3")
	fuzzer.Add("GET", "example.com", "/", strings.Repeat("9", 64), "h2")

	fuzzer.Fuzz(func(
		t *testing.T,
		method, host, target, headerValue, carrier string,
	) {
		parsed, err := url.Parse(target)
		if err != nil {
			return
		}
		header := make(http.Header)
		for _, name := range fuzzHeaderNames {
			header.Set(name, headerValue)
		}
		header.Set(HeaderCarrier, carrier)
		request := &http.Request{
			Method: method,
			Host:   host,
			URL:    parsed,
			Header: header,
		}

		claims, signature, err := requestClaimsFromHeaders(request)
		if err != nil {
			return
		}
		if len(signature) == 0 {
			t.Fatal("header parsing returned an empty signature without an error")
		}
		if err := validateRequestClaims(claims); err != nil {
			return
		}

		// Accepted claims are about to be canonicalised and fed to signature
		// verification. Header injection through the request-line fields would
		// let a peer forge a different canonical form than the one it signed.
		for _, field := range []string{
			claims.Method, claims.Authority, claims.RequestTarget,
			claims.Carrier, claims.DeviceID, claims.SessionID,
		} {
			if strings.ContainsAny(field, "\r\n") {
				t.Fatalf("validated claims retain a CR or LF: %q", field)
			}
		}
		if claims.MaxDatagram < 576 || claims.MaxDatagram > 1500 {
			t.Fatalf("validated claims carry an out-of-range MTU: %d", claims.MaxDatagram)
		}
		if len(claims.Manifest) != 64 {
			t.Fatalf("validated claims carry a %d character manifest digest", len(claims.Manifest))
		}
		// Canonicalisation must not fail on anything validation accepted.
		if _, err := canonical(claims); err != nil {
			t.Fatalf("validated claims failed to canonicalise: %v", err)
		}
	})
}

// FuzzResponseClaimsFromHeaders is the client-side mirror. A hostile or
// tampered server response reaches this parser before its signature is
// verified, so a client crash here is a remote denial of service against the
// user, and a distinguishable crash is a fingerprint.
func FuzzResponseClaimsFromHeaders(fuzzer *testing.F) {
	fuzzer.Add(200, "")
	fuzzer.Add(599, "AA")
	fuzzer.Add(0, strings.Repeat("A", 1024))
	fuzzer.Add(-1, "%%%%")

	fuzzer.Fuzz(func(t *testing.T, status int, headerValue string) {
		header := make(http.Header)
		for _, name := range fuzzHeaderNames {
			header.Set(name, headerValue)
		}

		claims, signature, err := responseClaimsFromHeaders(header, status)
		if err != nil {
			return
		}
		if len(signature) == 0 {
			t.Fatal("header parsing returned an empty signature without an error")
		}
		if err := validateResponseClaims(claims); err != nil {
			return
		}
		if claims.Status < 200 || claims.Status > 299 {
			t.Fatalf("validated response claims carry status %d", claims.Status)
		}
		if claims.MaxDatagram < 576 || claims.MaxDatagram > 1500 {
			t.Fatalf("validated response claims carry an out-of-range MTU: %d", claims.MaxDatagram)
		}
		if _, err := canonical(claims); err != nil {
			t.Fatalf("validated response claims failed to canonicalise: %v", err)
		}
	})
}

// FuzzParseTimestamp isolates the timestamp parser. It runs on unauthenticated
// input and feeds time arithmetic, so an accepted extreme value can propagate
// into skew comparisons.
func FuzzParseTimestamp(fuzzer *testing.F) {
	fuzzer.Add("0")
	fuzzer.Add("1700000000000")
	fuzzer.Add("99999999999999999999")
	fuzzer.Add("-1")
	fuzzer.Add("+1")

	fuzzer.Fuzz(func(t *testing.T, value string) {
		parsed, err := parseTimestamp(value)
		if err != nil {
			return
		}
		if parsed.IsZero() {
			t.Fatalf("accepted %q as a zero timestamp", value)
		}
		if len(value) > 20 {
			t.Fatalf("accepted an over-long timestamp: %d characters", len(value))
		}
	})
}
