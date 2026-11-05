package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const testDeviceID = "issuance-device-1"

type stubAudit struct {
	healthy   bool
	recordErr error
	events    []string
}

func (s *stubAudit) Record(event, deviceID, requestID, detail string) error {
	s.events = append(s.events, event)
	return s.recordErr
}

func (s *stubAudit) Healthy() bool { return s.healthy }

type stubLimiter struct {
	allow bool
	retry time.Duration
	keys  []string
}

func (s *stubLimiter) Allow(key string) (bool, time.Duration) {
	s.keys = append(s.keys, key)
	return s.allow, s.retry
}

type stubIssuer struct {
	response privacytoken.IssueResponse
	err      error
	calls    int
	last     privacytoken.IssueRequest
}

func (s *stubIssuer) BlindSign(request privacytoken.IssueRequest) (privacytoken.IssueResponse, error) {
	s.calls++
	s.last = request
	return s.response, s.err
}

type stubAuthorizer struct {
	err   error
	calls int
}

func (s *stubAuthorizer) Verify(request *http.Request, issue privacytoken.IssueRequest, certificateDeviceID string) (privacytoken.IssueAuthorization, error) {
	s.calls++
	return privacytoken.IssueAuthorization{}, s.err
}

type writeFailResponseWriter struct {
	http.ResponseWriter
	code int
}

func (w *writeFailResponseWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *writeFailResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func testSuite(t *testing.T) tlsconfig.Suite {
	t.Helper()
	suite, err := tlsconfig.ParseSuite("x25519-mlkem768")
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

func deviceLeaf(t *testing.T, deviceID string) *x509.Certificate {
	t.Helper()
	uri, err := url.Parse("spiffe://winn.local/device/" + deviceID)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{URIs: []*url.URL{uri}}
}

func winnTLS(t *testing.T, withDevice bool) *tls.ConnectionState {
	t.Helper()
	suite := testSuite(t)
	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CurveID:            suite.Curve,
		HandshakeComplete:  true,
		NegotiatedProtocol: http2.NextProtoTLS,
	}
	if withDevice {
		state.VerifiedChains = [][]*x509.Certificate{{deviceLeaf(t, testDeviceID)}}
	}
	return state
}

func issueJSON() io.Reader {
	return strings.NewReader(
		`{"format":"winn-privacy-token-issue/v1","token_key_id":"k","blinded_message":"YQ=="}`,
	)
}

func postIssue(t *testing.T, body io.Reader) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://issuer.test"+privacytoken.IssuePath, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	request.Header.Set("Content-Type", privacytoken.IssueMediaType)
	request.RemoteAddr = "192.0.2.1:54321"
	request.TLS = winnTLS(t, true)
	return request
}

func handlerForHTTP(t *testing.T) (*issueHandler, *stubAudit, *stubIssuer, *stubAuthorizer, *stubLimiter) {
	t.Helper()
	auditSink := &stubAudit{healthy: true}
	issuer := &stubIssuer{response: privacytoken.IssueResponse{
		Format:         "winn-privacy-token-response/v1",
		TokenKeyID:     "k",
		BlindSignature: "c2ln",
	}}
	authorizer := &stubAuthorizer{}
	limiter := &stubLimiter{allow: true}
	handler := &issueHandler{
		suite:      testSuite(t),
		issuer:     issuer,
		verifier:   authorizer,
		limiter:    limiter,
		audit:      auditSink,
		concurrent: make(chan struct{}, 4),
	}
	return handler, auditSink, issuer, authorizer, limiter
}

func TestRSAIssuerNilKeyReturnsError(t *testing.T) {
	t.Parallel()
	_, err := rsaIssuer{}.BlindSign(privacytoken.IssueRequest{})
	if err == nil {
		t.Fatal("nil issuer key was accepted")
	}
}

func TestMaximumIssueBodyIs32KiB(t *testing.T) {
	if maximumIssueBody != 32<<10 {
		t.Fatalf("maximumIssueBody = %d, want %d", maximumIssueBody, 32<<10)
	}
}

func TestRemoteHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"192.0.2.1:1234", "192.0.2.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"not-a-host-port", "not-a-host-port"},
		{"", ""},
	}
	for _, testCase := range cases {
		if got := remoteHost(testCase.in); got != testCase.want {
			t.Fatalf("remoteHost(%q) = %q, want %q", testCase.in, got, testCase.want)
		}
	}
}

func TestIssueHandlerNilOrUnhealthyAuditReturns503(t *testing.T) {
	t.Parallel()
	handler, _, _, _, _ := handlerForHTTP(t)
	handler.audit = nil
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil audit: got %d, want 503", recorder.Code)
	}

	handler, auditSink, _, _, _ := handlerForHTTP(t)
	auditSink.healthy = false
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy audit: got %d, want 503", recorder.Code)
	}
}

func TestIssueHandlerConcurrentCapReturns503(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	handler.concurrent = make(chan struct{}, 1)
	handler.concurrent <- struct{}{}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called %d times at cap, want 0", issuer.calls)
	}
}

func TestIssueHandlerWrongMethodPathOrQueryReturns404(t *testing.T) {
	t.Parallel()
	cases := []*http.Request{
		func() *http.Request {
			request := postIssue(t, issueJSON())
			request.Method = http.MethodGet
			return request
		}(),
		func() *http.Request {
			request, err := http.NewRequest(http.MethodPost, "https://issuer.test/not-the-issue-path", issueJSON())
			if err != nil {
				t.Fatal(err)
			}
			request.ProtoMajor = 2
			request.Header.Set("Content-Type", privacytoken.IssueMediaType)
			request.TLS = winnTLS(t, true)
			return request
		}(),
		func() *http.Request {
			request, err := http.NewRequest(http.MethodPost, "https://issuer.test"+privacytoken.IssuePath+"?x=1", issueJSON())
			if err != nil {
				t.Fatal(err)
			}
			request.ProtoMajor = 2
			request.Header.Set("Content-Type", privacytoken.IssueMediaType)
			request.TLS = winnTLS(t, true)
			return request
		}(),
	}
	for i, request := range cases {
		handler, _, issuer, _, _ := handlerForHTTP(t)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("case %d: got %d, want 404", i, recorder.Code)
		}
		if issuer.calls != 0 {
			t.Fatalf("case %d: BlindSign called", i)
		}
	}
}

func TestIssueHandlerHTTP1WrongTypeOrEncodingReturns415(t *testing.T) {
	t.Parallel()
	makeRequest := func(mutate func(*http.Request)) *http.Request {
		request := postIssue(t, issueJSON())
		mutate(request)
		return request
	}
	cases := []*http.Request{
		makeRequest(func(request *http.Request) {
			request.ProtoMajor = 1
			request.Proto = "HTTP/1.1"
		}),
		makeRequest(func(request *http.Request) {
			request.Header.Set("Content-Type", "application/json")
		}),
		makeRequest(func(request *http.Request) {
			request.Header.Set("Content-Encoding", "gzip")
		}),
	}
	for i, request := range cases {
		handler, _, issuer, _, _ := handlerForHTTP(t)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("case %d: got %d, want 415", i, recorder.Code)
		}
		if issuer.calls != 0 {
			t.Fatalf("case %d: BlindSign called", i)
		}
	}
}

func TestIssueHandlerInvalidTLSReturns426(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	request := postIssue(t, issueJSON())
	request.TLS = nil
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUpgradeRequired {
		t.Fatalf("got %d, want 426", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called")
	}
}

func TestIssueHandlerMissingDeviceIDReturns401(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	request := postIssue(t, issueJSON())
	request.TLS = winnTLS(t, false)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called")
	}
}

func TestIssueHandlerRateLimitReturns429(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, limiter := handlerForHTTP(t)
	limiter.allow = false
	limiter.retry = 7 * time.Second
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", recorder.Code)
	}
	if recorder.Header().Get("Retry-After") != "7" {
		t.Fatalf("Retry-After = %q, want 7", recorder.Header().Get("Retry-After"))
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called")
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != testDeviceID+"|192.0.2.1" {
		t.Fatalf("limiter keys = %#v", limiter.keys)
	}
}

func TestIssueHandlerOversizedBodyReturns400(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	body := bytes.Repeat([]byte("a"), maximumIssueBody+1)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called")
	}
}

func TestIssueHandlerUnknownJSONFieldReturns400(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, strings.NewReader(
		`{"format":"winn-privacy-token-issue/v1","token_key_id":"k","blinded_message":"YQ==","extra":true}`,
	)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called")
	}
}

func TestIssueHandlerTrailingJSONReturns400(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, strings.NewReader(
		`{"format":"winn-privacy-token-issue/v1","token_key_id":"k","blinded_message":"YQ=="}{"x":1}`,
	)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called")
	}
}

func TestIssueHandlerVerifyFailureReturns401AndDoesNotSign(t *testing.T) {
	t.Parallel()
	handler, auditSink, issuer, authorizer, _ := handlerForHTTP(t)
	authorizer.err = errors.New("replayed nonce")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", recorder.Code)
	}
	if issuer.calls != 0 {
		t.Fatalf("BlindSign called after Verify failure")
	}
	if authorizer.calls != 1 {
		t.Fatalf("Verify calls = %d, want 1", authorizer.calls)
	}
	for _, event := range auditSink.events {
		if event == "privacy_token_issued" {
			t.Fatal("audited issuance after Verify failure")
		}
	}
}

func TestIssueHandlerBlindSignErrorReturns400(t *testing.T) {
	t.Parallel()
	handler, _, issuer, _, _ := handlerForHTTP(t)
	issuer.err = errors.New("invalid blinded privacy token request")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", recorder.Code)
	}
	if issuer.calls != 1 {
		t.Fatalf("BlindSign calls = %d, want 1", issuer.calls)
	}
}

func TestIssueHandlerAuditRecordFailureReturns503WithoutToken(t *testing.T) {
	t.Parallel()
	handler, auditSink, issuer, _, _ := handlerForHTTP(t)
	auditSink.recordErr = errors.New("audit disk full")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", recorder.Code)
	}
	if issuer.calls != 1 {
		t.Fatalf("BlindSign calls = %d, want 1", issuer.calls)
	}
	if strings.Contains(recorder.Body.String(), "c2ln") {
		t.Fatalf("token body leaked after audit failure: %q", recorder.Body.String())
	}
}

func TestIssueHandlerSuccessWritesToken(t *testing.T) {
	t.Parallel()
	handler, auditSink, issuer, authorizer, _ := handlerForHTTP(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, postIssue(t, issueJSON()))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d %q, want 200", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Type") != privacytoken.IssueMediaType {
		t.Fatalf("Content-Type = %q", recorder.Header().Get("Content-Type"))
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
	var response privacytoken.IssueResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.BlindSignature != "c2ln" || response.TokenKeyID != "k" {
		t.Fatalf("response = %#v", response)
	}
	if issuer.calls != 1 || authorizer.calls != 1 {
		t.Fatalf("issuer=%d authorizer=%d", issuer.calls, authorizer.calls)
	}
	if len(auditSink.events) != 1 || auditSink.events[0] != "privacy_token_issued" {
		t.Fatalf("audit events = %#v", auditSink.events)
	}
}

func TestIssueHandlerWriteFailureIsLogged(t *testing.T) {
	handler, auditSink, _, _, _ := handlerForHTTP(t)
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	recorder := httptest.NewRecorder()
	writer := &writeFailResponseWriter{ResponseWriter: recorder}
	handler.ServeHTTP(writer, postIssue(t, issueJSON()))
	if writer.code != http.StatusOK {
		t.Fatalf("WriteHeader code = %d, want 200", writer.code)
	}
	if !strings.Contains(logs.String(), "privacy-token issue response write failed") {
		t.Fatalf("write failure was silent; logs = %q", logs.String())
	}
	if len(auditSink.events) != 1 || auditSink.events[0] != "privacy_token_issued" {
		t.Fatalf("audit events = %#v", auditSink.events)
	}
}
