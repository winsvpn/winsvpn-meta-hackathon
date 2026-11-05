package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connlimit"
	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/decoy"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/identity"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const maximumIssueBody = 32 << 10

type issueHandler struct {
	suite      tlsconfig.Suite
	issuer     privacyIssuer
	verifier   issueAuthorizer
	limiter    ratelimit.Limiter
	audit      audit.Sink
	concurrent chan struct{}
}

type privacyIssuer interface {
	BlindSign(privacytoken.IssueRequest) (privacytoken.IssueResponse, error)
}

type issueAuthorizer interface {
	Verify(request *http.Request, issue privacytoken.IssueRequest, certificateDeviceID string) (privacytoken.IssueAuthorization, error)
}

type rsaIssuer struct {
	key *rsa.PrivateKey
}

func (issuer rsaIssuer) BlindSign(request privacytoken.IssueRequest) (privacytoken.IssueResponse, error) {
	return privacytoken.BlindSign(request, issuer.key)
}

func main() {
	var address string
	var certPath string
	var keyPath string
	var clientCAPath string
	var registryPath string
	var issuerKeyPath string
	var echKeysPath string
	var auditLogPath string
	var auditKeyPath string
	var suiteName string
	var replayLimit int
	var rateBurst int
	var ratePerMinute float64
	var rateMaxKeys int
	var maxConcurrent int
	var maxPreAuthConnections int
	var maxPreAuthConnectionsPerIP int
	var decoyOriginTarget string
	var coverServerName string
	var coverCertPath string
	var coverKeyPath string
	var allowWinnLeafAsCover bool
	var allowIdentifyingCover bool
	var allowImplausibleCover bool
	flag.StringVar(&address, "addr", ":9444", "HTTPS token-issuer listen address")
	flag.StringVar(&certPath, "cert", "", "issuer server certificate PEM")
	flag.StringVar(&keyPath, "key", "", "issuer server private key PEM")
	flag.StringVar(&clientCAPath, "client-ca", "", "trusted device CA PEM")
	flag.StringVar(&registryPath, "device-registry", "", "registered device ML-DSA keys")
	flag.StringVar(&issuerKeyPath, "privacy-token-private-key", "", "blind RSA issuer private key PEM")
	flag.StringVar(&echKeysPath, "ech-keys", "", "RFC 9849 ECH server key set")
	flag.StringVar(&auditLogPath, "audit-log", "", "fsynced HMAC-chained issuance audit log")
	flag.StringVar(&auditKeyPath, "audit-key", "", "32-byte issuance audit key")
	flag.StringVar(&suiteName, "suite", "x25519-mlkem768", "strict hybrid TLS suite")
	flag.IntVar(&replayLimit, "replay-limit", 100000, "maximum unexpired issuance nonces")
	flag.IntVar(&rateBurst, "rate-burst", 4, "issuance burst per device/IP")
	flag.Float64Var(&ratePerMinute, "rate-per-minute", 6, "issuance refill per device/IP per minute")
	flag.IntVar(&rateMaxKeys, "rate-max-keys", 100000, "maximum issuance limiter entries")
	flag.IntVar(&maxConcurrent, "max-concurrent", 128, "maximum concurrent issue requests")
	flag.IntVar(&maxPreAuthConnections, "max-preauth-connections", 1024, "ceiling on concurrent accepted TCP connections before authentication; 0 disables")
	flag.IntVar(&maxPreAuthConnectionsPerIP, "max-preauth-connections-per-ip", 32, "ceiling on concurrent accepted TCP connections from one source; 0 disables")
	flag.StringVar(&decoyOriginTarget, "decoy-origin", "", "absolute http(s) URL reverse-proxied to unauthenticated peers; empty serves a per-deployment generated placeholder site (a stopgap - see OPERATIONS.md 2.2)")
	flag.StringVar(&coverServerName, "cover-server-name", "", "private ECH-inner SNI that selects the Winn TLS profile; empty derives it from the server certificate")
	flag.StringVar(&coverCertPath, "cover-cert", "", "certificate PEM presented to unauthenticated peers; required unless -insecure-cover-reuses-winn-leaf")
	flag.StringVar(&coverKeyPath, "cover-key", "", "private key PEM for -cover-cert")
	flag.BoolVar(&allowWinnLeafAsCover, "insecure-cover-reuses-winn-leaf", false, "lab only: serve the Winn leaf to unauthenticated peers, disclosing its issuer to every prober")
	flag.BoolVar(&allowIdentifyingCover, "insecure-cover-identifies-operator", false, "lab only: accept a cover certificate whose subject names the operator (EV/OV attributes)")
	flag.BoolVar(&allowImplausibleCover, "insecure-cover-is-not-a-real-origin", false, "lab only: accept a cover certificate that could not belong to a real public origin (self-signed, CA, reserved TLD)")
	flag.Parse()
	if certPath == "" || keyPath == "" || clientCAPath == "" ||
		registryPath == "" || issuerKeyPath == "" || echKeysPath == "" ||
		auditLogPath == "" || auditKeyPath == "" {
		exitError(errors.New("cert, key, client-ca, device-registry, privacy-token-private-key, ech-keys, audit-log, and audit-key are required"))
	}
	if maxConcurrent < 1 || maxConcurrent > 4096 {
		exitError(errors.New("max-concurrent is invalid"))
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		exitError(err)
	}
	tlsConfiguration, err := tlsconfig.ServerForALPN(
		certPath, keyPath, clientCAPath, suite, http2.NextProtoTLS,
	)
	if err != nil {
		exitError(err)
	}
	echKeys, err := echconfig.LoadServerKeys(echKeysPath)
	if err != nil {
		exitError(err)
	}
	if err := echconfig.ConfigureServer(tlsConfiguration, echKeys, true); err != nil {
		exitError(err)
	}
	// Probe resistance. This listener is the one a device must reach before it
	// can get an anonymous carrier token, so it is exposed by design -
	// deploy/systemd/winn-token-issuer.env.example binds 0.0.0.0:9444 - and it
	// requests a client certificate unconditionally, so a CertificateRequest
	// naming the Winn CA reached every prober that connected to it.
	coverListener, err := coverlisten.Apply(coverlisten.Options{
		Winn:            tlsConfiguration,
		CoverALPN:       []string{http2.NextProtoTLS, "http/1.1"},
		CoverServerName: coverServerName,
		CoverCertPath:   coverCertPath,
		CoverKeyPath:    coverKeyPath,
		ECHKeys:         echKeys,
		// tlsconfig.ServerForALPN pins RequireAndVerifyClientCert.
		RequestsClientCertificate:        true,
		AllowWinnLeafAsCover:             allowWinnLeafAsCover,
		AllowIdentifyingCoverCertificate: allowIdentifyingCover,
		AllowImplausibleCoverCertificate: allowImplausibleCover,
		Logf:                             log.Printf,
	})
	if err != nil {
		exitError(err)
	}
	// The cover site is seeded from the certificate this listener hands to
	// probers. Without that, every deployment that does not pass -decoy-origin
	// serves byte-identical HTML with an identical ETag, and one body hash
	// enumerates the fleet - the same disclosure the cover certificate closed
	// at the TLS layer, re-opened one layer up over plain HTTP.
	coverTLS := coverListener.TLS
	decoyOrigin, err := decoy.NewOrigin(decoy.Config{
		Target:            decoyOriginTarget,
		CoverTLS:          coverTLS,
		PrivateServerName: coverListener.PrivateServerName,
		Logf:              log.Printf,
	})
	if err != nil {
		exitError(err)
	}
	registry, err := pqauth.LoadRegistry(registryPath)
	if err != nil {
		exitError(err)
	}
	issuerKey, err := privacytoken.LoadIssuerPrivateKey(issuerKeyPath)
	if err != nil {
		exitError(err)
	}
	replay, err := carrierauth.NewReplayCache(replayLimit)
	if err != nil {
		exitError(err)
	}
	limiter, err := ratelimit.New(rateBurst, ratePerMinute, rateMaxKeys)
	if err != nil {
		exitError(err)
	}
	auditLog, err := audit.Open(auditLogPath, auditKeyPath)
	if err != nil {
		exitError(err)
	}
	defer auditLog.Close()
	if err := auditLog.Record("privacy_token_issuer_starting", "", "", "suite="+suite.Name); err != nil {
		exitError(err)
	}
	handler := &issueHandler{
		suite: suite, issuer: rsaIssuer{key: issuerKey},
		verifier: &privacytoken.IssueAuthorizationVerifier{
			Registry: registry, Replay: replay, MaxSkew: 2 * time.Minute,
		},
		limiter: limiter, audit: auditLog,
		concurrent: make(chan struct{}, maxConcurrent),
	}
	// Anything that is not a fully-formed Winn connection is served the cover
	// website instead of a protocol error. Without this a prober that
	// completes the cover handshake reaches issueHandler and gets a
	// distinctive 404/415/426 ladder keyed on method, path, ALPN and TLS
	// profile - a fingerprint at the application layer to replace the one just
	// removed from the TLS layer.
	guard := &decoy.Guard{
		Winn:                      handler,
		Origin:                    decoyOrigin,
		Suite:                     suite.Curve,
		ServerName:                coverListener.PrivateServerName,
		RequireVerifiedClientCert: true,
		Paths:                     []string{privacytoken.IssuePath},
	}
	// Re-check at the point of use. coverlisten.Apply already verified what it
	// built, so on this path the call is redundant by construction - which is
	// the point. A configuration that reaches this listener by any other route
	// cannot be served.
	if err := coverlisten.Verify(coverTLS); err != nil {
		exitError(fmt.Errorf(
			"token-issuer listener is not probe resistant: %w", err,
		))
	}
	server := &http.Server{
		Addr: address, Handler: guard, TLSConfig: coverTLS,
		ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 64 << 10,
		// net/http interpolates the peer address into TLS handshake failures.
		// Issuance is the one place a device identity and a network address
		// meet, so that address must never reach a durable log.
		ErrorLog: observability.ErrorLogger(os.Stderr, "issuer: "),
	}
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 128, IdleTimeout: 30 * time.Second,
		MaxReadFrameSize: 1 << 14,
	}); err != nil {
		exitError(err)
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer stop()
	failures := make(chan error, 1)
	// Bound connections before the handshake: the token-bucket limiter is
	// keyed on principal|IP and cannot run until ML-DSA verification has
	// already succeeded.
	rawListener, err := net.Listen("tcp", address)
	if err != nil {
		exitError(err)
	}
	boundedListener, err := connlimit.Listen(rawListener, connlimit.Options{
		MaxTotal: maxPreAuthConnections,
		MaxPerIP: maxPreAuthConnectionsPerIP,
	})
	if err != nil {
		_ = rawListener.Close()
		exitError(err)
	}
	// Answer cleartext on the TLS port the way an ordinary server does rather
	// than with net/http's reply, which names the Go standard library.
	issuerListener := decoy.TLSOnlyListener(boundedListener, 8*time.Second, decoyOrigin)
	go func() {
		log.Printf("Winn privacy-token issuer listening on tcp/%s", address)
		failures <- server.ServeTLS(issuerListener, "", "")
	}()
	select {
	case <-ctx.Done():
	case failure := <-failures:
		if failure != nil && !errors.Is(failure, http.ErrServerClosed) {
			log.Printf("privacy-token issuer stopped unexpectedly: %v", failure)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.Printf("privacy-token issuer shutdown: %v", err)
	}
	if err := auditLog.Record("privacy_token_issuer_stopped", "", "", "graceful shutdown"); err != nil {
		log.Printf("privacy-token issuer stop audit: %v", err)
	}
}

func (handler *issueHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if handler.audit == nil || !handler.audit.Healthy() {
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	select {
	case handler.concurrent <- struct{}{}:
		defer func() { <-handler.concurrent }()
	default:
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != privacytoken.IssuePath ||
		request.URL.RawQuery != "" {
		http.Error(writer, "Not Found", http.StatusNotFound)
		return
	}
	if request.ProtoMajor != 2 ||
		request.Header.Get("Content-Type") != privacytoken.IssueMediaType ||
		request.Header.Get("Content-Encoding") != "" {
		http.Error(writer, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}
	if err := tlsconfig.ValidateStateForALPN(
		request.TLS, handler.suite, http2.NextProtoTLS,
	); err != nil {
		http.Error(writer, "Upgrade Required", http.StatusUpgradeRequired)
		return
	}
	deviceID, err := identity.DeviceID(request.TLS)
	if err != nil {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if allowed, retry := handler.limiter.Allow(
		deviceID + "|" + remoteHost(request.RemoteAddr),
	); !allowed {
		writer.Header().Set(
			"Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))),
		)
		http.Error(writer, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maximumIssueBody))
	if err != nil {
		log.Printf("privacy-token issue body rejected: %v", err)
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var issue privacytoken.IssueRequest
	if err := decoder.Decode(&issue); err != nil {
		log.Printf("privacy-token issue JSON rejected: %v", err)
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON after issue request")
		}
		log.Printf("privacy-token issue JSON trailing data rejected: %v", err)
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}
	if _, err := handler.verifier.Verify(request, issue, deviceID); err != nil {
		log.Printf("privacy-token issue authorization rejected: %v", err)
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}
	response, err := handler.issuer.BlindSign(issue)
	if err != nil {
		log.Printf("privacy-token blind request rejected: %v", err)
		http.Error(writer, "Bad Request", http.StatusBadRequest)
		return
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		log.Printf("privacy-token issue response marshal failed: %v", err)
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := handler.audit.Record(
		"privacy_token_issued", deviceID, "", "token_key_id="+issue.TokenKeyID,
	); err != nil {
		log.Printf("privacy-token issue audit failed: %v", err)
		http.Error(writer, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", privacytoken.IssueMediaType)
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(encoded); err != nil {
		log.Printf("privacy-token issue response write failed: %v", err)
	}
}

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "winn-token-issuer:", err)
	os.Exit(1)
}
