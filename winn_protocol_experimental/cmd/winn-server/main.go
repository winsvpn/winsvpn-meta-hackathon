package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/connlimit"
	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/decoy"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func main() {
	var listenAddress string
	var certPath string
	var keyPath string
	var clientCAPath string
	var statePath string
	var stateKeyPath string
	var auditLogPath string
	var auditKeyPath string
	var postgresDSNFile string
	var postgresMaxConnections int
	var postgresInsecureLoopback bool
	var postgresAutoMigrate bool
	var suiteName string
	var controllerID string
	var controllerPQSeed string
	var deviceRegistryPath string
	var ttl time.Duration
	var applyFile string
	var awgBinary string
	var awgInterface string
	var adminListenAddress string
	var rateBurst int
	var ratePerMinute float64
	var rateMaxKeys int
	var maxConcurrent int
	var labMode bool
	var once bool
	var echKeysPath string
	var maxPreAuthConnections int
	var maxPreAuthConnectionsPerIP int
	var decoyOriginTarget string
	var coverServerName string
	var coverCertPath string
	var coverKeyPath string
	var allowWinnLeafAsCover bool
	var allowIdentifyingCover bool
	var allowImplausibleCover bool

	flag.StringVar(&listenAddress, "listen", "127.0.0.1:9443", "TCP listen address")
	flag.StringVar(&certPath, "cert", "", "controller certificate PEM")
	flag.StringVar(&keyPath, "key", "", "controller private key PEM")
	flag.StringVar(&clientCAPath, "client-ca", "", "trusted device CA PEM")
	flag.StringVar(&statePath, "state", "", "encrypted controller state path")
	flag.StringVar(&stateKeyPath, "state-key", "", "32-byte controller state key path")
	flag.StringVar(&auditLogPath, "audit-log", "", "tamper-evident JSONL audit log path")
	flag.StringVar(&auditKeyPath, "audit-key", "", "32-byte HMAC audit key path")
	flag.StringVar(&postgresDSNFile, "postgres-dsn-file", "", "private file containing a PostgreSQL URL (alternative to -state)")
	flag.IntVar(&postgresMaxConnections, "postgres-max-connections", 16, "PostgreSQL connection pool ceiling")
	flag.BoolVar(&postgresInsecureLoopback, "postgres-insecure-loopback", false, "allow test-only non-TLS PostgreSQL on a numeric loopback address")
	flag.BoolVar(&postgresAutoMigrate, "postgres-auto-migrate", false, "apply PostgreSQL schema at startup (lab/bootstrap only)")
	flag.StringVar(&suiteName, "suite", protocol.DefaultSuite, "strict hybrid suite")
	flag.StringVar(&controllerID, "controller-id", "winn-controller-1", "stable controller audience identifier")
	flag.StringVar(&controllerPQSeed, "controller-pq-seed", "", "controller ML-DSA seed for the selected suite")
	flag.StringVar(&deviceRegistryPath, "device-pq-registry", "", "registered device ML-DSA public keys")
	flag.DurationVar(&ttl, "key-ttl", 24*time.Hour, "issued AWG PSK lifetime")
	flag.StringVar(&applyFile, "apply-file", "", "lab-only controller PSK output file")
	flag.StringVar(&awgBinary, "awg-bin", "", "real awg/amneziawg/wg binary")
	flag.StringVar(&awgInterface, "interface", "", "real AWG interface name")
	flag.StringVar(&adminListenAddress, "admin-listen", "127.0.0.1:9095", "loopback-only health and metrics listen address")
	flag.IntVar(&rateBurst, "rate-burst", 6, "per-device/IP request burst")
	flag.Float64Var(&ratePerMinute, "rate-per-minute", 12, "per-device/IP sustained requests per minute")
	flag.IntVar(&rateMaxKeys, "rate-max-keys", 100000, "maximum in-memory rate-limit identities")
	flag.IntVar(&maxConcurrent, "max-concurrent", 128, "maximum concurrent protocol requests")
	flag.BoolVar(&labMode, "lab-mode", false, "enable explicitly non-production test adapters and settings")
	flag.BoolVar(&once, "once", false, "exit after one successful response")
	flag.IntVar(&maxPreAuthConnections, "max-preauth-connections", 1024, "ceiling on concurrent accepted TCP connections before authentication; 0 disables")
	flag.IntVar(&maxPreAuthConnectionsPerIP, "max-preauth-connections-per-ip", 32, "ceiling on concurrent accepted TCP connections from one source; 0 disables")
	flag.StringVar(&echKeysPath, "ech-keys", "", "RFC 9849 ECH server key set")
	flag.StringVar(&decoyOriginTarget, "decoy-origin", "", "absolute http(s) URL reverse-proxied to unauthenticated peers; empty serves a per-deployment generated placeholder site (a stopgap - see OPERATIONS.md 2.2)")
	flag.StringVar(&coverServerName, "cover-server-name", "", "private ECH-inner SNI that selects the Winn TLS profile; empty derives it from the server certificate")
	flag.StringVar(&coverCertPath, "cover-cert", "", "certificate PEM presented to unauthenticated peers; required unless -insecure-cover-reuses-winn-leaf")
	flag.StringVar(&coverKeyPath, "cover-key", "", "private key PEM for -cover-cert")
	flag.BoolVar(&allowWinnLeafAsCover, "insecure-cover-reuses-winn-leaf", false, "lab only: serve the Winn leaf to unauthenticated peers, disclosing its issuer to every prober")
	flag.BoolVar(&allowIdentifyingCover, "insecure-cover-identifies-operator", false, "lab only: accept a cover certificate whose subject names the operator (EV/OV attributes)")
	flag.BoolVar(&allowImplausibleCover, "insecure-cover-is-not-a-real-origin", false, "lab only: accept a cover certificate that could not belong to a real public origin (self-signed, CA, reserved TLD)")
	flag.Parse()

	for name, value := range map[string]string{
		"-cert": certPath, "-key": keyPath, "-client-ca": clientCAPath,
		"-state-key": stateKeyPath, "-audit-log": auditLogPath, "-audit-key": auditKeyPath,
		"-controller-pq-seed": controllerPQSeed, "-device-pq-registry": deviceRegistryPath,
		"-ech-keys": echKeysPath,
	} {
		if value == "" {
			exitError(name + " is required")
		}
	}
	if (statePath == "") == (postgresDSNFile == "") {
		exitError("choose exactly one state backend: -state or -postgres-dsn-file")
	}
	if postgresMaxConnections < 1 || postgresMaxConnections > 1024 {
		exitError("-postgres-max-connections must be between 1 and 1024")
	}
	if postgresInsecureLoopback && !labMode {
		exitError("-postgres-insecure-loopback requires -lab-mode")
	}
	if postgresAutoMigrate && !labMode {
		exitError("-postgres-auto-migrate requires -lab-mode; production migrations are separate")
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		exitError(err.Error())
	}
	limiter, err := ratelimit.New(rateBurst, ratePerMinute, rateMaxKeys)
	if err != nil {
		exitError(err.Error())
	}
	if maxConcurrent < 1 {
		exitError("-max-concurrent must be positive")
	}
	if err := requireLoopbackListen(adminListenAddress); err != nil {
		exitError(err.Error())
	}
	authAlgorithm := protocol.RequiredAuthAlgorithm(suite.Name)
	controllerSigner, err := pqauth.LoadSigner(authAlgorithm, controllerPQSeed)
	if err != nil {
		exitError(err.Error())
	}
	deviceRegistry, err := pqauth.LoadRegistry(deviceRegistryPath)
	if err != nil {
		exitError(err.Error())
	}
	applier, err := selectApplier(applyFile, awgBinary, awgInterface, labMode)
	if err != nil {
		exitError(err.Error())
	}
	var controllerState state.Controller
	if postgresDSNFile != "" {
		dsnData, readErr := securefile.ReadPrivateLimited(postgresDSNFile, 64<<10)
		if readErr != nil {
			exitError("read PostgreSQL DSN: " + readErr.Error())
		}
		dsn := strings.TrimSpace(string(dsnData))
		clear(dsnData)
		startupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		controllerState, err = state.OpenPostgres(startupContext, state.PostgresOptions{
			DSN:                   dsn,
			StateKeyPath:          stateKeyPath,
			TTL:                   ttl,
			ControllerID:          controllerID,
			Signer:                controllerSigner,
			MaxConnections:        postgresMaxConnections,
			AllowInsecureLoopback: postgresInsecureLoopback,
			AutoMigrate:           postgresAutoMigrate,
		})
		cancel()
	} else {
		controllerState, err = state.Open(statePath, stateKeyPath, ttl, controllerID, controllerSigner)
	}
	if err != nil {
		exitError(err.Error())
	}
	defer controllerState.Close()
	auditLog, err := audit.Open(auditLogPath, auditKeyPath)
	if err != nil {
		exitError(err.Error())
	}
	defer auditLog.Close()
	if err := auditLog.Record("server_started", "", "", "suite="+suite.Name); err != nil {
		exitError(err.Error())
	}
	tlsConfiguration, err := tlsconfig.Server(certPath, keyPath, clientCAPath, suite)
	if err != nil {
		exitError(err.Error())
	}
	echKeys, err := echconfig.LoadServerKeys(echKeysPath)
	if err != nil {
		exitError(err.Error())
	}
	if err := echconfig.ConfigureServer(tlsConfiguration, echKeys, true); err != nil {
		exitError(err.Error())
	}
	// Probe resistance. Everything above configures the profile a genuine Winn
	// client negotiates; this configures what a censor gets. Until now it got
	// a refusal, and the refusal identified the endpoint on one connection:
	// TLS 1.3 only, one named group, mandatory ECH, and - worst - a
	// CertificateRequest whose certificate_authorities field named the Winn
	// CA. This listener always requests a client certificate, so unlike the
	// carrier it has no anonymous mode in which there is no CA name to leak.
	//
	// -listen defaults to loopback but deploy/systemd/winn-server.env.example
	// sets 0.0.0.0:9443, so this is a reachable listener in every shipped
	// configuration.
	coverListener, err := coverlisten.Apply(coverlisten.Options{
		Winn:            tlsConfiguration,
		CoverALPN:       []string{"h2", "http/1.1"},
		CoverServerName: coverServerName,
		CoverCertPath:   coverCertPath,
		CoverKeyPath:    coverKeyPath,
		ECHKeys:         echKeys,
		// tlsconfig.Server pins RequireAndVerifyClientCert unconditionally.
		RequestsClientCertificate:        true,
		AllowWinnLeafAsCover:             allowWinnLeafAsCover,
		AllowIdentifyingCoverCertificate: allowIdentifyingCover,
		AllowImplausibleCoverCertificate: allowImplausibleCover,
		Logf:                             log.Printf,
	})
	if err != nil {
		exitError(err.Error())
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
		exitError(err.Error())
	}
	rawListener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		exitError(err.Error())
	}
	// Bound connections before the handshake. The token-bucket limiter below
	// is keyed on principal|IP and cannot run until ML-DSA verification has
	// already succeeded, so without this nothing at all limits an
	// unauthenticated source.
	boundedListener, err := connlimit.Listen(rawListener, connlimit.Options{
		MaxTotal: maxPreAuthConnections,
		MaxPerIP: maxPreAuthConnectionsPerIP,
	})
	if err != nil {
		_ = rawListener.Close()
		exitError(err.Error())
	}
	// Answer cleartext on the TLS port the way an ordinary server does rather
	// than with net/http's reply, which names the Go standard library.
	listener := decoy.TLSOnlyListener(boundedListener, 5*time.Second, decoyOrigin)
	adminListener, err := net.Listen("tcp", adminListenAddress)
	if err != nil {
		_ = listener.Close()
		exitError(err.Error())
	}

	success := make(chan struct{}, 1)
	metrics := observability.New()
	service := &bootstrap.Server{
		Store:          controllerState,
		Applier:        applier,
		Suite:          suite,
		ControllerID:   controllerID,
		DeviceRegistry: deviceRegistry,
		Logger:         log.New(os.Stderr, "", 0),
		Audit:          auditLog,
		Limiter:        limiter,
		Metrics:        metrics,
		Concurrency:    make(chan struct{}, maxConcurrent),
		ApplyTimeout:   8 * time.Second,
		OnSuccess: func() {
			if once {
				select {
				case success <- struct{}{}:
				default:
				}
			}
		},
	}
	// Anything that is not a fully-formed Winn connection is served the cover
	// website instead of a protocol error. Without this a prober that
	// completes the cover handshake reaches bootstrap.Server and is answered
	// with its JSON error envelope - {"error":"not_found",...} - which is as
	// good an identifier as the certificate was.
	guard := &decoy.Guard{
		Winn:                      service,
		Origin:                    decoyOrigin,
		Suite:                     suite.Curve,
		ServerName:                coverListener.PrivateServerName,
		RequireVerifiedClientCert: true,
		Paths:                     []string{protocol.RekeyPath},
		OnDiverted: func(reason string) {
			metrics.Inc("cover_origin_served_" + reason)
		},
	}
	// Re-check at the point of use. coverlisten.Apply already verified what it
	// built, so on this path the call is redundant by construction - which is
	// the point. A configuration that reaches this listener by any other route
	// cannot be served.
	if err := coverlisten.Verify(coverTLS); err != nil {
		exitError("controller listener is not probe resistant: " + err.Error())
	}
	httpServer := &http.Server{
		Handler:           guard,
		TLSConfig:         coverTLS,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// net/http interpolates the peer address into TLS handshake failures.
		// Redact it: a durable record of which addresses reached this endpoint
		// is a safety hazard for the people this controller serves.
		ErrorLog: observability.ErrorLogger(os.Stderr, "tls: "),
	}
	adminServer := &http.Server{
		Handler:           metrics.Handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          observability.ErrorLogger(os.Stderr, "admin: "),
	}
	metrics.SetReady(true)
	ready, _ := json.Marshal(map[string]any{
		"event":          "ready",
		"listen":         listener.Addr().String(),
		"admin_listen":   adminListener.Addr().String(),
		"suite":          suite.Name,
		"key_exchange":   suite.Curve.String(),
		"pq_auth":        controllerSigner.Algorithm(),
		"pq_auth_key_id": controllerSigner.KeyID(),
		"adapter":        applier.Description(),
	})
	fmt.Println(string(ready))

	serverError := make(chan error, 1)
	adminError := make(chan error, 1)
	go func() {
		serverError <- httpServer.ServeTLS(listener, "", "")
	}()
	go func() {
		adminError <- adminServer.Serve(adminListener)
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	var runError error
	protocolDone := false
	adminDone := false
	select {
	case err := <-serverError:
		protocolDone = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runError = err
		}
	case err := <-adminError:
		adminDone = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runError = err
		}
	case <-success:
	case <-signals:
	}
	metrics.SetReady(false)
	if err := auditLog.Record("server_stopping", "", "", "graceful shutdown"); err != nil {
		runError = errors.Join(runError, err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		runError = errors.Join(runError, err)
	}
	if err := adminServer.Shutdown(shutdownContext); err != nil {
		runError = errors.Join(runError, err)
	}
	if !protocolDone {
		if err := <-serverError; err != nil && !errors.Is(err, http.ErrServerClosed) {
			runError = errors.Join(runError, err)
		}
	}
	if !adminDone {
		if err := <-adminError; err != nil && !errors.Is(err, http.ErrServerClosed) {
			runError = errors.Join(runError, err)
		}
	}
	if runError != nil {
		exitError(runError.Error())
	}
}

func requireLoopbackListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid -admin-listen: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("-admin-listen must use a numeric loopback address")
	}
	return nil
}

func selectApplier(applyFile, binary, interfaceName string, labMode bool) (awg.Applier, error) {
	if applyFile != "" {
		if !labMode {
			return nil, errors.New("-apply-file requires -lab-mode")
		}
		if binary != "" || interfaceName != "" {
			return nil, errors.New("-apply-file cannot be combined with -awg-bin or -interface")
		}
		return awg.FileApplier{Path: applyFile}, nil
	}
	if binary == "" || interfaceName == "" {
		return nil, errors.New("choose -apply-file for a lab or both -awg-bin and -interface for a real tunnel")
	}
	return awg.CommandApplier{Binary: binary, Interface: interfaceName}, nil
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-server:", message)
	os.Exit(1)
}
