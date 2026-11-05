package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/connlimit"
	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/decoy"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/reality"
	"winsvpn.local/winnprotocol/internal/revocation"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/state"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func main() {
	var address string
	var metricsAddress string
	var template string
	var publicTarget string
	var backend string
	var certPath string
	var keyPath string
	var clientCAPath string
	var registryPath string
	var controllerSeedPath string
	var auditLogPath string
	var auditKeyPath string
	var controllerAlgorithm string
	var controllerID string
	var suiteName string
	var replayLimit int
	var maxDatagram int
	var rateBurst int
	var ratePerMinute float64
	var rateMaxKeys int
	var maxConcurrent int
	var manifestPath string
	var nodeID string
	var controllerPinsPath string
	var transparencyLog string
	var transparencyCheckpoint string
	var manifestFormat string
	var manifestV2TrustState string
	var transportID string
	var echKeysPath string
	var revocationListPath string
	var revocationStatePath string
	var revocationMaxAge time.Duration
	var revocationReloadInterval time.Duration
	var revocationRequireFresh bool
	var authorizationMode string
	var privacyTokenKeyID string
	var privacyTokenPostgresDSNFile string
	var privacyTokenPostgresMaxConnections int
	var privacyTokenPostgresInsecureLoopback bool
	var decoyOriginTarget string
	var coverServerName string
	var coverCertPath string
	var coverKeyPath string
	var allowWinnLeafAsCover bool
	var allowIdentifyingCover bool
	var allowImplausibleCover bool
	var maxPreAuthConnections int
	var maxPreAuthConnectionsPerIP int
	var labMode bool
	var spaRequired bool
	var spaKeysPath string
	var realityRelayTarget string
	var realityRelayTimeout time.Duration

	flag.StringVar(&address, "addr", ":9443", "TCP and UDP listen address")
	flag.StringVar(&metricsAddress, "metrics-addr", "127.0.0.1:9092", "health and metrics listen address; empty disables")
	flag.StringVar(&template, "masque-template", "", "public HTTPS RFC 9298 URI template")
	flag.StringVar(&publicTarget, "public-target", "winn.invalid:443", "logical CONNECT-UDP target accepted from clients")
	flag.StringVar(&backend, "awg-backend", "", "fixed AWG UDP backend host:port")
	flag.StringVar(&certPath, "cert", "", "server certificate PEM")
	flag.StringVar(&keyPath, "key", "", "server private key PEM")
	flag.StringVar(&clientCAPath, "client-ca", "", "trusted device CA PEM")
	flag.StringVar(&registryPath, "device-registry", "", "registered device ML-DSA keys")
	flag.StringVar(&controllerSeedPath, "controller-pq-seed", "", "controller ML-DSA seed")
	flag.StringVar(&auditLogPath, "audit-log", "", "fsynced HMAC-chained carrier audit log")
	flag.StringVar(&auditKeyPath, "audit-key", "", "32-byte carrier audit key")
	flag.StringVar(&controllerAlgorithm, "controller-pq-algorithm", pqauth.MLDSA87, "controller ML-DSA algorithm")
	flag.StringVar(&controllerID, "controller-id", "", "controller identity signed into responses")
	flag.StringVar(&suiteName, "suite", "x25519-mlkem768", "strict hybrid TLS suite")
	flag.IntVar(&replayLimit, "replay-limit", 100000, "maximum unexpired carrier nonces")
	flag.IntVar(&maxDatagram, "max-datagram", carrier.DefaultMaxDatagram, "maximum inner AWG UDP payload")
	flag.IntVar(&rateBurst, "rate-burst", 10, "carrier establishment burst per device/IP")
	flag.Float64Var(&ratePerMinute, "rate-per-minute", 30, "carrier establishment refill per device/IP per minute")
	flag.IntVar(&rateMaxKeys, "rate-max-keys", 100000, "maximum device/IP limiter entries")
	flag.IntVar(&maxConcurrent, "max-concurrent", 1024, "maximum active H3 and H2 carrier sessions")
	flag.StringVar(&manifestPath, "gateway-manifest", "", "signed, current gateway manifest (required outside lab mode)")
	flag.StringVar(&nodeID, "node-id", "", "this carrier's node ID in the signed gateway manifest")
	flag.StringVar(&controllerPinsPath, "controller-pq-pins", "", "controller ML-DSA pins for manifest and transparency verification")
	flag.StringVar(&transparencyLog, "transparency-log", "", "verified append-only manifest receipt log")
	flag.StringVar(&transparencyCheckpoint, "transparency-checkpoint", "", "externally retained transparency checkpoint")
	flag.StringVar(&manifestFormat, "manifest-format", "v1", "signed gateway manifest format: v1 or v2")
	flag.StringVar(&manifestV2TrustState, "manifest-v2-trust-state", "", "retained v2 rollback/transparency trust state")
	flag.StringVar(&transportID, "transport-id", "", "v2 H3 transport ID selected on this node")
	flag.StringVar(&echKeysPath, "ech-keys", "", "RFC 9849 ECH server key set")
	flag.StringVar(&revocationListPath, "device-revocation-list", "", "signed device revocation list (required in identity mode outside lab mode)")
	flag.StringVar(&revocationStatePath, "device-revocation-state", "", "retained revocation-list rollback pin")
	flag.DurationVar(&revocationMaxAge, "device-revocation-max-age", revocation.DefaultMaxAge, "age past which the revocation list is reported stale")
	flag.DurationVar(&revocationReloadInterval, "device-revocation-reload-interval", 15*time.Minute, "how often to re-read the revocation list; 0 disables and pins the list to startup")
	flag.BoolVar(&revocationRequireFresh, "device-revocation-require-fresh", false, "deny every device once the revocation list is stale; see SECURITY.md before enabling")
	flag.StringVar(&authorizationMode, "authorization-mode", carrierauth.AuthModeIdentity, "identity or anonymous-token")
	flag.StringVar(&privacyTokenKeyID, "privacy-token-key-id", "", "manifest privacy-token key accepted by this listener")
	flag.StringVar(&privacyTokenPostgresDSNFile, "privacy-token-postgres-dsn-file", "", "private PostgreSQL URL file for durable single-use token redemption")
	flag.IntVar(&privacyTokenPostgresMaxConnections, "privacy-token-postgres-max-connections", 8, "privacy-token PostgreSQL connection pool ceiling")
	flag.BoolVar(&privacyTokenPostgresInsecureLoopback, "privacy-token-postgres-insecure-loopback", false, "allow test-only non-TLS token PostgreSQL on numeric loopback")
	flag.StringVar(&decoyOriginTarget, "decoy-origin", "", "absolute http(s) URL reverse-proxied to unauthenticated peers; empty serves a per-deployment generated placeholder site (a stopgap - see OPERATIONS.md 2.2)")
	flag.StringVar(&coverServerName, "cover-server-name", "", "private ECH-inner SNI that selects the Winn TLS profile; empty derives it from the server certificate")
	flag.StringVar(&coverCertPath, "cover-cert", "", "certificate PEM presented to unauthenticated peers; required unless -insecure-cover-reuses-winn-leaf")
	flag.StringVar(&coverKeyPath, "cover-key", "", "private key PEM for -cover-cert")
	flag.BoolVar(&allowWinnLeafAsCover, "insecure-cover-reuses-winn-leaf", false, "lab only: serve the Winn leaf to unauthenticated peers, disclosing its issuer to every prober")
	flag.BoolVar(&allowIdentifyingCover, "insecure-cover-identifies-operator", false, "lab only: accept a cover certificate whose subject names the operator (EV/OV attributes)")
	flag.BoolVar(&allowImplausibleCover, "insecure-cover-is-not-a-real-origin", false, "lab only: accept a cover certificate that could not belong to a real public origin (self-signed, CA, reserved TLD)")
	flag.IntVar(&maxPreAuthConnections, "max-preauth-connections", 4096, "ceiling on concurrent accepted TCP connections before authentication; 0 disables")
	flag.IntVar(&maxPreAuthConnectionsPerIP, "max-preauth-connections-per-ip", 64, "ceiling on concurrent accepted TCP connections from one source; 0 disables")
	flag.BoolVar(&labMode, "lab-mode", false, "allow direct endpoint flags instead of signed manifest and transparency")
	flag.BoolVar(&spaRequired, "spa-required", false, "ALTERNATIVE CONNECTION INITIATION: require a valid Single Packet Authorization knock (internal/knock) on udp before either listener responds to a source at all; off by default so default behaviour is unchanged, see docs/SPA_DESIGN.md")
	flag.StringVar(&spaKeysPath, "spa-keys", "", "file of hex-encoded SPA keys, one per non-empty non-comment line, most current first for rotation overlap; required when -spa-required is set; never logged")
	flag.StringVar(&realityRelayTarget, "reality-relay-target", "", "REALITY-style probe defence (internal/reality), TCP/H2 carrier listener only - the QUIC/H3 listener is NOT covered by this flag and keeps serving -cover-cert as it does today. host:port of a real, independent, third-party TLS server this deployment does not operate. When set, any TCP connection that does not present the Winn profile is transparently relayed to it, byte for byte, so an unauthenticated prober receives that party's own real, unmodified TLS handshake and certificate instead of -cover-cert - there is then no certificate belonging to this deployment anywhere on that wire for a prober to catch. This works by silently relaying to a site that has not agreed to it and was not asked; there is no agreement being breached (none exists), but it is a real, documented point of controversy in the wider circumvention community, not a free lunch - see docs/handoff for the dated design note this was built against. For that reason this flag is never defaulted, chosen, or guessed on the operator's behalf: empty (the default) leaves every listener's behaviour byte-for-byte what it is today. A non-empty value is validated with a real TLS dial at startup - RFC-ordinary WebPKI verification, exactly what a prober's own TLS client would itself require - and the server refuses to start at all, rather than falling back to -cover-cert or -decoy-origin, if that validation fails.")
	flag.DurationVar(&realityRelayTimeout, "reality-relay-timeout", 8*time.Second, "dial timeout for -reality-relay-target: applied to the one-time startup validation dial and to every subsequent relayed connection's dial to that target; unused when -reality-relay-target is empty")
	flag.Parse()

	if backend == "" || certPath == "" || keyPath == "" ||
		controllerSeedPath == "" || auditLogPath == "" ||
		auditKeyPath == "" || echKeysPath == "" {
		exitError("awg-backend, cert, key, controller-pq-seed, audit-log, audit-key, and ech-keys are required")
	}
	if authorizationMode != carrierauth.AuthModeIdentity &&
		authorizationMode != carrierauth.AuthModeAnonymousToken {
		exitError("authorization-mode must be identity or anonymous-token")
	}
	if privacyTokenPostgresMaxConnections < 1 ||
		privacyTokenPostgresMaxConnections > 1024 {
		exitError(
			"privacy-token-postgres-max-connections must be between 1 and 1024",
		)
	}
	if privacyTokenPostgresInsecureLoopback && !labMode {
		exitError(
			"privacy-token-postgres-insecure-loopback requires lab-mode",
		)
	}
	if authorizationMode == carrierauth.AuthModeAnonymousToken &&
		privacyTokenPostgresDSNFile == "" {
		exitError(
			"production anonymous-token authorization requires privacy-token-postgres-dsn-file",
		)
	}
	if metricsAddress != "" {
		if err := requireLoopbackAddress(metricsAddress); err != nil {
			exitError(err.Error())
		}
	}
	if maxDatagram < 576 || maxDatagram > carrier.AbsoluteMaxDatagram {
		exitError("max-datagram must be between 576 and 1500")
	}
	if spaRequired && spaKeysPath == "" {
		exitError("spa-keys is required when -spa-required is set")
	}
	if !spaRequired && spaKeysPath != "" {
		exitError("spa-keys was set without -spa-required; refusing rather than silently ignoring a configured key file")
	}
	manifestDigest := carrierauth.LabManifestDigest
	var manifest gatewaymanifest.Manifest
	var selectedNode gatewaymanifest.Node
	var tokenKeys []gatewaymanifest.PrivacyTokenKey
	var expectedControllerAlgorithm string
	var expectedControllerKeyID string
	// nextManifestV2State is the advanced v2 rollback/transparency pin,
	// committed to -manifest-v2-trust-state once every startup check passed.
	var nextManifestV2State *gatewaymanifest.TrustStateV2
	// controllerPins is hoisted out of the manifest branch because the signed
	// device revocation list is verified against the same controller pin set.
	// One trust anchor governs both artifacts, so a carrier that can be told
	// where to connect can also be told who may not connect.
	var controllerPins *pqauth.VerifierSet
	enableH2 := true
	if labMode {
		if template == "" || controllerID == "" {
			exitError("lab mode requires masque-template and controller-id")
		}
		if authorizationMode != carrierauth.AuthModeIdentity {
			exitError("anonymous-token authorization requires a signed manifest")
		}
		if controllerPinsPath != "" {
			var loadErr error
			controllerPins, loadErr = pqauth.LoadVerifierSet(controllerPinsPath)
			if loadErr != nil {
				exitError(loadErr.Error())
			}
		}
	} else {
		if manifestPath == "" || nodeID == "" || controllerPinsPath == "" ||
			transparencyLog == "" {
			exitError("gateway-manifest, node-id, controller-pq-pins, and transparency-log are required outside lab mode")
		}
		var loadErr error
		controllerPins, loadErr = pqauth.LoadVerifierSet(controllerPinsPath)
		if loadErr != nil {
			exitError(loadErr.Error())
		}
		switch manifestFormat {
		case "v1":
			if transparencyCheckpoint == "" {
				exitError(
					"v1 manifest requires transparency-checkpoint",
				)
			}
			manifest, selectedNode, manifestDigest, _, loadErr =
				gatewaymanifest.LoadVerifiedNode(
					manifestPath, nodeID, transparencyLog,
					transparencyCheckpoint, controllerPins,
					time.Now().UTC(),
				)
			if loadErr != nil {
				exitError(loadErr.Error())
			}
			if !containsMode(
				selectedNode.AuthenticationModes,
				authorizationMode,
			) {
				exitError(
					"signed gateway node does not authorize " +
						authorizationMode,
				)
			}
			template = selectedNode.MASQUETemplate
			controllerID = manifest.ControllerID
			suiteName = manifest.Suite
			maxDatagram = min(
				maxDatagram, selectedNode.MaxInnerDatagram,
			)
			tokenKeys = manifest.PrivacyTokenKey
			expectedControllerAlgorithm = manifest.AuthAlgorithm
			expectedControllerKeyID = manifest.AuthKeyID
		case "v2":
			if manifestV2TrustState == "" || transportID == "" {
				exitError(
					"v2 manifest requires manifest-v2-trust-state and transport-id",
				)
			}
			var manifestV2 gatewaymanifest.ManifestV2
			var selectedNodeV2 gatewaymanifest.NodeV2
			var nextState gatewaymanifest.TrustStateV2
			manifestV2, selectedNodeV2, manifestDigest, nextState, loadErr =
				gatewaymanifest.LoadVerifiedNodeV2(
					manifestPath, nodeID, transparencyLog,
					manifestV2TrustState, controllerPins,
					time.Now().UTC(),
				)
			if loadErr != nil {
				exitError(loadErr.Error())
			}
			selectedTransport, transportErr :=
				selectedNodeV2.Transport(transportID)
			if transportErr != nil {
				exitError(transportErr.Error())
			}
			if selectedTransport.Type !=
				connectivity.CarrierHTTP3 {
				exitError(
					"v2 carrier listener requires an H3 transport",
				)
			}
			if !containsMode(
				selectedTransport.AuthenticationModes,
				authorizationMode,
			) {
				exitError(
					"signed v2 transport does not authorize " +
						authorizationMode,
				)
			}
			if selectedTransport.FixedBackend != backend {
				exitError(
					"configured AWG backend differs from signed v2 transport",
				)
			}
			publicTarget = selectedTransport.PublicTarget
			template = selectedTransport.Endpoint
			controllerID = manifestV2.ControllerID
			suiteName = manifestV2.Suite
			maxDatagram = min(
				maxDatagram,
				selectedTransport.MaxInnerDatagram,
			)
			tokenKeys = manifestV2.PrivacyTokenKeys
			expectedControllerAlgorithm =
				manifestV2.AuthAlgorithm
			expectedControllerKeyID = manifestV2.AuthKeyID
			nextManifestV2State = &nextState
			enableH2 = false
		default:
			exitError("manifest-format must be v1 or v2")
		}
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		exitError(err.Error())
	}
	serverH3TLS, serverH2TLS, err := serverTLSConfigurations(
		authorizationMode, certPath, keyPath, clientCAPath, suite,
	)
	if err != nil {
		exitError(err.Error())
	}
	echKeys, err := echconfig.LoadServerKeys(echKeysPath)
	if err != nil {
		exitError(err.Error())
	}
	if err := echconfig.ConfigureServer(serverH3TLS, echKeys, true); err != nil {
		exitError(err.Error())
	}
	if err := echconfig.ConfigureServer(serverH2TLS, echKeys, true); err != nil {
		exitError(err.Error())
	}

	// Probe resistance. Everything above configures the profile a genuine Winn
	// client negotiates. What follows configures what a censor gets, which
	// until now was a refusal - and a refusal, on five independent counts,
	// identified the endpoint on a single unauthenticated connection.
	//
	// In identity mode the private server name is what makes the tiering work:
	// a peer that does not present it never reaches the strict profile and so
	// never sees a CertificateRequest, which is what was disclosing the Winn
	// CA's Distinguished Name to anyone who connected. Anonymous-token mode
	// requests no client certificate at all and therefore has no CA name to
	// protect; it stays on the cover profile throughout.
	//
	// The assembly is coverlisten's, not this file's: it used to be inline
	// here, and being inline here is exactly why winn-server and
	// winn-token-issuer shipped without it.
	coverOptions := coverlisten.Options{
		CoverServerName: coverServerName,
		CoverCertPath:   coverCertPath,
		CoverKeyPath:    coverKeyPath,
		ECHKeys:         echKeys,
		// Identity mode is the only mode with a client CA to protect, so it is
		// the only one that must still reach the strict profile when the
		// certificate carries no DNS name to match on.
		RequestsClientCertificate:        authorizationMode == carrierauth.AuthModeIdentity,
		AllowWinnLeafAsCover:             allowWinnLeafAsCover,
		AllowIdentifyingCoverCertificate: allowIdentifyingCover,
		AllowImplausibleCoverCertificate: allowImplausibleCover,
		Logf:                             log.Printf,
	}
	h3Options := coverOptions
	h3Options.Winn = serverH3TLS
	h3Options.CoverALPN = []string{http3.NextProtoH3}
	h3Listener, err := coverlisten.Apply(h3Options)
	if err != nil {
		exitError(err.Error())
	}
	h2Options := coverOptions
	h2Options.Winn = serverH2TLS
	h2Options.CoverALPN = []string{http2.NextProtoTLS, "http/1.1"}
	h2Listener, err := coverlisten.Apply(h2Options)
	if err != nil {
		exitError(err.Error())
	}
	coverH3TLS := h3Listener.TLS
	coverH2TLS := h2Listener.TLS
	privateServerName := h2Listener.PrivateServerName
	// The cover site is seeded from the certificate these listeners hand to
	// probers. Without that, every deployment that does not pass -decoy-origin
	// serves byte-identical HTML with an identical ETag, and one body hash
	// enumerates the fleet - the same disclosure the cover certificate closed
	// at the TLS layer, re-opened one layer up over plain HTTP. H2 and H3 are
	// built from the same coverOptions and so present the same certificate;
	// either one names this deployment.
	decoyOrigin, err := decoy.NewOrigin(decoy.Config{
		Target:            decoyOriginTarget,
		CoverTLS:          coverH2TLS,
		PrivateServerName: privateServerName,
		Logf:              log.Printf,
	})
	if err != nil {
		exitError(err.Error())
	}
	var registry *pqauth.Registry
	if authorizationMode == carrierauth.AuthModeIdentity {
		if clientCAPath == "" || registryPath == "" {
			exitError("identity mode requires client-ca and device-registry")
		}
		registry, err = pqauth.LoadRegistry(registryPath)
		if err != nil {
			exitError(err.Error())
		}
	}
	controllerSigner, err := pqauth.LoadSigner(controllerAlgorithm, controllerSeedPath)
	if err != nil {
		exitError(err.Error())
	}
	if !labMode &&
		(controllerSigner.Algorithm() != expectedControllerAlgorithm ||
			controllerSigner.KeyID() != expectedControllerKeyID) {
		exitError(
			"carrier response signer differs from signed manifest controller",
		)
	}
	if nextManifestV2State != nil {
		// LoadVerifiedNodeV2 does not persist the pin it advances. Without
		// this the retained state stays at its bootstrap sequence: an older
		// manifest stays replayable across restarts, and the second rotation
		// is refused as a sequence gap.
		if err := commitManifestV2TrustState(
			manifestV2TrustState, *nextManifestV2State,
		); err != nil {
			exitError(err.Error())
		}
	}
	replay, err := carrierauth.NewReplayCache(replayLimit)
	if err != nil {
		exitError(err.Error())
	}
	limiter, err := ratelimit.New(rateBurst, ratePerMinute, rateMaxKeys)
	if err != nil {
		exitError(err.Error())
	}
	if maxConcurrent < 1 {
		exitError("max-concurrent must be positive")
	}
	auditLog, err := audit.Open(auditLogPath, auditKeyPath)
	if err != nil {
		exitError(err.Error())
	}
	defer auditLog.Close()
	if err := auditLog.Record("carrier_server_starting", "", "", "suite="+suite.Name); err != nil {
		exitError(err.Error())
	}
	// Device revocation, identity mode only.
	//
	// Anonymous-token mode is skipped deliberately, not by oversight: it has
	// no stable device identity to revoke, and it bounds exposure with short
	// token validity windows plus single-use durable redemption instead. A
	// revocation list has nothing to say about a pseudonym that exists for one
	// request.
	var revocationChecker *revocation.Checker
	var revocationSource revocation.Source
	if authorizationMode == carrierauth.AuthModeIdentity {
		if revocationListPath == "" {
			// Refusing to start is safe here in a way that refusing traffic is
			// not: this is operator misconfiguration at startup, not an
			// adversary withholding a list from a running node, so failing
			// closed costs nothing an operator cannot immediately fix.
			if !labMode {
				exitError(
					"identity mode requires device-revocation-list; " +
						"pass -lab-mode only for local testing",
				)
			}
			log.Print(
				"WARNING: lab mode without -device-revocation-list; " +
					"revoked devices retain carrier data-plane access",
			)
			if err := auditLog.Record(
				"carrier_revocation_disabled", "", "",
				"lab mode started without a device revocation list",
			); err != nil {
				exitError(err.Error())
			}
		} else {
			if controllerPins == nil {
				exitError(
					"device-revocation-list requires controller-pq-pins",
				)
			}
			// Without a retained pin every restart trusts whatever list it
			// is handed first, so a replayed older list silently un-revokes
			// devices across a restart.
			if revocationStatePath == "" && !labMode {
				exitError(
					"identity mode requires device-revocation-state; " +
						"pass -lab-mode only for local testing",
				)
			}
			revocationSource = revocation.Source{
				ListPath:     revocationListPath,
				StatePath:    revocationStatePath,
				ControllerID: controllerID,
				Pins:         controllerPins,
			}
			list, nextState, loadErr := revocation.LoadVerified(
				revocationListPath, revocationStatePath, controllerID,
				controllerPins, time.Now().UTC(),
			)
			if loadErr != nil {
				exitError(loadErr.Error())
			}
			revocationChecker, err = revocation.NewChecker(
				list, revocationMaxAge, revocationRequireFresh,
			)
			if err != nil {
				exitError(err.Error())
			}
			if revocationStatePath != "" {
				encoded, encodeErr := revocation.EncodeTrustState(nextState)
				if encodeErr != nil {
					exitError(encodeErr.Error())
				}
				if writeErr := securefile.AtomicWrite(
					revocationStatePath, encoded, 0o600,
				); writeErr != nil {
					exitError(writeErr.Error())
				}
				clear(encoded)
			}
			status := revocationChecker.Status()
			if status.Stale {
				// Loud, but not fatal. A stale list is still an authentic
				// under-approximation of the revoked set, and denying every
				// user because a fetch failed would hand the adversary the
				// outage they were trying to cause. See internal/revocation.
				log.Printf(
					"WARNING: device revocation list is stale "+
						"(sequence=%d age=%s); revocations issued since its "+
						"known-good instant are not yet enforced",
					status.Sequence, status.Age.Round(time.Second),
				)
			}
			if err := auditLog.Record(
				"carrier_revocation_loaded", "", "",
				fmt.Sprintf(
					"sequence=%d devices=%d stale=%t require_fresh=%t",
					status.Sequence, status.Count, status.Stale,
					status.RequireFresh,
				),
			); err != nil {
				exitError(err.Error())
			}
		}
	}
	requestVerifier := &carrierauth.RequestVerifier{
		Registry: registry, Replay: replay, Suite: suite.Name,
		MaxSkew: 2 * time.Minute, RequiredManifestDigest: manifestDigest,
	}
	// A nil *revocation.Checker in an interface field would be non-nil to the
	// verifier and silently answer "not revoked" for everyone, so only assign
	// when a list was actually installed.
	if revocationChecker != nil {
		requestVerifier.Revocations = revocationChecker
	}
	var tokenVerifier *carrier.PrivacyTokenVerifier
	var tokenRedemptions *state.PostgresRedemptionStore
	if authorizationMode == carrierauth.AuthModeAnonymousToken {
		dsnData, readErr := securefile.ReadPrivateLimited(
			privacyTokenPostgresDSNFile, 64<<10,
		)
		if readErr != nil {
			exitError("read privacy-token PostgreSQL DSN: " + readErr.Error())
		}
		dsn := strings.TrimSpace(string(dsnData))
		clear(dsnData)
		startupContext, cancelStartup := context.WithTimeout(
			context.Background(), 15*time.Second,
		)
		tokenRedemptions, err = state.OpenPostgresRedemptions(
			startupContext,
			state.PostgresRedemptionOptions{
				DSN:                   dsn,
				MaxConnections:        privacyTokenPostgresMaxConnections,
				AllowInsecureLoopback: privacyTokenPostgresInsecureLoopback,
			},
		)
		cancelStartup()
		if err != nil {
			exitError(err.Error())
		}
		defer tokenRedemptions.Close()
		tokenVerifier, err = privacyVerifierFromKeys(
			tokenKeys, privacyTokenKeyID, publicTarget,
			tokenRedemptions, time.Now().UTC(),
		)
		if err != nil {
			exitError(err.Error())
		}
	}
	metrics := observability.New()
	// Surface the revocation posture on /metrics so the operator can alert on
	// it. These are the three states that matter and they are not
	// interchangeable: not enforced at all, enforced from a list that has
	// aged out, and actively denying everyone under require-fresh.
	if revocationChecker == nil {
		metrics.Inc("carrier_revocation_not_enforced")
	} else if status := revocationChecker.Status(); status.Stale {
		metrics.Inc("carrier_revocation_list_stale")
		if status.DenyingAll {
			metrics.Inc("carrier_revocation_denying_all")
		}
	}
	h3Handler, err := carrier.NewH3Server(
		template, publicTarget, backend, suite, requestVerifier,
		controllerSigner, controllerID,
	)
	if err != nil {
		exitError(err.Error())
	}
	h3Handler.Metrics = metrics
	h3Handler.Audit = auditLog
	h3Handler.Limiter = limiter
	h3Handler.Concurrency = make(chan struct{}, maxConcurrent)
	h3Handler.MaxDatagram = maxDatagram
	h3Handler.MaxOuterDatagram = maxDatagram + carrier.CarrierEnvelopeOverhead
	h3Handler.PrivacyTokens = tokenVerifier
	h2Handler, err := carrier.NewH2Server(
		publicTarget, backend, suite, requestVerifier,
		controllerSigner, controllerID,
	)
	if err != nil {
		exitError(err.Error())
	}
	h2Handler.Metrics = metrics
	h2Handler.Audit = auditLog
	h2Handler.Limiter = limiter
	h2Handler.Concurrency = h3Handler.Concurrency
	h2Handler.MaxDatagram = maxDatagram
	h2Handler.MaxOuterDatagram = maxDatagram + carrier.CarrierEnvelopeOverhead
	h2Handler.Deduplicator = h3Handler.Deduplicator
	h2Handler.PrivacyTokens = tokenVerifier
	initialPacketSize := carrier.H3InitialPacketSize(
		maxDatagram + carrier.CarrierEnvelopeOverhead,
	)

	// ALTERNATIVE CONNECTION INITIATION (opt-in, off by default): when
	// -spa-required is set, neither listener responds to a source address
	// at all until it presents a valid Single Packet Authorization knock on
	// udp/<addr>. See docs/SPA_DESIGN.md for the design and
	// internal/knock's package doc for the wire format and rationale.
	//
	// The knock's PacketSize is deliberately set to the SAME value this
	// deployment already uses for its QUIC Initial packets
	// (initialPacketSize, just computed above), not a package default: a
	// knock is meant to be indistinguishable in size from the only other
	// pre-handshake datagram this port legitimately receives. One Gate is
	// shared between the H2 (TCP) and H3 (UDP) listeners below, so a single
	// knock authorizes whichever carrier the client's own racing logic
	// picks - see internal/knock's Gate doc.
	var knockGate *knock.Gate
	if spaRequired {
		spaKeys, spaKeysErr := knock.LoadKeysFromFile(spaKeysPath)
		if spaKeysErr != nil {
			exitError(spaKeysErr.Error())
		}
		knockGate, err = knock.NewGate(spaKeys, int(initialPacketSize), knock.GateConfig{
			// Grace is left at internal/knock's default (90s = 2x this
			// function's own quic.Config.MaxIdleTimeout of 45s, see the H3
			// service below) rather than duplicated here as a literal that
			// could silently drift out of sync with it.
			OnKnockAccepted: func(netip.Addr) {
				metrics.Inc("spa_knock_accepted")
			},
			OnKnockRejected: func(_ netip.Addr, reason string) {
				metrics.Inc("spa_knock_rejected_" + reason)
			},
		})
		if err != nil {
			exitError("spa: " + err.Error())
		}
	}

	// Anything that is not a fully-formed Winn connection is served the cover
	// website instead of a protocol error. The guard wraps the carrier
	// handlers rather than living inside them, so authenticated behaviour is
	// byte-for-byte what it was.
	guardPaths := []string{carrier.H2Path}
	if masquePrefix := templatePathPrefix(template); masquePrefix != "" {
		guardPaths = append(guardPaths, masquePrefix)
	}
	newGuard := func(protocol http.Handler) *decoy.Guard {
		return &decoy.Guard{
			Winn:       protocol,
			Origin:     decoyOrigin,
			Suite:      suite.Curve,
			ServerName: privateServerName,
			RequireVerifiedClientCert: authorizationMode ==
				carrierauth.AuthModeIdentity,
			Paths: guardPaths,
			OnDiverted: func(reason string) {
				metrics.Inc("cover_origin_served_" + reason)
			},
		}
	}

	// Re-check at the point of use. coverlisten.Apply already verified what it
	// built, so on this path the call is redundant by construction - which is
	// the point. A configuration that reaches a listener by any other route
	// cannot be served.
	if err := coverlisten.Verify(coverH3TLS); err != nil {
		exitError("carrier H3 listener is not probe resistant: " + err.Error())
	}
	if err := coverlisten.Verify(coverH2TLS); err != nil {
		exitError("carrier H2 listener is not probe resistant: " + err.Error())
	}

	// REALITY-style probe relay (internal/reality), TCP/H2 only - see
	// -reality-relay-target's own help text for the full tradeoff. Off by
	// default (empty target); validated by a real dial the moment it is not,
	// so a misconfigured target is caught here, at startup, rather than
	// discovered by the first prober or the first genuine user who reaches
	// it. Refusing to start is the only failure mode: there is no fallback
	// to -cover-cert or -decoy-origin for this flag, because a silent
	// fallback is exactly the "answers every prober convincingly until you
	// look closely" gap this flag exists to close.
	realityTarget := reality.Target{
		Address:     realityRelayTarget,
		DialTimeout: realityRelayTimeout,
	}
	if realityRelayTarget != "" {
		validationContext, cancelValidation := context.WithTimeout(
			context.Background(), realityRelayTimeout+2*time.Second,
		)
		validationErr := realityTarget.Validate(validationContext)
		cancelValidation()
		if validationErr != nil {
			exitError("reality-relay-target: " + validationErr.Error())
		}
		if err := auditLog.Record(
			"carrier_reality_relay_enabled", "", "",
			"target="+realityRelayTarget,
		); err != nil {
			exitError(err.Error())
		}
	}

	h3Service := &http3.Server{
		Addr:            address,
		TLSConfig:       coverH3TLS,
		Handler:         newGuard(h3Handler),
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams:         true,
			Allow0RTT:               false,
			InitialPacketSize:       initialPacketSize,
			DisablePathMTUDiscovery: false,
			HandshakeIdleTimeout:    8 * time.Second,
			MaxIdleTimeout:          45 * time.Second,
			KeepAlivePeriod:         15 * time.Second,
			MaxIncomingStreams:      128,
		},
	}
	h2Service := &http.Server{
		Addr:              address,
		Handler:           newGuard(h2Handler),
		TLSConfig:         coverH2TLS,
		ReadHeaderTimeout: 8 * time.Second,
		IdleTimeout:       45 * time.Second,
		MaxHeaderBytes:    64 << 10,
		// net/http interpolates the peer address into TLS handshake failures,
		// and an unauthenticated peer can force one such line per aborted
		// handshake. Redact the address: on a circumvention carrier a durable
		// record of who reached the endpoint is a safety failure, not a
		// debugging convenience.
		ErrorLog: observability.ErrorLogger(os.Stderr, "carrier: "),
	}
	if err := http2.ConfigureServer(h2Service, &http2.Server{
		MaxConcurrentStreams: 128,
		IdleTimeout:          45 * time.Second,
		MaxReadFrameSize:     1 << 14,
	}); err != nil {
		exitError(err.Error())
	}
	var metricsService *http.Server
	if metricsAddress != "" {
		metricsService = &http.Server{
			Addr:              metricsAddress,
			Handler:           metrics.Handler(),
			ReadHeaderTimeout: 3 * time.Second,
			ErrorLog:          observability.ErrorLogger(os.Stderr, "metrics: "),
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Re-read the revocation list on a timer. Without this the list is only
	// consulted at startup, which would make the propagation delay for a
	// revocation "until an operator restarts every carrier" - better than
	// hand-editing the device registry on each node, but still not a
	// revocation path anyone should rely on in an incident. With it, the
	// delay is bounded by this interval plus whatever the operator's
	// distribution takes.
	//
	// A failed refresh is an alert, never a shutdown. The previously verified
	// list stays in force; see internal/revocation for why discarding it
	// would be the wrong response to a blocked distribution channel.
	if revocationChecker != nil && revocationReloadInterval > 0 {
		go func() {
			ticker := time.NewTicker(revocationReloadInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					changed, refreshErr := revocationChecker.Refresh(
						revocationSource, time.Now().UTC(),
					)
					switch {
					case refreshErr != nil:
						metrics.Inc("carrier_revocation_refresh_failed")
						log.Printf(
							"WARNING: device revocation refresh failed, "+
								"continuing on the previously verified list: %v",
							refreshErr,
						)
					case changed:
						status := revocationChecker.Status()
						metrics.Inc("carrier_revocation_refreshed")
						_ = auditLog.Record(
							"carrier_revocation_refreshed", "", "",
							fmt.Sprintf(
								"sequence=%d devices=%d",
								status.Sequence, status.Count,
							),
						)
					}
					if revocationChecker.Status().Stale {
						metrics.Inc("carrier_revocation_list_stale")
					}
				}
			}
		}()
	}
	failures := make(chan error, 3)
	go func() {
		log.Printf("Winn carrier HTTP/3 listening on udp/%s", address)
		if knockGate == nil {
			failures <- h3Service.ListenAndServe()
			return
		}
		// SPA is required: bind the socket ourselves so it can be wrapped
		// before quic-go ever reads from it, and hand quic-go the wrapped
		// conn via Serve instead of letting ListenAndServe bind its own -
		// the same caller-supplied-socket shape internal/carrier's own
		// dialers already require on the client side (see
		// internal/carrier/supplied_socket.go).
		udpAddr, resolveErr := net.ResolveUDPAddr("udp", address)
		if resolveErr != nil {
			failures <- resolveErr
			return
		}
		udpConn, listenErr := net.ListenUDP("udp", udpAddr)
		if listenErr != nil {
			failures <- listenErr
			return
		}
		failures <- h3Service.Serve(knockGate.WrapPacketConn(udpConn))
	}()
	if enableH2 {
		// Bound the connection before the handshake rather than after
		// authentication. The token-bucket limiter is keyed on principal|IP
		// and so cannot run until ML-DSA verification has already succeeded;
		// until it does, nothing at all limits an unauthenticated source.
		tcpListener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			exitError(listenErr.Error())
		}
		boundedListener, limitErr := connlimit.Listen(tcpListener, connlimit.Options{
			MaxTotal: maxPreAuthConnections,
			MaxPerIP: maxPreAuthConnectionsPerIP,
			// Aggregate count only - recording which address was rejected
			// would rebuild the enumeration artifact the operational log was
			// just fixed to stop producing.
			OnRejected: func() { metrics.Inc("preauth_connection_rejected") },
		})
		if limitErr != nil {
			exitError(limitErr.Error())
		}
		// SPA, when required, sits between the raw connection-count bound
		// above and TLS classification below: an unauthorized source is
		// accepted (unavoidable - see internal/knock's Gate doc) and
		// immediately closed with zero bytes, never reaching the cover TLS
		// handshake at all.
		var preSPA net.Listener = boundedListener
		if knockGate != nil {
			preSPA = knockGate.WrapListener(boundedListener)
		}
		// Classify by first byte so cleartext HTTP does not reach net/http,
		// whose reply for that case names the Go standard library.
		classified := decoy.TLSOnlyListener(preSPA, 8*time.Second, decoyOrigin)
		h2Listener, buildErr := buildH2Listener(
			classified, coverH2TLS, realityTarget, metrics,
		)
		if buildErr != nil {
			exitError(buildErr.Error())
		}
		go func() {
			log.Printf("Winn carrier HTTP/2 listening on tcp/%s", address)
			if realityRelayTarget == "" {
				// Byte-for-byte the same call this deployment has always
				// made: buildH2Listener returns classified itself, unwrapped,
				// whenever reality relay is off, so this line is the entire
				// difference reality relay could possibly make to that case.
				failures <- h2Service.ServeTLS(h2Listener, "", "")
				return
			}
			// h2Listener already performs the TLS handshake itself (see
			// internal/reality) for exactly the connections that reach it;
			// ServeTLS would try to do so a second time via its own
			// tls.NewListener wrapping, which is neither necessary nor
			// correct here.
			failures <- h2Service.Serve(h2Listener)
		}()
	}
	if metricsService != nil {
		go func() {
			log.Printf("Winn carrier metrics listening on http://%s", metricsAddress)
			failures <- metricsService.ListenAndServe()
		}()
	}
	metrics.SetReady(true)
	select {
	case <-ctx.Done():
	case failure := <-failures:
		if failure != nil && !errors.Is(failure, http.ErrServerClosed) {
			log.Printf("carrier service stopped unexpectedly: %v", failure)
		}
	}
	metrics.SetReady(false)
	shutdownContext, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if enableH2 {
		_ = h2Service.Shutdown(shutdownContext)
	}
	_ = h3Service.Shutdown(shutdownContext)
	_ = h3Handler.Close()
	if metricsService != nil {
		_ = metricsService.Shutdown(shutdownContext)
	}
	if err := auditLog.Record("carrier_server_stopped", "", "", "graceful shutdown"); err != nil {
		log.Printf("carrier audit shutdown record: %v", err)
	}
}

// buildH2Listener returns the net.Listener the H2 carrier service should
// Serve.
//
// When target.Address is empty, it returns classified completely unchanged -
// this is the entire mechanism behind -reality-relay-target's "empty leaves
// every listener's behaviour byte-for-byte what it is today" promise. The
// off case is not a specially-configured reality.Listen; it is
// internal/reality never being invoked at all, which is the only way "off"
// is actually convincing rather than merely intended.
//
// When target.Address is non-empty - already validated by the caller via
// Target.Validate before this is reached - it wraps classified with
// reality.Listen, so a connection that does not present the Winn profile is
// relayed to target instead of being handed cover's certificate.
func buildH2Listener(
	classified net.Listener, cover *tls.Config, target reality.Target,
	metrics *observability.Registry,
) (net.Listener, error) {
	if target.Address == "" {
		return classified, nil
	}
	return reality.Listen(classified, reality.Options{
		Cover:            cover,
		Target:           target,
		HandshakeTimeout: 8 * time.Second,
		Logf:             log.Printf,
		OnOutcome: func(outcome string) {
			metrics.Inc("reality_relay_" + outcome)
		},
	})
}

func serverTLSConfigurations(mode, certPath, keyPath, clientCAPath string, suite tlsconfig.Suite) (*tls.Config, *tls.Config, error) {
	switch mode {
	case carrierauth.AuthModeIdentity:
		h3, err := tlsconfig.ServerForALPN(
			certPath, keyPath, clientCAPath, suite, http3.NextProtoH3,
		)
		if err != nil {
			return nil, nil, err
		}
		h2, err := tlsconfig.ServerForALPN(
			certPath, keyPath, clientCAPath, suite, http2.NextProtoTLS,
		)
		return h3, h2, err
	case carrierauth.AuthModeAnonymousToken:
		h3, err := tlsconfig.ServerAnonymousForALPN(
			certPath, keyPath, suite, http3.NextProtoH3,
		)
		if err != nil {
			return nil, nil, err
		}
		h2, err := tlsconfig.ServerAnonymousForALPN(
			certPath, keyPath, suite, http2.NextProtoTLS,
		)
		return h3, h2, err
	default:
		return nil, nil, errors.New("unsupported carrier authorization mode")
	}
}

func privacyVerifierFromKeys(
	keys []gatewaymanifest.PrivacyTokenKey,
	requestedKeyID string,
	publicTarget string,
	redemptions privacytoken.RedemptionStore,
	now time.Time,
) (*carrier.PrivacyTokenVerifier, error) {
	if !privacytoken.IsDurableRedemptionStore(redemptions) {
		return nil, errors.New(
			"production privacy-token verifier requires durable redemption state",
		)
	}
	for _, metadata := range keys {
		if requestedKeyID != "" && metadata.ID != requestedKeyID {
			continue
		}
		if metadata.Scope != "carrier:"+publicTarget {
			continue
		}
		notBefore, notAfter, err := metadata.Validity()
		if err != nil {
			return nil, err
		}
		if err := privacytoken.ValidateKeyWindow(notBefore, notAfter, now); err != nil {
			continue
		}
		der, err := metadata.PublicKeyDER()
		if err != nil {
			return nil, err
		}
		publicKey, err := privacytoken.ParseIssuerPublicKeyDER(der)
		clear(der)
		if err != nil {
			return nil, err
		}
		return &carrier.PrivacyTokenVerifier{
			PublicKey: publicKey, KeyID: metadata.ID,
			NotBefore: notBefore, NotAfter: notAfter,
			Redemptions: redemptions,
		}, nil
	}
	return nil, errors.New("no currently valid carrier privacy-token key is present in the signed manifest")
}

// templatePathPrefix reduces the RFC 9298 URI template to the fixed path
// prefix its expansions share, so the cover guard can tell protocol traffic
// from everything else without duplicating the template grammar.
func templatePathPrefix(template string) string {
	if template == "" {
		return ""
	}
	parsed, err := url.Parse(template)
	if err != nil {
		return ""
	}
	path := parsed.Path
	if path == "" {
		return ""
	}
	if index := strings.IndexByte(path, '{'); index >= 0 {
		path = path[:index]
	}
	if path == "" || path == "/" {
		return ""
	}
	return path
}

func containsMode(modes []string, expected string) bool {
	for _, mode := range modes {
		if mode == expected {
			return true
		}
	}
	return false
}

func requireLoopbackAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid metrics address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("metrics address must use a numeric loopback IP")
	}
	return nil
}

// commitManifestV2TrustState atomically writes the v2 rollback/transparency
// pin that LoadVerifiedNodeV2 returned, as internal/linuxauto's
// CommitTrustState does for the client.
func commitManifestV2TrustState(
	path string, next gatewaymanifest.TrustStateV2,
) error {
	encoded, err := gatewaymanifest.EncodeTrustStateV2(next)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := securefile.AtomicWrite(path, encoded, 0o600); err != nil {
		return fmt.Errorf("commit v2 manifest trust state: %w", err)
	}
	return nil
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-carrier-server:", message)
	os.Exit(1)
}
