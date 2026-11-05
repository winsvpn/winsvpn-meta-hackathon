package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
	"winsvpn.local/winnprotocol/internal/knock"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/netdial"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func main() {
	var template string
	var h2URL string
	var publicTarget string
	var localAddress string
	var metricsAddress string
	var certPath string
	var keyPath string
	var rootCAPath string
	var serverName string
	var deviceID string
	var deviceSeedPath string
	var deviceAlgorithm string
	var controllerPinsPath string
	var controllerID string
	var suiteName string
	var sessionID string
	var localPeerAddress string
	var order string
	var generation uint64
	var maxDatagram int
	var manifestPath string
	var nodeID string
	var transparencyLog string
	var transparencyCheckpoint string
	var echConfigPath string
	var authorizationMode string
	var privacyTokenBundles stringList
	var privacyTokenKeyID string
	var privacyProfile string
	var handoffRedundancy time.Duration
	var redundantDatagrams int
	var enableCoverTraffic bool
	var coverIntervalMin time.Duration
	var coverIntervalMax time.Duration
	var coverDatagramSize int
	var labMode bool
	var connectTimeout time.Duration
	var alternateNodes stringList
	var spaRequired bool
	var spaKeyPath string

	flag.StringVar(&template, "masque-template", "", "public HTTPS RFC 9298 URI template")
	flag.StringVar(&h2URL, "h2-url", "", "lab HTTPS fallback URL; defaults to the MASQUE authority plus /winn/v2/udp-stream")
	flag.StringVar(&publicTarget, "public-target", "winn.invalid:443", "logical carrier target")
	flag.StringVar(&localAddress, "local", "127.0.0.1:51821", "local UDP address for the AWG client")
	flag.StringVar(&localPeerAddress, "local-peer", "", "host:port of the local AWG client allowed to use the tunnel (required outside lab mode)")
	flag.StringVar(&metricsAddress, "metrics-addr", "127.0.0.1:9093", "health and metrics listen address; empty disables")
	flag.StringVar(&certPath, "cert", "", "device certificate PEM")
	flag.StringVar(&keyPath, "key", "", "device private key PEM")
	flag.StringVar(&rootCAPath, "root-ca", "", "trusted carrier server CA PEM")
	flag.StringVar(&serverName, "server-name", "", "carrier certificate DNS name or IP")
	flag.StringVar(&deviceID, "device-id", "", "device ID matching the certificate URI SAN")
	flag.StringVar(&deviceSeedPath, "device-pq-seed", "", "device ML-DSA seed")
	flag.StringVar(&deviceAlgorithm, "device-pq-algorithm", pqauth.MLDSA65, "device ML-DSA algorithm")
	flag.StringVar(&controllerPinsPath, "controller-pq-pins", "", "pinned controller ML-DSA keys")
	flag.StringVar(&controllerID, "controller-id", "", "expected controller identity")
	flag.StringVar(&suiteName, "suite", "x25519-mlkem768", "strict hybrid TLS suite")
	flag.StringVar(&sessionID, "session-id", "", "stable 128-bit lowercase hex session ID; generated when empty")
	flag.StringVar(&order, "carriers", "h3,h2", "ordered carrier list: h3,h2 or h2,h3")
	flag.Uint64Var(&generation, "tunnel-generation", 1, "current AWG PSK generation preserved across carrier changes")
	flag.IntVar(&maxDatagram, "max-datagram", carrier.DefaultMaxDatagram, "maximum inner AWG UDP payload")
	flag.StringVar(&manifestPath, "gateway-manifest", "", "signed, current gateway manifest (required outside lab mode)")
	flag.StringVar(&nodeID, "node-id", "", "preferred node ID in the signed gateway manifest")
	flag.StringVar(&transparencyLog, "transparency-log", "", "verified append-only manifest receipt log")
	flag.StringVar(&transparencyCheckpoint, "transparency-checkpoint", "", "externally retained transparency checkpoint")
	flag.StringVar(&echConfigPath, "ech-config-list", "", "lab RFC 9849 ECHConfigList")
	flag.StringVar(&authorizationMode, "authorization-mode", carrierauth.AuthModeIdentity, "identity or anonymous-token")
	flag.Var(&privacyTokenBundles, "privacy-token-bundle", "repeatable one-time blind-token bundle for anonymous carrier attempts")
	flag.StringVar(&privacyTokenKeyID, "privacy-token-key-id", "", "manifest token key ID; inferred from the token when empty")
	// Length padding is the traffic-analysis defence, and it is switched on by
	// the privacy profile. Defaulting to standard left it inert for everyone
	// who did not know to ask for it, which is the wrong default for a tool
	// whose users are all at risk on identification. Standard remains
	// available for bandwidth-constrained networks; see docs for the measured
	// cost.
	flag.StringVar(&privacyProfile, "privacy-profile", carrierauth.PrivacyHighRisk, "standard or high-risk")
	flag.DurationVar(&handoffRedundancy, "handoff-redundancy", 0, "bounded duplicate-send window during carrier handoff (maximum 1s)")
	flag.IntVar(&redundantDatagrams, "handoff-redundant-datagrams", 64, "maximum duplicated datagrams per handoff (maximum 128)")
	flag.BoolVar(&enableCoverTraffic, "enable-cover-traffic", false, "send bounded cover datagrams in high-risk mode")
	flag.DurationVar(&coverIntervalMin, "cover-interval-min", 2*time.Second, "minimum cover-traffic interval")
	flag.DurationVar(&coverIntervalMax, "cover-interval-max", 5*time.Second, "maximum cover-traffic interval")
	flag.IntVar(&coverDatagramSize, "cover-datagram-size", 256, "padded cover datagram size")
	flag.BoolVar(&labMode, "lab-mode", false, "allow direct endpoint flags instead of signed manifest and transparency")
	flag.DurationVar(&connectTimeout, "connect-timeout", 30*time.Second, "time allowed to establish any authenticated carrier")
	flag.Var(&alternateNodes, "alternate-node", "repeatable ID|MASQUE_TEMPLATE|H2_URL self-healing node")
	flag.BoolVar(&spaRequired, "spa-required", false, "ALTERNATIVE CONNECTION INITIATION: send a Single Packet Authorization knock (internal/knock) to every candidate node before dialing; off by default, must match the target server's -spa-required, see docs/SPA_DESIGN.md")
	flag.StringVar(&spaKeyPath, "spa-key-file", "", "file holding this client's current hex-encoded SPA key (exactly one key line); required when -spa-required is set")
	flag.Parse()

	if rootCAPath == "" || controllerPinsPath == "" {
		exitError("root-ca and controller-pq-pins are required")
	}
	if maxDatagram < 576 || maxDatagram > carrier.AbsoluteMaxDatagram {
		exitError("max-datagram must be between 576 and 1500")
	}
	if connectTimeout <= 0 || connectTimeout > 5*time.Minute {
		exitError("connect-timeout must be positive and no more than five minutes")
	}
	if metricsAddress != "" {
		if err := requireLoopbackAddress(metricsAddress); err != nil {
			exitError(err.Error())
		}
	}
	if len(alternateNodes) > 8 {
		exitError("at most eight alternate nodes are supported")
	}
	if !labMode && len(alternateNodes) != 0 {
		exitError("alternate-node is lab-only; production alternates come from the signed manifest")
	}
	if spaRequired && spaKeyPath == "" {
		exitError("spa-key-file is required when -spa-required is set")
	}
	if !spaRequired && spaKeyPath != "" {
		exitError("spa-key-file was set without -spa-required; refusing rather than silently ignoring a configured key")
	}
	var spaKey []byte
	if spaRequired {
		spaKeys, spaKeysErr := knock.LoadKeysFromFile(spaKeyPath)
		if spaKeysErr != nil {
			exitError(spaKeysErr.Error())
		}
		if len(spaKeys) != 1 {
			exitError(fmt.Sprintf(
				"spa-key-file must contain exactly one key for a client, found %d",
				len(spaKeys),
			))
		}
		spaKey = spaKeys[0]
	}
	if !labMode && localPeerAddress == "" {
		exitError("local-peer is required outside lab mode; without it the first local UDP sender is pinned for the connection lifetime")
	}
	if privacyProfile != carrierauth.PrivacyStandard &&
		privacyProfile != carrierauth.PrivacyHighRisk {
		exitError("privacy-profile must be standard or high-risk")
	}
	if enableCoverTraffic && privacyProfile != carrierauth.PrivacyHighRisk {
		exitError("cover traffic requires privacy-profile=high-risk")
	}
	if authorizationMode != carrierauth.AuthModeIdentity &&
		authorizationMode != carrierauth.AuthModeAnonymousToken {
		exitError("authorization-mode must be identity or anonymous-token")
	}
	if sessionID == "" {
		var err error
		sessionID, err = mobility.NewSessionID()
		if err != nil {
			exitError(err.Error())
		}
	}
	if !mobility.ValidSessionID(sessionID) || generation == 0 {
		exitError("session-id must be 32 lowercase hexadecimal characters and tunnel-generation must be positive")
	}
	sequenceEpoch, err := mobility.NewSessionID()
	if err != nil {
		exitError(err.Error())
	}
	controllerPins, err := pqauth.LoadVerifierSet(controllerPinsPath)
	if err != nil {
		exitError(err.Error())
	}
	var nodes []gatewaymanifest.Node
	manifestDigest := carrierauth.LabManifestDigest
	var manifest gatewaymanifest.Manifest
	if labMode {
		if template == "" || serverName == "" || controllerID == "" ||
			echConfigPath == "" {
			exitError("lab mode requires masque-template, server-name, controller-id, and ech-config-list")
		}
		parsedTemplate, parseErr := url.Parse(template)
		if parseErr != nil || parsedTemplate.Scheme != "https" ||
			parsedTemplate.Host == "" {
			exitError("masque-template must be an absolute HTTPS URI template")
		}
		if h2URL == "" {
			h2URL = "https://" + parsedTemplate.Host + carrier.H2Path
		}
		echList, loadErr := echconfig.LoadClientConfigList(echConfigPath)
		if loadErr != nil {
			exitError(loadErr.Error())
		}
		nodes = append(nodes, gatewaymanifest.Node{
			ID: "primary", MASQUETemplate: template, H2URL: h2URL,
			ServerName:          serverName,
			ECHConfigList:       encodeBase64(echList),
			MaxInnerDatagram:    maxDatagram,
			AuthenticationModes: []string{authorizationMode},
		})
		clear(echList)
		for _, encodedNode := range alternateNodes {
			alternateID, alternateTemplate, alternateH2URL, parseErr :=
				parseAlternateNode(encodedNode)
			if parseErr != nil {
				exitError(parseErr.Error())
			}
			nodes = append(nodes, gatewaymanifest.Node{
				ID: alternateID, MASQUETemplate: alternateTemplate,
				H2URL: alternateH2URL, ServerName: serverName,
				ECHConfigList:       nodes[0].ECHConfigList,
				MaxInnerDatagram:    maxDatagram,
				AuthenticationModes: []string{authorizationMode},
			})
		}
	} else {
		if manifestPath == "" || nodeID == "" || transparencyLog == "" ||
			transparencyCheckpoint == "" {
			exitError("gateway-manifest, node-id, transparency-log, and transparency-checkpoint are required outside lab mode")
		}
		var selected gatewaymanifest.Node
		manifest, selected, manifestDigest, _, err =
			gatewaymanifest.LoadVerifiedNode(
				manifestPath, nodeID, transparencyLog, transparencyCheckpoint,
				controllerPins, time.Now().UTC(),
			)
		if err != nil {
			exitError(err.Error())
		}
		controllerID = manifest.ControllerID
		suiteName = manifest.Suite
		nodes = append(nodes, selected)
		for _, candidate := range manifest.Nodes {
			if candidate.ID != selected.ID {
				nodes = append(nodes, candidate)
			}
		}
	}
	for _, node := range nodes {
		if !containsString(node.AuthenticationModes, authorizationMode) {
			exitError("gateway node " + node.ID + " does not authorize " + authorizationMode)
		}
		maxDatagram = min(maxDatagram, node.MaxInnerDatagram)
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		exitError(err.Error())
	}
	var deviceSigner *pqauth.Signer
	var carrierToken *privacytoken.Token
	var credentialSource *privacyCredentialPool
	switch authorizationMode {
	case carrierauth.AuthModeIdentity:
		if certPath == "" || keyPath == "" || deviceID == "" ||
			deviceSeedPath == "" {
			exitError("identity mode requires cert, key, device-id, and device-pq-seed")
		}
		deviceSigner, err = pqauth.LoadSigner(deviceAlgorithm, deviceSeedPath)
		if err != nil {
			exitError(err.Error())
		}
	case carrierauth.AuthModeAnonymousToken:
		if labMode {
			exitError("anonymous-token mode requires a signed manifest")
		}
		if len(privacyTokenBundles) == 0 {
			exitError("at least one privacy-token-bundle is required for anonymous-token mode")
		}
		if certPath != "" || keyPath != "" {
			exitError("anonymous-token mode must not load a stable client certificate")
		}
		credentialSource = &privacyCredentialPool{}
		for _, bundlePath := range privacyTokenBundles {
			bundle, loadErr := privacytoken.LoadBundle(bundlePath)
			if loadErr != nil {
				exitError(loadErr.Error())
			}
			signer, signerErr := bundle.Signer()
			if signerErr != nil {
				exitError(signerErr.Error())
			}
			verified, verifyErr := verifyManifestToken(
				manifest, bundle.PublicToken(), privacyTokenKeyID,
				publicTarget, time.Now().UTC(),
			)
			if verifyErr != nil {
				exitError(verifyErr.Error())
			}
			credentialSource.credentials = append(
				credentialSource.credentials,
				carrier.AnonymousCredential{
					Pseudonym: verified.Pseudonym, Signer: signer,
					Token: bundle.PublicToken(),
				},
			)
		}
		deviceID = credentialSource.credentials[0].Pseudonym
		deviceSigner = credentialSource.credentials[0].Signer
	}
	responseVerifier := &carrierauth.ResponseVerifier{
		Verifiers:    controllerPins,
		ControllerID: controllerID,
		Suite:        suite.Name,
		MaxSkew:      2 * time.Minute,
	}
	priorities, err := carrierPriorities(order)
	if err != nil {
		exitError(err.Error())
	}
	candidates := make([]carrier.Candidate, 0, len(nodes)*2)
	for index, node := range nodes {
		echList, configErr := node.ECHConfigs()
		if configErr != nil {
			exitError(configErr.Error())
		}
		h3TLS, h2TLS, tlsErr := clientTLSConfigurations(
			authorizationMode, certPath, keyPath, rootCAPath,
			node.ServerName, suite,
		)
		if tlsErr != nil {
			clear(echList)
			exitError(tlsErr.Error())
		}
		if err := echconfig.ConfigureClient(h3TLS, echList, true); err != nil {
			clear(echList)
			exitError(err.Error())
		}
		if err := echconfig.ConfigureClient(h2TLS, echList, true); err != nil {
			clear(echList)
			exitError(err.Error())
		}
		clear(echList)
		happy, parseErr := happyEyeballsForNode(node)
		if parseErr != nil {
			exitError(parseErr.Error())
		}
		h3Dialer, dialErr := carrier.NewH3Dialer(
			node.MASQUETemplate, publicTarget, deviceID, sessionID, suite,
			h3TLS, deviceSigner, responseVerifier,
		)
		if dialErr != nil {
			exitError("node " + node.ID + ": " + dialErr.Error())
		}
		h3Dialer.MaxDatagram = maxDatagram
		h3Dialer.MaxOuterDatagram = maxDatagram + carrier.CarrierEnvelopeOverhead
		h3Dialer.ManifestDigest = manifestDigest
		h3Dialer.AuthorizationMode = authorizationMode
		h3Dialer.DisableLengthPadding =
			privacyProfile != carrierauth.PrivacyHighRisk
		h3Dialer.PrivacyToken = carrierToken
		h3Dialer.AnonymousCredentials = credentialSource
		h3Dialer.SequenceEpoch = sequenceEpoch
		h3Dialer.DialQUICPath = happy.DialQUICPath
		h2Dialer, dialErr := carrier.NewH2Dialer(
			node.H2URL, publicTarget, deviceID, sessionID, suite,
			h2TLS, deviceSigner, responseVerifier,
		)
		if dialErr != nil {
			exitError("node " + node.ID + ": " + dialErr.Error())
		}
		h2Dialer.MaxDatagram = maxDatagram
		h2Dialer.MaxOuterDatagram = maxDatagram + carrier.CarrierEnvelopeOverhead
		h2Dialer.ManifestDigest = manifestDigest
		h2Dialer.AuthorizationMode = authorizationMode
		h2Dialer.DisableLengthPadding =
			privacyProfile != carrierauth.PrivacyHighRisk
		h2Dialer.PrivacyToken = carrierToken
		h2Dialer.AnonymousCredentials = credentialSource
		h2Dialer.SequenceEpoch = sequenceEpoch
		h2Dialer.DialContext = happy.DialContext
		offset := float64(index * 10)
		candidates = append(candidates,
			carrier.Candidate{
				Path: mobility.Path{
					ID: node.ID + "-h3", Carrier: mobility.HTTP3,
					Endpoint: node.MASQUETemplate, Priority: priorities["h3"] + offset,
				},
				Dialer: h3Dialer,
			},
			carrier.Candidate{
				Path: mobility.Path{
					ID: node.ID + "-h2", Carrier: mobility.HTTP2,
					Endpoint: node.H2URL, Priority: priorities["h2"] + offset,
				},
				Dialer: h2Dialer,
			},
		)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	metrics := observability.New()
	managerConfig := carrier.DefaultManagerConfig()
	managerConfig.Metrics = metrics
	managerConfig.HandoffRedundancy = handoffRedundancy
	managerConfig.RedundantDatagrams = redundantDatagrams
	if enableCoverTraffic {
		managerConfig.CoverIntervalMin = coverIntervalMin
		managerConfig.CoverIntervalMax = coverIntervalMax
		managerConfig.CoverDatagramSize = coverDatagramSize
	}
	manager, err := carrier.NewManager(
		ctx, sessionID, generation, candidates,
		mobility.DefaultConfig(), managerConfig,
	)
	if err != nil {
		exitError(err.Error())
	}
	defer manager.Close()

	// ALTERNATIVE CONNECTION INITIATION (opt-in, off by default): send a
	// Single Packet Authorization knock to every candidate node before
	// dialing any of them. This does not touch the dialers or candidates
	// built above - see internal/carrier/supplied_socket.go's own
	// "everything here is additive" precedent - it only runs earlier and
	// independently. A knock never blocks on or waits for a reply (see
	// internal/knock's package doc), so a failed or skipped knock does not
	// abort the connection attempt: it proceeds exactly as it would with
	// -spa-required unset, and either the target does not require SPA, or
	// the subsequent dial fails on its own for that node while others in
	// the race may still succeed.
	if spaRequired {
		knockPacketSize := int(carrier.H3InitialPacketSize(
			maxDatagram + carrier.CarrierEnvelopeOverhead,
		))
		knockCtx, cancelKnock := context.WithTimeout(ctx, connectTimeout)
		for _, node := range nodes {
			target, targetErr := knockTargetFromNode(node)
			if targetErr != nil {
				log.Printf("spa: skipping knock for node %s: %v", node.ID, targetErr)
				continue
			}
			if sendErr := knock.Send(knockCtx, target, spaKey, knockPacketSize, knock.Options{}); sendErr != nil {
				log.Printf("spa: knock to node %s (%s) failed: %v", node.ID, target, sendErr)
			}
		}
		cancelKnock()
	}

	connectContext, cancelConnect := context.WithTimeout(ctx, connectTimeout)
	if err := manager.Connect(connectContext); err != nil {
		cancelConnect()
		exitError("no authenticated carrier became ready: " + err.Error())
	}
	cancelConnect()
	localUDPAddress, err := net.ResolveUDPAddr("udp", localAddress)
	if err != nil {
		exitError(err.Error())
	}
	localConnection, err := net.ListenUDP("udp", localUDPAddress)
	if err != nil {
		exitError(err.Error())
	}
	defer localConnection.Close()

	// Without an expected local peer the relay pins whichever local process
	// sends first and keeps it for the connection lifetime. A co-resident
	// process that wins the startup race then denies the tunnel to the real
	// AWG client and receives every carrier-to-local packet, which is a local
	// oracle confirming this tool is running. The two other production relay
	// paths pin the peer; this one did not.
	var expectedLocalPeer *net.UDPAddr
	if localPeerAddress != "" {
		expectedLocalPeer, err = net.ResolveUDPAddr("udp", localPeerAddress)
		if err != nil {
			exitError("local-peer: " + err.Error())
		}
		if expectedLocalPeer.IP == nil || expectedLocalPeer.Port < 1 {
			exitError("local-peer must be a host:port with a non-zero port")
		}
	}

	var metricsService *http.Server
	if metricsAddress != "" {
		metricsService = &http.Server{
			Addr:              metricsAddress,
			Handler:           metrics.Handler(),
			ReadHeaderTimeout: 3 * time.Second,
		}
		go func() {
			if serveErr := metricsService.ListenAndServe(); serveErr != nil &&
				!errors.Is(serveErr, http.ErrServerClosed) {
				log.Printf("metrics service: %v", serveErr)
			}
		}()
		defer func() {
			shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = metricsService.Shutdown(shutdownContext)
		}()
	}
	metrics.SetReady(true)
	snapshot := manager.Snapshot()
	log.Printf(
		"Winn carrier ready: local=%s session=%s generation=%d active=%s max_datagram=%d",
		localConnection.LocalAddr(), snapshot.SessionID, snapshot.TunnelGeneration,
		snapshot.ActivePath, maxDatagram,
	)
	err = carrier.RelayLocalUDP(ctx, localConnection, manager, carrier.RelayConfig{
		MaxDatagram:       maxDatagram,
		ExpectedLocalPeer: expectedLocalPeer,
	})
	metrics.SetReady(false)
	if err != nil && !errors.Is(err, context.Canceled) {
		exitError(err.Error())
	}
}

func clientTLSConfigurations(mode, certPath, keyPath, rootCAPath, serverName string, suite tlsconfig.Suite) (*tls.Config, *tls.Config, error) {
	switch mode {
	case carrierauth.AuthModeIdentity:
		h3, err := tlsconfig.ClientForALPN(
			certPath, keyPath, rootCAPath, serverName,
			suite, http3.NextProtoH3,
		)
		if err != nil {
			return nil, nil, err
		}
		h2, err := tlsconfig.ClientForALPN(
			certPath, keyPath, rootCAPath, serverName,
			suite, http2.NextProtoTLS,
		)
		return h3, h2, err
	case carrierauth.AuthModeAnonymousToken:
		h3, err := tlsconfig.ClientAnonymousForALPN(
			rootCAPath, serverName, suite, http3.NextProtoH3,
		)
		if err != nil {
			return nil, nil, err
		}
		h2, err := tlsconfig.ClientAnonymousForALPN(
			rootCAPath, serverName, suite, http2.NextProtoTLS,
		)
		return h3, h2, err
	default:
		return nil, nil, errors.New("unsupported carrier authorization mode")
	}
}

// knockTargetFromNode extracts the udp host:port to knock before dialing
// node - the same address this deployment's H2 and H3 carriers share (both
// bind cmd/winn-carrier-server's single -addr), so one knock covers
// whichever carrier wins the race.
func knockTargetFromNode(node gatewaymanifest.Node) (string, error) {
	parsed, err := url.Parse(node.H2URL)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" || parsed.Port() == "" {
		return "", errors.New("node H2 URL must include an explicit host:port")
	}
	return parsed.Host, nil
}

func happyEyeballsForNode(node gatewaymanifest.Node) (netdial.HappyEyeballs, error) {
	result := netdial.HappyEyeballs{
		FallbackDelay:  netdial.DefaultFallbackDelay,
		AttemptTimeout: 8 * time.Second,
	}
	for _, encoded := range node.IPv6Hints {
		address, err := netip.ParseAddr(encoded)
		if err != nil || !address.Is6() || address.Is4In6() {
			return netdial.HappyEyeballs{}, fmt.Errorf("node %s has invalid IPv6 hint %q", node.ID, encoded)
		}
		result.IPv6Hints = append(result.IPv6Hints, address)
	}
	for _, encoded := range node.IPv4Hints {
		address, err := netip.ParseAddr(encoded)
		if err != nil || !address.Is4() {
			return netdial.HappyEyeballs{}, fmt.Errorf("node %s has invalid IPv4 hint %q", node.ID, encoded)
		}
		result.IPv4Hints = append(result.IPv4Hints, address)
	}
	return result, nil
}

func verifyManifestToken(manifest gatewaymanifest.Manifest, token privacytoken.Token, requestedKeyID, publicTarget string, now time.Time) (privacytoken.Verified, error) {
	var failures []error
	for _, metadata := range manifest.PrivacyTokenKey {
		if requestedKeyID != "" && metadata.ID != requestedKeyID {
			continue
		}
		if metadata.Scope != "carrier:"+publicTarget {
			failures = append(failures, fmt.Errorf(
				"privacy token key %s has scope %q", metadata.ID, metadata.Scope,
			))
			continue
		}
		notBefore, notAfter, err := metadata.Validity()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if err := privacytoken.ValidateKeyWindow(notBefore, notAfter, now); err != nil {
			failures = append(failures, err)
			continue
		}
		der, err := metadata.PublicKeyDER()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		publicKey, err := privacytoken.ParseIssuerPublicKeyDER(der)
		clear(der)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		verified, err := privacytoken.Verify(token, publicKey, metadata.ID)
		if err == nil {
			return verified, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return privacytoken.Verified{}, errors.New("privacy token key is absent from the signed manifest")
	}
	return privacytoken.Verified{}, errors.Join(failures...)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func encodeBase64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func orderedCandidates(order, h3Endpoint, h2Endpoint string, h3 carrier.Dialer, h2 carrier.Dialer) ([]carrier.Candidate, error) {
	priorities, err := carrierPriorities(order)
	if err != nil {
		return nil, err
	}
	result := make([]carrier.Candidate, 0, 2)
	result = append(result,
		carrier.Candidate{
			Path: mobility.Path{
				ID: "h3-primary", Carrier: mobility.HTTP3,
				Endpoint: h3Endpoint, Priority: priorities["h3"],
			},
			Dialer: h3,
		},
		carrier.Candidate{
			Path: mobility.Path{
				ID: "h2-fallback", Carrier: mobility.HTTP2,
				Endpoint: h2Endpoint, Priority: priorities["h2"],
			},
			Dialer: h2,
		},
	)
	return result, nil
}

func carrierPriorities(order string) (map[string]float64, error) {
	parts := strings.Split(order, ",")
	if len(parts) != 2 {
		return nil, errors.New("carriers must contain h3 and h2 exactly once")
	}
	priorities := make(map[string]float64, 2)
	for index, rawName := range parts {
		name := strings.TrimSpace(rawName)
		if name != "h3" && name != "h2" {
			return nil, fmt.Errorf("unsupported carrier %q", rawName)
		}
		if _, duplicate := priorities[name]; duplicate {
			return nil, errors.New("carriers must contain h3 and h2 exactly once")
		}
		priorities[name] = float64(index * 100)
	}
	return priorities, nil
}

func parseAlternateNode(value string) (string, string, string, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 3 || !protocol.ValidDeviceID(parts[0]) {
		return "", "", "", errors.New("alternate-node must be ID|MASQUE_TEMPLATE|H2_URL with a valid ID")
	}
	if parts[0] == "primary" || parts[1] == "" || parts[2] == "" {
		return "", "", "", errors.New("alternate-node ID and URLs are invalid")
	}
	return parts[0], parts[1], parts[2], nil
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

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	if value == "" {
		return errors.New("alternate node must not be empty")
	}
	*values = append(*values, value)
	return nil
}

type privacyCredentialPool struct {
	mu          sync.Mutex
	credentials []carrier.AnonymousCredential
}

func (pool *privacyCredentialPool) NextAnonymousCredential() (carrier.AnonymousCredential, error) {
	if pool == nil {
		return carrier.AnonymousCredential{}, errors.New("privacy credential pool is unavailable")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.credentials) == 0 {
		return carrier.AnonymousCredential{}, errors.New("one-time privacy-token inventory is exhausted")
	}
	credential := pool.credentials[0]
	pool.credentials[0] = carrier.AnonymousCredential{}
	pool.credentials = pool.credentials[1:]
	return credential, nil
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-carrier-client:", message)
	os.Exit(1)
}
