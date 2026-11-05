package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/connlimit"
	"winsvpn.local/winnprotocol/internal/coverlisten"
	"winsvpn.local/winnprotocol/internal/decoy"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/observability"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

// Cover on cmd/winn3-gateway.
//
// In-band initiation (winn3/core admission) is the probe-resistance: an
// unauthenticated v3 datagram still gets silence. What was missing is the
// APPEARANCE of a legitimate service. A prober that hits this process with
// TLS or QUIC must complete a handshake into a per-deployment decoy origin
// with SNI hidden by ECH, the same way winn-server / winn-carrier-server /
// winn-token-issuer already do. The assembly is theirs, not a new one:
// coverlisten.Apply, decoy.NewOrigin, echconfig.ConfigureServer on the
// strict profile, decoy.TLSOnlyListener on TCP.
//
// TCP cover binds the same host:port as the v3 UDP socket. QUIC/H3 shares
// that UDP socket through splitUDP, so a UDP probe of the open port is not
// answered with silence.

func requireCoverFlags(opts serveOptions) error {
	if strings.TrimSpace(opts.certPath) == "" {
		return errors.New("-cert is required: the cover listener needs a Winn leaf for the strict TLS profile")
	}
	if strings.TrimSpace(opts.keyPath) == "" {
		return errors.New("-key is required")
	}
	if strings.TrimSpace(opts.echKeysPath) == "" {
		return errors.New("-ech-keys is required: without ECH keys a genuine client's inner ClientHello cannot be decrypted and a prober sees a listener that cannot be a real ECH origin")
	}
	if !opts.allowWinnLeafAsCover &&
		(strings.TrimSpace(opts.coverCertPath) == "" || strings.TrimSpace(opts.coverKeyPath) == "") {
		return errors.New("-cover-cert and -cover-key are required unless -insecure-cover-reuses-winn-leaf")
	}
	return nil
}

type coverRuntime struct {
	v3   udpConn
	tcp  *tcpIngress
	stop func()
}

func startCover(ctx context.Context, opts serveOptions, udp *net.UDPConn, messageSize int,
	sessionCfg session.Config, sizing driver.Sizing) (*coverRuntime, error) {
	if err := requireCoverFlags(opts); err != nil {
		return nil, err
	}
	suiteName := strings.TrimSpace(opts.suite)
	if suiteName == "" {
		suiteName = protocol.DefaultSuite
	}
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		return nil, fmt.Errorf("-suite: %w", err)
	}
	echKeys, err := echconfig.LoadServerKeys(opts.echKeysPath)
	if err != nil {
		return nil, fmt.Errorf("-ech-keys: %w", err)
	}

	winnH2, err := tlsconfig.ServerAnonymousForALPN(
		opts.certPath, opts.keyPath, suite, http2.NextProtoTLS,
	)
	if err != nil {
		return nil, fmt.Errorf("strict H2 TLS: %w", err)
	}
	winnH3, err := tlsconfig.ServerAnonymousForALPN(
		opts.certPath, opts.keyPath, suite, http3.NextProtoH3,
	)
	if err != nil {
		return nil, fmt.Errorf("strict H3 TLS: %w", err)
	}
	if err := echconfig.ConfigureServer(winnH2, echKeys, true); err != nil {
		return nil, fmt.Errorf("strict H2 ECH: %w", err)
	}
	if err := echconfig.ConfigureServer(winnH3, echKeys, true); err != nil {
		return nil, fmt.Errorf("strict H3 ECH: %w", err)
	}

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "winn3-gateway: "+format+"\n", args...)
	}
	coverOptions := coverlisten.Options{
		CoverServerName:                  opts.coverServerName,
		CoverCertPath:                    opts.coverCertPath,
		CoverKeyPath:                     opts.coverKeyPath,
		ECHKeys:                          echKeys,
		RequestsClientCertificate:        false,
		AllowWinnLeafAsCover:             opts.allowWinnLeafAsCover,
		AllowIdentifyingCoverCertificate: opts.allowIdentifyingCover,
		AllowImplausibleCoverCertificate: opts.allowImplausibleCover,
		// Nothing on this gateway is served on the strict profile: Guard.Winn
		// below is the decoy itself. Leaving the profile selectable would let
		// a peer that sends the private server name in the OUTER SNI with an
		// undecryptable ECH extension draw the Winn leaf; see
		// coverlisten.Options.CoverOnly.
		CoverOnly: true,
		Logf:      logf,
	}
	h2Options := coverOptions
	h2Options.Winn = winnH2
	h2Options.CoverALPN = []string{http2.NextProtoTLS, "http/1.1"}
	h2Listener, err := coverlisten.Apply(h2Options)
	if err != nil {
		return nil, fmt.Errorf("cover H2: %w", err)
	}
	h3Options := coverOptions
	h3Options.Winn = winnH3
	h3Options.CoverALPN = []string{http3.NextProtoH3}
	h3Listener, err := coverlisten.Apply(h3Options)
	if err != nil {
		return nil, fmt.Errorf("cover H3: %w", err)
	}
	coverH2TLS := h2Listener.TLS
	coverH3TLS := h3Listener.TLS
	decoyOrigin, err := decoy.NewOrigin(decoy.Config{
		Target:            opts.decoyOrigin,
		CoverTLS:          coverH2TLS,
		PrivateServerName: h2Listener.PrivateServerName,
		Logf:              logf,
	})
	if err != nil {
		return nil, fmt.Errorf("decoy origin: %w", err)
	}
	if err := coverlisten.Verify(coverH2TLS); err != nil {
		return nil, fmt.Errorf("gateway H2 listener is not probe resistant: %w", err)
	}
	if err := coverlisten.Verify(coverH3TLS); err != nil {
		return nil, fmt.Errorf("gateway H3 listener is not probe resistant: %w", err)
	}

	// v3 is not an HTTP protocol. Every HTTP request on this listener is
	// cover appearance, including a peer that presented the private ECH-inner
	// SNI. A dedicated Winn path that 404s only for those peers would be a
	// distinguisher, not a service.
	guard := &decoy.Guard{
		Winn:                      decoyOrigin,
		Origin:                    decoyOrigin,
		Suite:                     suite.Curve,
		ServerName:                h2Listener.PrivateServerName,
		RequireVerifiedClientCert: false,
	}

	tcpAddr, err := tcpAddrMatching(udp.LocalAddr())
	if err != nil {
		return nil, err
	}
	rawTCP, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("cover TCP listen on %s: %w", tcpAddr, err)
	}
	bounded, err := connlimit.Listen(rawTCP, connlimit.Options{
		MaxTotal: opts.maxPreauthConnections,
		MaxPerIP: opts.maxPreauthConnectionsPerIP,
	})
	if err != nil {
		_ = rawTCP.Close()
		return nil, fmt.Errorf("cover connlimit: %w", err)
	}
	// Round W's TCP ingress only with -tcp-ingress (WINN3_GATEWAY_TCP_INGRESS=1).
	// Off, the cover listener is built exactly as before Round W: the TLS-only
	// classifier sits directly on the bounded raw listener, and tcp stays nil,
	// so server.serve never starts tcpLoop and no v3 session is built over TCP.
	var tcp *tcpIngress
	var coverTCP net.Listener = bounded
	if opts.tcpIngress {
		var admission []byte
		if len(sessionCfg.Core.Gateway.AdmissionKeys) > 0 {
			admission = sessionCfg.Core.Gateway.AdmissionKeys[0]
		}
		tcp = newTCPIngress(bounded, admission, sessionCfg, sizing)
		coverTCP = tcp
	}
	classified := decoy.TLSOnlyListener(coverTCP, 5*time.Second, decoyOrigin)

	h2Service := &http.Server{
		Handler:           guard,
		TLSConfig:         coverH2TLS,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          observability.ErrorLogger(os.Stderr, "winn3-gateway cover: "),
	}
	if err := http2.ConfigureServer(h2Service, &http2.Server{
		MaxConcurrentStreams: 128,
		IdleTimeout:          45 * time.Second,
		MaxReadFrameSize:     1 << 14,
	}); err != nil {
		_ = classified.Close()
		return nil, fmt.Errorf("cover h2: %w", err)
	}
	h3Service := &http3.Server{
		TLSConfig: coverH3TLS,
		Handler:   guard,
		QUICConfig: &quic.Config{
			Allow0RTT:            false,
			HandshakeIdleTimeout: 8 * time.Second,
			MaxIdleTimeout:       45 * time.Second,
			KeepAlivePeriod:      15 * time.Second,
			MaxIncomingStreams:   128,
		},
	}

	split := newSplitUDP(udp, messageSize)
	tr := &quic.Transport{
		Conn:                  split.quic,
		ConnectionIDLength:    split.cidGen.ConnectionIDLen(),
		ConnectionIDGenerator: split.cidGen,
	}
	ln, err := tr.Listen(coverH3TLS, h3Service.QUICConfig)
	if err != nil {
		split.stop()
		_ = classified.Close()
		return nil, fmt.Errorf("cover QUIC transport listen: %w", err)
	}

	coverErr := make(chan error, 2)
	go func() {
		err := h2Service.ServeTLS(classified, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			coverErr <- fmt.Errorf("cover HTTPS: %w", err)
			return
		}
		coverErr <- nil
	}()
	go func() {
		err := h3Service.ServeListener(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			coverErr <- fmt.Errorf("cover QUIC: %w", err)
			return
		}
		coverErr <- nil
	}()
	go func() {
		select {
		case <-ctx.Done():
			return
		case err := <-coverErr:
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "winn3-gateway: cover listener failed: %v\n", err)
				_ = udp.Close()
			}
		}
	}()

	fmt.Fprintf(os.Stderr,
		"winn3-gateway: cover HTTPS on tcp/%s and QUIC/H3 on the UDP socket\n",
		rawTCP.Addr().String())
	logTCPIngress(tcpIngressStateLine(opts.tcpIngress, rawTCP.Addr()))

	stop := func() {
		_ = h2Service.Close()
		_ = h3Service.Close()
		_ = ln.Close()
		_ = tr.Close()
		_ = classified.Close()
		split.stop()
	}
	go func() {
		<-ctx.Done()
		stop()
	}()

	return &coverRuntime{v3: split.v3, tcp: tcp, stop: stop}, nil
}

func tcpAddrMatching(udp net.Addr) (*net.TCPAddr, error) {
	ua, ok := udp.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("cover: UDP local addr is %T, not *net.UDPAddr", udp)
	}
	return &net.TCPAddr{IP: ua.IP, Port: ua.Port}, nil
}
