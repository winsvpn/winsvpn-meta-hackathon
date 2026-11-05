// SPDX-License-Identifier: MIT
// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
package hostqueue

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
)

const winn3DialTimeout = 30 * time.Second

func winn3BuildSession(
	profile winn3Profile,
) (session.Config, []byte, error) {
	staticKeyBytes, err := ReadKeyFile(profile.Keys.StaticPath, "keys.static_path")
	if err != nil {
		return session.Config{}, nil, err
	}
	staticKey, err := core.NewStaticKey(staticKeyBytes)
	// ecdh.NewPrivateKey keeps its own copy of the scalar (as in
	// cmd/winn-datapath's sessionConfigFrom).
	clear(staticKeyBytes)
	if err != nil {
		return session.Config{}, nil, fmt.Errorf("keys.static_path: %w", err)
	}
	admission, err := ReadPrivateKeyFile(profile.Keys.AdmissionPath, "keys.admission_path")
	if err != nil {
		return session.Config{}, nil, err
	}
	admission = bytes.TrimRight(admission, "\r\n")

	cfg := session.Config{
		Core: core.Config{
			Gateway: core.GatewayParams{
				AdmissionKeys: [][]byte{admission},
				GatewayID:     []byte(profile.GatewayID),
			},
		},
		Static:  staticKey,
		Padding: core.PadBucket,
		FastPQ:  profile.FastPQ,
	}
	switch profile.Role {
	case winn3RoleClient:
		gatewayBytes, err := ReadKeyFile(
			profile.Keys.GatewayStaticPath, "keys.gateway_static_path")
		if err != nil {
			return session.Config{}, nil, err
		}
		gatewayStatic, err := core.NewPublicKey(gatewayBytes)
		if err != nil {
			return session.Config{}, nil, fmt.Errorf(
				"keys.gateway_static_path: %w", err)
		}
		cfg.GatewayStatic = gatewayStatic
		if err := ApplyDualAuthPublics(
			&cfg, profile.Keys.DualAuthEd25519PubPath, profile.Keys.DualAuthMLDSA65PubPath,
		); err != nil {
			return session.Config{}, nil, err
		}
	case winn3RoleGateway:
		cfg.Accept = func([]byte) error { return nil }
	}
	return cfg, admission, nil
}

func winn3DialCarrier(
	ctx context.Context,
	profile winn3Profile,
	sizing driver.Sizing,
	admission []byte,
) (carrier.Conn, error) {
	class, err := winn3ClassNamed(profile.Carrier.Class)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, winn3DialTimeout)
	defer cancel()

	role := carrier.RoleClient
	if profile.Role == winn3RoleGateway {
		role = carrier.RoleGateway
	}

	switch class {
	case carrier.ClassUDP:
		remote, resolveErr := net.ResolveUDPAddr("udp", profile.Carrier.Endpoint)
		if resolveErr != nil {
			return nil, fmt.Errorf("carrier.endpoint: %w", resolveErr)
		}
		return carrier.DialUDP(dialCtx, carrier.UDPConfig{
			Remote:         remote,
			MaxMessageSize: sizing.MessageSize,
			PathMTU:        sizing.PathMTU,
			SocketBufferHook: func(requested, gotRead, gotWrite int, setErr error) {
				fmt.Fprintf(os.Stderr, "winn-datapath: %s\n",
					carrier.FormatUDPSocketBufferGrant(requested, gotRead, gotWrite, setErr))
			},
		})
	case carrier.ClassTCP:
		return carrier.DialStream(dialCtx,
			carrier.DialTCP(profile.Carrier.Endpoint),
			carrier.StreamConfig{
				Secret:         admission,
				Role:           role,
				MaxMessageSize: sizing.MessageSize,
				PathMTU:        sizing.PathMTU,
				TCPFirstFlight: true,
			})
	case carrier.ClassTLS:
		return winn3DialTLS(dialCtx, profile, sizing, admission, role)
	default:
		return nil, winn3Refuse("carrier.class %s", class)
	}
}

func winn3DialTLS(
	ctx context.Context,
	profile winn3Profile,
	sizing driver.Sizing,
	admission []byte,
	role carrier.Role,
) (carrier.Conn, error) {
	suite, err := tlsconfig.ParseSuite(profile.Carrier.Suite)
	if err != nil {
		return nil, winn3Refuse("carrier.suite: %v", err)
	}
	alpn := profile.Carrier.tlsALPN()
	trust := tlsconfig.ClientTrust{
		Anchor:     tlsconfig.TrustAnchor(profile.Carrier.TrustAnchor),
		RootCAPath: profile.Carrier.RootCAPath,
	}
	var clientTLS *tls.Config
	if trust.Anchor == tlsconfig.TrustWebPKI {
		clientTLS, err = tlsconfig.ClientAnonymousTrusted(
			trust, profile.Carrier.ServerName, suite, alpn)
	} else {
		clientTLS, err = tlsconfig.ClientForALPN(
			profile.Carrier.ClientCertPath,
			profile.Carrier.ClientKeyPath,
			profile.Carrier.RootCAPath,
			profile.Carrier.ServerName,
			suite,
			alpn,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("winn3 tls client: %w", err)
	}
	echList, err := echconfig.LoadClientConfigList(profile.Carrier.ECHConfigListPath)
	if err != nil {
		return nil, fmt.Errorf("winn3 tls ECH config list: %w", err)
	}
	err = echconfig.ConfigureClient(clientTLS, echList, true)
	clear(echList)
	if err != nil {
		return nil, fmt.Errorf("winn3 tls ECH: %w", err)
	}

	endpoint := profile.Carrier.Endpoint
	raw, err := (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		_ = raw.Close()
		return nil, winn3Refuse(
			"dialled class tls but the connection is %T: refusing a silent downgrade",
			raw)
	}
	state := tlsConn.ConnectionState()
	if !state.ECHAccepted {
		_ = tlsConn.Close()
		return nil, winn3Refuse("dialled class tls but ECH was not accepted")
	}
	if err := tlsconfig.ValidateStateForALPN(&state, suite, alpn); err != nil {
		_ = tlsConn.Close()
		return nil, winn3Refuse("winn3 tls handshake: %v", err)
	}
	stream, err := carrier.NewStream(carrier.StreamConfig{
		Conn:           tlsConn,
		Secret:         admission,
		Role:           role,
		MaxMessageSize: sizing.MessageSize,
		PathMTU:        sizing.PathMTU,
	})
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if stream.Class() != carrier.ClassTLS {
		_ = stream.Close()
		return nil, winn3Refuse(
			"dialled class tls but the stream is %s: refusing a silent downgrade",
			stream.Class())
	}
	return stream, nil
}
