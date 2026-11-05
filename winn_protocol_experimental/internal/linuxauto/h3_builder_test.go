package linuxauto

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yosida95/uritemplate/v3"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/h3candidate"
	"winsvpn.local/winnprotocol/internal/preparation"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

func TestSignedH3RemoteEndpointUsesOnlyVerifiedHints(t *testing.T) {
	input := validH3BuilderInput()
	if endpoint, err := signedH3RemoteEndpoint(
		input, false,
	); err != nil || endpoint != "198.51.100.20:443" {
		t.Fatalf("IPv4 endpoint = %q, %v", endpoint, err)
	}
	if endpoint, err := signedH3RemoteEndpoint(
		input, true,
	); err != nil || endpoint != "[2001:db8::20]:443" {
		t.Fatalf("IPv6 endpoint = %q, %v", endpoint, err)
	}
	input.EndpointTemplate =
		"https://other.example/.well-known/masque/udp/{target_host}/{target_port}/"
	if _, err := signedH3RemoteEndpoint(input, false); err == nil {
		t.Fatal("unsigned authority mismatch was accepted")
	}
}

func TestH3BuilderRejectsInvalidVerifiedInputBeforeFactories(t *testing.T) {
	var dialerCalls int
	var tunnelCalls int
	builder := &H3Builder{config: H3BuilderConfig{
		DialerFactory: func(
			context.Context,
			preparation.H3PreparationInput,
		) (*carrier.H3Dialer, error) {
			dialerCalls++
			return nil, errors.New("must not be called")
		},
		TunnelFactory: func(
			context.Context,
			preparation.H3PreparationInput,
		) (h3candidate.TunnelController, error) {
			tunnelCalls++
			return nil, errors.New("must not be called")
		},
		Now: func() time.Time { return time.Now().UTC() },
	}}
	input := validH3BuilderInput()
	input.Suite = "mlkem768-only"
	if _, err := builder.PrepareH3(
		context.Background(), input,
	); err == nil {
		t.Fatal("non-hybrid H3 input was accepted")
	}
	if dialerCalls != 0 || tunnelCalls != 0 {
		t.Fatal("invalid verified input reached dependency factories")
	}
}

func TestValidateH3InputAcceptsProductionDatagramEnvelope(t *testing.T) {
	input := validH3BuilderInput()
	input.MaxInnerDatagram = carrier.DefaultMaxDatagram
	if err := validateH3Input(input, time.Now().UTC()); err != nil {
		t.Fatalf(
			"production %d-byte inner datagram was rejected: %v",
			carrier.DefaultMaxDatagram,
			err,
		)
	}
	if got := input.MaxInnerDatagram + h3EnvelopeOverhead; got > carrier.AbsoluteMaxCarrierEnvelope {
		t.Fatalf(
			"authenticated envelope size %d exceeds absolute limit %d",
			got,
			carrier.AbsoluteMaxCarrierEnvelope,
		)
	}
}

func TestBindDialerRejectsAnonymousTLSIdentityAndResumption(t *testing.T) {
	input := validH3BuilderInput()
	template, err := uritemplate.New(input.EndpointTemplate)
	if err != nil {
		t.Fatal(err)
	}
	baseTLS := &tls.Config{
		ServerName:                     input.ServerName,
		MinVersion:                     tls.VersionTLS13,
		MaxVersion:                     tls.VersionTLS13,
		CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
		EncryptedClientHelloConfigList: append([]byte(nil), input.ECHConfigList...),
		SessionTicketsDisabled:         true,
	}
	newDialer := func() *carrier.H3Dialer {
		return &carrier.H3Dialer{
			Template:     template,
			PublicTarget: input.PublicTarget,
			Suite: tlsconfig.Suite{
				Name:  input.Suite,
				Curve: tls.X25519MLKEM768,
			},
			TLSConfig: baseTLS.Clone(),
			ResponseVerifier: &carrierauth.ResponseVerifier{
				ControllerID: input.ControllerID,
			},
		}
	}
	tests := []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{
			name: "certificate",
			mutate: func(config *tls.Config) {
				config.Certificates = []tls.Certificate{{}}
			},
		},
		{
			name: "client certificate callback",
			mutate: func(config *tls.Config) {
				config.GetClientCertificate = func(
					*tls.CertificateRequestInfo,
				) (*tls.Certificate, error) {
					return &tls.Certificate{}, nil
				}
			},
		},
		{
			name: "client session cache",
			mutate: func(config *tls.Config) {
				config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			},
		},
		{
			name: "session tickets enabled",
			mutate: func(config *tls.Config) {
				config.SessionTicketsDisabled = false
			},
		},
		{
			name: "TLS key logging",
			mutate: func(config *tls.Config) {
				config.KeyLogWriter = &strings.Builder{}
			},
		},
		{
			name: "custom entropy",
			mutate: func(config *tls.Config) {
				config.Rand = strings.NewReader(
					"deterministic-anonymous-client-randomness",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := newDialer()
			test.mutate(dialer.TLSConfig)
			if err := bindDialerToVerifiedInput(
				dialer,
				input,
			); err == nil || !strings.Contains(
				err.Error(),
				"stable client identity or resumption",
			) {
				t.Fatalf("anonymous TLS validation error = %v", err)
			}
		})
	}
	if err := bindDialerToVerifiedInput(newDialer(), input); err != nil {
		t.Fatalf("identity-free anonymous TLS config rejected: %v", err)
	}
	tokenDialer := newDialer()
	tokenDialer.QUICConfig = &quic.Config{
		TokenStore: quic.NewLRUTokenStore(1, 1),
	}
	if err := bindDialerToVerifiedInput(
		tokenDialer,
		input,
	); err == nil || !strings.Contains(
		err.Error(),
		"persistent address tokens",
	) {
		t.Fatalf("anonymous QUIC token-store rejection error = %v", err)
	}
}

// TestBindDialerEnablesLengthPadding is the regression test for the review's
// second high finding on this path specifically. Length padding used to be
// hardcoded off here, so the bucket ladder was unreachable on the Linux auto
// path however the signed deployment was configured, and inner datagram
// lengths went out one-to-one on a shipped binary.
//
// A dialer bound to a verified deployment must pad. The gateway derives the
// same decision from the signed PrivacyProfile claim, so this also settles the
// return direction.
func TestBindDialerEnablesLengthPadding(t *testing.T) {
	input := validH3BuilderInput()
	template, err := uritemplate.New(input.EndpointTemplate)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &carrier.H3Dialer{
		Template:     template,
		PublicTarget: input.PublicTarget,
		Suite: tlsconfig.Suite{
			Name:  input.Suite,
			Curve: tls.X25519MLKEM768,
		},
		TLSConfig: &tls.Config{
			ServerName:                     input.ServerName,
			MinVersion:                     tls.VersionTLS13,
			MaxVersion:                     tls.VersionTLS13,
			CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768},
			EncryptedClientHelloConfigList: append([]byte(nil), input.ECHConfigList...),
			SessionTicketsDisabled:         true,
		},
		ResponseVerifier: &carrierauth.ResponseVerifier{
			ControllerID: input.ControllerID,
		},
		// Start from the leaking configuration so the test fails if binding
		// stops making the decision at all.
		DisableLengthPadding: true,
	}
	if err := bindDialerToVerifiedInput(dialer, input); err != nil {
		t.Fatal(err)
	}
	if dialer.DisableLengthPadding {
		t.Fatal(
			"Linux auto H3 dialer leaks inner datagram lengths: length " +
				"padding is disabled after binding to a verified deployment",
		)
	}
}

func validH3BuilderInput() preparation.H3PreparationInput {
	now := time.Now().UTC()
	return preparation.H3PreparationInput{
		Context: preparation.CandidateContext{
			Profile:           "auto",
			Mode:              connectivity.ModeAuto,
			ManifestDigest:    strings.Repeat("a", 64),
			ManifestExpiresAt: now.Add(time.Hour),
			PSKGeneration:     1,
			PSKExpiresAt:      now.Add(time.Hour),
			Descriptor: connectivity.CandidateDescriptor{
				ID:        "h3-primary",
				Carrier:   connectivity.CarrierHTTP3,
				NodeID:    "gateway-primary",
				ExpiresAt: now.Add(time.Hour),
			},
		},
		ManifestSequence:     1,
		ControllerID:         "controller-primary",
		Suite:                "x25519-mlkem768",
		EndpointTemplate:     "https://cover.example/.well-known/masque/udp/{target_host}/{target_port}/",
		ServerName:           "cover.example",
		IPv4Hints:            []string{"198.51.100.20"},
		IPv6Hints:            []string{"2001:db8::20"},
		ECHConfigList:        []byte{1, 2, 3},
		ALPN:                 []string{"h3"},
		PublicTarget:         "winn.invalid:443",
		FixedBackend:         "192.0.2.10:51820",
		GatewayPublicKey:     "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ=",
		MinInnerDatagram:     576,
		MaxInnerDatagram:     1280,
		AuthorizationMode:    "anonymous-token",
		ReservedCredentials:  preparation.MinimumReservedCredentialsPerH3,
		AnonymousCredentials: &nilCredentialSource{},
		UnderlayMark: preparation.UnderlayMarkAuthorization{
			AuthorizationID: "underlay-h3",
			InterfaceName:   "eth0",
			FirewallMark:    9,
			ExpiresAt:       now.Add(time.Hour),
		},
	}
}

type nilCredentialSource struct{}

func (*nilCredentialSource) NextAnonymousCredential() (
	carrier.AnonymousCredential,
	error,
) {
	return carrier.AnonymousCredential{},
		errors.New("not used by validation test")
}
