// Package linuxauto contains Linux production composition for Winn Auto mode.
package linuxauto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/h3candidate"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/preparation"
)

const h3EnvelopeOverhead = carrier.CarrierEnvelopeOverhead

type H3DialerFactory func(
	context.Context,
	preparation.H3PreparationInput,
) (*carrier.H3Dialer, error)

type H3TunnelFactory func(
	context.Context,
	preparation.H3PreparationInput,
) (h3candidate.TunnelController, error)

type H3BuilderConfig struct {
	DialerFactory H3DialerFactory
	TunnelFactory H3TunnelFactory
	Verifier      h3candidate.CandidateVerifier
	Transactions  h3candidate.TransactionFactory

	PreferIPv6      bool
	WarmAge         time.Duration
	HealthInterval  time.Duration
	TeardownTimeout time.Duration
	Now             func() time.Time
}

// H3Builder implements preparation.H3PreparationBuilder with a live,
// authenticated, single-use prepared carrier. TLS trust material and the inner
// AWG controller remain injected boundaries because both are derived from
// controller-signed deployment profiles outside the generic manifest record.
type H3Builder struct {
	config H3BuilderConfig
}

var _ preparation.H3PreparationBuilder = (*H3Builder)(nil)

func NewH3Builder(config H3BuilderConfig) (*H3Builder, error) {
	if config.DialerFactory == nil ||
		config.TunnelFactory == nil ||
		nilInterface(config.Verifier) ||
		nilInterface(config.Transactions) {
		return nil, errors.New(
			"linux Auto H3 builder dependencies are required",
		)
	}
	if config.WarmAge == 0 {
		config.WarmAge = time.Minute
	}
	if config.WarmAge <= 0 ||
		config.WarmAge > h3candidate.MaxPreparedH3Age {
		return nil, errors.New(
			"linux Auto H3 warm lifetime is invalid",
		)
	}
	if config.HealthInterval == 0 {
		config.HealthInterval = time.Second
	}
	if config.HealthInterval < 100*time.Millisecond ||
		config.HealthInterval > 30*time.Second {
		return nil, errors.New(
			"linux Auto H3 health interval is invalid",
		)
	}
	if config.TeardownTimeout < 0 ||
		config.TeardownTimeout > h3candidate.MaxTeardownTimeout {
		return nil, errors.New(
			"linux Auto H3 teardown timeout is invalid",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &H3Builder{config: config}, nil
}

func (builder *H3Builder) PrepareH3(
	ctx context.Context,
	input preparation.H3PreparationInput,
) (preparation.CandidateBuild, error) {
	if builder == nil {
		return preparation.CandidateBuild{},
			errors.New("linux Auto H3 builder is nil")
	}
	if ctx == nil {
		return preparation.CandidateBuild{},
			errors.New("linux Auto H3 preparation context is required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return preparation.CandidateBuild{}, cause
	}
	now := builder.config.Now().UTC()
	if err := validateH3Input(input, now); err != nil {
		return preparation.CandidateBuild{}, err
	}
	remoteEndpoint, err := signedH3RemoteEndpoint(
		input, builder.config.PreferIPv6,
	)
	if err != nil {
		return preparation.CandidateBuild{}, err
	}
	underlay, err := h3candidate.NewLinuxProtectedUnderlayFactory(
		h3candidate.LinuxProtectedUnderlayConfig{
			InterfaceName:    input.UnderlayMark.InterfaceName,
			FirewallMark:     input.UnderlayMark.FirewallMark,
			ServerName:       input.ServerName,
			RemoteEndpoint:   remoteEndpoint,
			SessionExpiresAt: input.UnderlayMark.ExpiresAt.UTC(),
			HealthInterval:   builder.config.HealthInterval,
		},
	)
	if err != nil {
		return preparation.CandidateBuild{},
			fmt.Errorf("construct protected Linux H3 underlay: %w", err)
	}
	dialer, err := builder.config.DialerFactory(ctx, input)
	if err != nil {
		return preparation.CandidateBuild{},
			fmt.Errorf("construct verified H3 dialer: %w", err)
	}
	if err := bindDialerToVerifiedInput(dialer, input); err != nil {
		return preparation.CandidateBuild{}, err
	}
	tunnel, err := builder.config.TunnelFactory(ctx, input)
	if err != nil {
		return preparation.CandidateBuild{},
			fmt.Errorf("construct verified H3 inner tunnel: %w", err)
	}
	if nilInterface(tunnel) {
		return preparation.CandidateBuild{},
			errors.New("verified H3 inner tunnel is nil")
	}
	warm, err := h3candidate.PrepareWarm(
		ctx,
		h3candidate.Config{
			Descriptor:       input.Context.Descriptor,
			SessionExpiresAt: input.UnderlayMark.ExpiresAt.UTC(),
			Dialer:           dialer,
			Underlay:         underlay,
			Tunnel:           tunnel,
			Verifier:         builder.config.Verifier,
			Transactions:     builder.config.Transactions,
			Now:              builder.config.Now,
			TeardownTimeout:  builder.config.TeardownTimeout,
		},
		builder.config.WarmAge,
	)
	if err != nil {
		return preparation.CandidateBuild{},
			fmt.Errorf("prepare live authenticated H3 carrier: %w", err)
	}
	return preparation.CandidateBuild{
		Candidate:       warm.Candidate,
		ProbeFreshUntil: warm.ProbeFreshUntil,
		Warm:            true,
		WarmUntil:       warm.WarmUntil,
		Resource:        warm.Resource,
	}, nil
}

func validateH3Input(
	input preparation.H3PreparationInput,
	now time.Time,
) error {
	if input.Context.Descriptor.Carrier !=
		connectivity.CarrierHTTP3 ||
		input.Suite != "x25519-mlkem768" ||
		input.AuthorizationMode != "anonymous-token" ||
		input.ReservedCredentials <
			preparation.MinimumReservedCredentialsPerH3 ||
		nilInterface(input.AnonymousCredentials) ||
		input.EndpointTemplate == "" ||
		input.ServerName == "" ||
		input.PublicTarget == "" ||
		input.FixedBackend == "" ||
		input.GatewayPublicKey == "" ||
		input.MinInnerDatagram < 576 ||
		input.MaxInnerDatagram < input.MinInnerDatagram ||
		input.MaxInnerDatagram >
			carrier.AbsoluteMaxDatagram ||
		len(input.ECHConfigList) == 0 ||
		!slices.Contains(input.ALPN, http3.NextProtoH3) ||
		input.UnderlayMark.InterfaceName == "" ||
		input.UnderlayMark.FirewallMark == 0 ||
		!input.UnderlayMark.ExpiresAt.After(now) {
		return errors.New("verified Linux Auto H3 input is invalid")
	}
	return nil
}

func bindDialerToVerifiedInput(
	dialer *carrier.H3Dialer,
	input preparation.H3PreparationInput,
) error {
	if dialer == nil || dialer.Template == nil ||
		dialer.TLSConfig == nil ||
		dialer.ResponseVerifier == nil {
		return errors.New("verified H3 dialer is incomplete")
	}
	if input.AuthorizationMode == carrierauth.AuthModeAnonymousToken {
		if err := carrier.ValidateAnonymousClientTLS(
			dialer.TLSConfig,
		); err != nil {
			return err
		}
		if err := carrier.ValidateAnonymousQUICConfig(
			dialer.QUICConfig,
		); err != nil {
			return err
		}
	}
	if dialer.Template.Raw() != input.EndpointTemplate ||
		dialer.PublicTarget != input.PublicTarget ||
		dialer.Suite.Name != input.Suite ||
		!strings.EqualFold(
			strings.TrimSuffix(dialer.TLSConfig.ServerName, "."),
			input.ServerName,
		) ||
		!bytes.Equal(
			dialer.TLSConfig.EncryptedClientHelloConfigList,
			input.ECHConfigList,
		) ||
		dialer.ResponseVerifier.ControllerID != input.ControllerID {
		return errors.New(
			"constructed H3 dialer differs from verified deployment",
		)
	}
	preparationSession, err := mobility.NewSessionID()
	if err != nil {
		return err
	}
	preparationEpoch, err := mobility.NewSessionID()
	if err != nil {
		return err
	}
	dialer.SessionID = preparationSession
	dialer.SequenceEpoch = preparationEpoch
	dialer.ManifestDigest = input.Context.ManifestDigest
	dialer.AuthorizationMode = input.AuthorizationMode
	dialer.PrivacyToken = nil
	dialer.AnonymousCredentials = input.AnonymousCredentials
	dialer.MaxDatagram = input.MaxInnerDatagram
	dialer.MaxOuterDatagram =
		input.MaxInnerDatagram + h3EnvelopeOverhead
	// Length padding was hardcoded off here, which made the bucket ladder
	// unreachable on the Linux auto path however the deployment was
	// configured, so inner datagram lengths went out 1:1 on a shipped path.
	//
	// H3Dialer derives the signed PrivacyProfile claim from this field, so
	// clearing it also makes the gateway pad the return direction. Padding one
	// direction only would leave the other readable.
	//
	// The assignment is redundant now that the zero value pads, and is kept
	// deliberately: this path is verified against a signed deployment and
	// should state its wire behaviour rather than inherit it.
	dialer.DisableLengthPadding = false
	dialer.DialQUIC = nil
	dialer.DialQUICPath = nil
	return nil
}

func signedH3RemoteEndpoint(
	input preparation.H3PreparationInput,
	preferIPv6 bool,
) (string, error) {
	parsed, err := url.Parse(input.EndpointTemplate)
	if err != nil || parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.User != nil ||
		!strings.EqualFold(parsed.Hostname(), input.ServerName) {
		return "", errors.New(
			"verified H3 endpoint template is not an absolute signed authority",
		)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	numericPort, err := strconv.Atoi(port)
	if err != nil || numericPort < 1 || numericPort > 65535 {
		return "", errors.New("verified H3 authority port is invalid")
	}
	selectHint := func(source []string, ipv6 bool) net.IP {
		for _, hint := range source {
			current := net.ParseIP(hint)
			if current == nil || current.IsUnspecified() ||
				current.IsMulticast() {
				continue
			}
			if (current.To4() == nil) == ipv6 {
				return current
			}
		}
		return nil
	}
	var selected net.IP
	if preferIPv6 {
		selected = selectHint(input.IPv6Hints, true)
	}
	if selected == nil {
		selected = selectHint(input.IPv4Hints, false)
	}
	if selected == nil && !preferIPv6 {
		selected = selectHint(input.IPv6Hints, true)
	}
	if selected == nil {
		return "", errors.New(
			"verified H3 transport has no usable signed IP hint",
		)
	}
	return net.JoinHostPort(selected.String(), port), nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
