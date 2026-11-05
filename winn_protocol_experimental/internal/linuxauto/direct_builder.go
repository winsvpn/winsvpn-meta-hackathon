package linuxauto

import (
	"context"
	"errors"
	"fmt"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/preparation"
)

type DirectControllerFactory func(
	context.Context,
	preparation.DirectAWGPreparationInput,
) (directawg.TunnelController, error)

// DirectProbe must perform real, protected, independently fresh endpoint
// evidence before returning. It must not return a configuration-only success.
// Resource owns every probe object until the generation retires.
type DirectProbe func(
	context.Context,
	preparation.DirectAWGPreparationInput,
) (DirectProbeResult, error)

// DirectProbeResult may include a live candidate only for a true-cold
// operation whose final Binding was allocated before the probe. Ordinary
// background preparation returns freshness evidence and leaves Candidate nil.
type DirectProbeResult struct {
	FreshUntil time.Time
	Resource   preparation.Resource
	Candidate  connectivity.Candidate
}

type DirectBuilderConfig struct {
	ControllerFactory DirectControllerFactory
	Probe             DirectProbe
	DialerFactory     DirectRemoteDialerFactory

	LocalRelayAddress string
	IdleTimeout       time.Duration
	SocketBufferBytes int
	PollInterval      time.Duration
	MaxProbeAge       time.Duration
	Now               func() time.Time
}

// DirectBuilder constructs the production protected raw-AWG candidate only
// after a caller-supplied real probe has returned bounded evidence.
type DirectBuilder struct {
	config DirectBuilderConfig
}

var _ preparation.DirectAWGPreparationBuilder = (*DirectBuilder)(nil)

const defaultDirectSocketBufferBytes = 8 << 20

func NewDirectBuilder(config DirectBuilderConfig) (*DirectBuilder, error) {
	if config.ControllerFactory == nil || config.Probe == nil {
		return nil, errors.New(
			"linux Auto DirectAWG controller and probe are required",
		)
	}
	socketBufferBytes, err := normalizeDirectSocketBufferBytes(
		config.SocketBufferBytes,
	)
	if err != nil {
		return nil, err
	}
	config.SocketBufferBytes = socketBufferBytes
	if config.IdleTimeout < 0 ||
		config.PollInterval < 0 ||
		config.PollInterval > 250*time.Millisecond {
		return nil, errors.New(
			"linux Auto DirectAWG relay configuration is invalid",
		)
	}
	if config.MaxProbeAge == 0 {
		config.MaxProbeAge = 30 * time.Second
	}
	if config.MaxProbeAge <= 0 || config.MaxProbeAge > 5*time.Minute {
		return nil, errors.New(
			"linux Auto DirectAWG probe lifetime is invalid",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.DialerFactory == nil {
		config.DialerFactory = func(
			authorization preparation.UnderlayMarkAuthorization,
		) (directawg.RemoteDialer, error) {
			return directawg.NewLinuxProtectedUDPDialer(
				directawg.LinuxProtectedUDPDialerConfig{
					InterfaceName: authorization.InterfaceName,
					FirewallMark:  authorization.FirewallMark,
				},
			)
		}
	}
	return &DirectBuilder{config: config}, nil
}

func (builder *DirectBuilder) PrepareDirectAWG(
	ctx context.Context,
	input preparation.DirectAWGPreparationInput,
) (preparation.CandidateBuild, error) {
	if builder == nil {
		return preparation.CandidateBuild{},
			errors.New("linux Auto DirectAWG builder is nil")
	}
	if ctx == nil {
		return preparation.CandidateBuild{},
			errors.New("linux Auto DirectAWG context is required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return preparation.CandidateBuild{}, cause
	}
	now := builder.config.Now().UTC()
	if input.Context.Descriptor.Carrier !=
		connectivity.CarrierDirectAWG ||
		input.Endpoint == "" ||
		input.GatewayPublicKey == "" ||
		input.MinInnerDatagram < 576 ||
		input.MaxInnerDatagram < input.MinInnerDatagram ||
		input.MaxInnerDatagram > carrier.AbsoluteMaxDatagram ||
		input.UnderlayMark.InterfaceName == "" ||
		input.UnderlayMark.FirewallMark == 0 ||
		!input.UnderlayMark.ExpiresAt.After(now) {
		return preparation.CandidateBuild{},
			errors.New("verified Linux Auto DirectAWG input is invalid")
	}
	probe, err := builder.config.Probe(ctx, input)
	if err != nil {
		return preparation.CandidateBuild{},
			fmt.Errorf("probe protected DirectAWG endpoint: %w", err)
	}
	freshUntil := probe.FreshUntil
	resource := probe.Resource
	closeProbe := func(cause error) (
		preparation.CandidateBuild,
		error,
	) {
		var closeErr error
		if !nilInterface(resource) {
			closeErr = resource.Close(context.Background())
		}
		return preparation.CandidateBuild{},
			errors.Join(cause, closeErr)
	}
	freshUntil = freshUntil.UTC()
	verifiedAt := builder.config.Now().UTC()
	evidenceLimit := minimumTime(
		input.Context.Descriptor.ExpiresAt.UTC(),
		input.Context.ManifestExpiresAt.UTC(),
		input.Context.PSKExpiresAt.UTC(),
		input.UnderlayMark.ExpiresAt.UTC(),
		verifiedAt.Add(builder.config.MaxProbeAge),
	)
	if !freshUntil.After(verifiedAt) ||
		freshUntil.After(evidenceLimit) ||
		nilInterface(resource) {
		return closeProbe(errors.New(
			"DirectAWG probe returned invalid freshness evidence",
		))
	}
	if !nilInterface(probe.Candidate) {
		if probe.Candidate.Descriptor() != input.Context.Descriptor {
			return closeProbe(errors.New(
				"DirectAWG live probe candidate differs from descriptor",
			))
		}
		return preparation.CandidateBuild{
			Candidate:       probe.Candidate,
			ProbeFreshUntil: freshUntil,
			Resource:        resource,
		}, nil
	}
	if input.Context.PreconnectBinding != (connectivity.Binding{}) {
		return closeProbe(errors.New(
			"cold DirectAWG probe returned no live bound candidate",
		))
	}
	controller, err := builder.config.ControllerFactory(ctx, input)
	if err != nil {
		return closeProbe(fmt.Errorf(
			"construct verified DirectAWG controller: %w", err,
		))
	}
	if nilInterface(controller) {
		return closeProbe(errors.New(
			"verified DirectAWG controller is nil",
		))
	}
	dialer, err := builder.config.DialerFactory(input.UnderlayMark)
	if err != nil {
		return closeProbe(fmt.Errorf(
			"construct protected DirectAWG dialer: %w", err,
		))
	}
	candidate, err := directawg.NewCandidate(directawg.Config{
		Descriptor:        input.Context.Descriptor,
		Endpoint:          input.Endpoint,
		GatewayPublicKey:  input.GatewayPublicKey,
		LocalRelayAddress: builder.config.LocalRelayAddress,
		MinInnerDatagram:  input.MinInnerDatagram,
		MaxInnerDatagram:  input.MaxInnerDatagram,
		IdleTimeout:       builder.config.IdleTimeout,
		SocketBufferBytes: builder.config.SocketBufferBytes,
		PollInterval:      builder.config.PollInterval,
		Controller:        controller,
		Dialer:            dialer,
		Now:               builder.config.Now,
	})
	if err != nil {
		return closeProbe(err)
	}
	return preparation.CandidateBuild{
		Candidate:       candidate,
		ProbeFreshUntil: freshUntil,
		Warm:            false,
		Resource:        resource,
	}, nil
}

func minimumTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

// normalizeDirectSocketBufferBytes maps the omitted (zero) Linux Auto
// DirectAWG buffer size onto the same 8 MiB client default winn3/carrier
// uses. Zero used to be forwarded unchanged; internal/carrier then treats
// zero as "do not call SetReadBuffer/SetWriteBuffer", which is the
// identified client-throughput ceiling. An explicit positive size is kept.
func normalizeDirectSocketBufferBytes(bytes int) (int, error) {
	if bytes == 0 {
		bytes = defaultDirectSocketBufferBytes
	}
	if bytes < 0 || bytes > carrier.MaxRelaySocketBufferBytes {
		return 0, errors.New(
			"linux Auto DirectAWG socket buffer size is invalid",
		)
	}
	return bytes, nil
}
