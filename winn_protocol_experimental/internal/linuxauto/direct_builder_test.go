package linuxauto

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/preparation"
)

func TestDirectBuilderRequiresAndCarriesRealProbeEvidence(t *testing.T) {
	now := time.Now().UTC()
	resource := &builderTestResource{}
	controller := &builderTestController{}
	var dialerFactoryCalls atomic.Int32
	builder, err := NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return controller, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			return DirectProbeResult{
				FreshUntil: now.Add(20 * time.Second),
				Resource:   resource,
			}, nil
		},
		DialerFactory: func(
			authorization preparation.UnderlayMarkAuthorization,
		) (directawg.RemoteDialer, error) {
			if authorization.InterfaceName != "eth0" ||
				authorization.FirewallMark != 7 {
				t.Fatalf(
					"dialer authorization = %#v", authorization,
				)
			}
			dialerFactoryCalls.Add(1)
			return builderTestDialer{}, nil
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	input := validDirectBuilderInput(now)
	build, err := builder.PrepareDirectAWG(
		context.Background(), input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if build.Candidate.Descriptor() != input.Context.Descriptor ||
		build.Warm ||
		!build.ProbeFreshUntil.Equal(now.Add(20*time.Second)) ||
		build.Resource != resource {
		t.Fatalf("DirectAWG build = %#v", build)
	}
	if dialerFactoryCalls.Load() != 1 {
		t.Fatalf(
			"dialer factory calls=%d, want 1",
			dialerFactoryCalls.Load(),
		)
	}
	if err := build.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resource.closed.Load() != 1 {
		t.Fatal("probe resource was not owned by candidate build")
	}
}

func TestDirectBuilderRejectsConfigurationOnlyProbe(t *testing.T) {
	now := time.Now().UTC()
	builder, err := NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return &builderTestController{}, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			return DirectProbeResult{
				FreshUntil: now.Add(time.Minute),
			}, nil
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.PrepareDirectAWG(
		context.Background(), validDirectBuilderInput(now),
	); err == nil {
		t.Fatal("configuration-only DirectAWG probe was accepted")
	}
}

func TestDirectBuilderBoundsFreshnessFromPostProbeObservation(
	t *testing.T,
) {
	startedAt := time.Now().UTC()
	current := startedAt
	resource := &builderTestResource{}
	builder, err := NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return &builderTestController{}, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			current = startedAt.Add(5 * time.Second)
			return DirectProbeResult{
				FreshUntil: current.Add(30 * time.Second),
				Resource:   resource,
			}, nil
		},
		MaxProbeAge: 30 * time.Second,
		Now:         func() time.Time { return current },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := builder.PrepareDirectAWG(
		context.Background(), validDirectBuilderInput(startedAt),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !build.ProbeFreshUntil.Equal(
		startedAt.Add(35 * time.Second),
	) {
		t.Fatalf(
			"post-probe freshness = %v",
			build.ProbeFreshUntil,
		)
	}
	if err := build.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDirectBuilderUsesColdProbeLiveCandidateWithoutSecondController(
	t *testing.T,
) {
	now := time.Now().UTC()
	input := validDirectBuilderInput(now)
	input.Context.PreconnectBinding = coldDirectTestBinding(now)
	input.Context.PreconnectBinding.ManifestDigest =
		input.Context.ManifestDigest
	input.Context.PreconnectBinding.Profile = input.Context.Profile
	input.Context.PreconnectBinding.CandidateID =
		input.Context.Descriptor.ID
	input.Context.PreconnectBinding.NodeID =
		input.Context.Descriptor.NodeID
	input.Context.PreconnectBinding.ExpiresAt = now.Add(20 * time.Second)
	var controllerCalls atomic.Int32
	var dials atomic.Int32
	live := runtimeCandidate{
		descriptor: input.Context.Descriptor,
		dials:      &dials,
	}
	resource := &builderTestResource{}
	builder, err := NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			controllerCalls.Add(1)
			return &builderTestController{}, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			return DirectProbeResult{
				FreshUntil: now.Add(20 * time.Second),
				Resource:   resource,
				Candidate:  live,
			}, nil
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := builder.PrepareDirectAWG(
		context.Background(), input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if build.Candidate.Descriptor() != input.Context.Descriptor ||
		build.Resource != resource ||
		controllerCalls.Load() != 0 {
		t.Fatalf(
			"cold build=%#v controller_calls=%d",
			build,
			controllerCalls.Load(),
		)
	}
}

func TestDirectBuilderDefaultsZeroSocketBufferBytes(t *testing.T) {
	builder, err := NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return &builderTestController{}, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			return DirectProbeResult{}, errors.New("not used")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if builder.config.SocketBufferBytes != defaultDirectSocketBufferBytes {
		t.Fatalf(
			"zero SocketBufferBytes stored %d, want default %d",
			builder.config.SocketBufferBytes,
			defaultDirectSocketBufferBytes,
		)
	}
	explicit := 4 << 20
	builder, err = NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return &builderTestController{}, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			return DirectProbeResult{}, errors.New("not used")
		},
		SocketBufferBytes: explicit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if builder.config.SocketBufferBytes != explicit {
		t.Fatalf(
			"explicit SocketBufferBytes stored %d, want %d",
			builder.config.SocketBufferBytes,
			explicit,
		)
	}
}

func TestDirectBuilderRejectsOversizedSocketBufferBytes(t *testing.T) {
	if _, err := NewDirectBuilder(DirectBuilderConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return &builderTestController{}, nil
		},
		Probe: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (DirectProbeResult, error) {
			return DirectProbeResult{}, errors.New("not used")
		},
		SocketBufferBytes: carrier.MaxRelaySocketBufferBytes + 1,
	}); err == nil {
		t.Fatal("oversized DirectAWG socket buffer was accepted")
	}
}

func TestNormalizeDirectSocketBufferBytesZeroBecomesDefault(t *testing.T) {
	got, err := normalizeDirectSocketBufferBytes(0)
	if err != nil {
		t.Fatal(err)
	}
	if got != defaultDirectSocketBufferBytes {
		t.Fatalf("normalize(0) = %d, want %d", got, defaultDirectSocketBufferBytes)
	}
	if defaultDirectSocketBufferBytes != 8<<20 {
		t.Fatalf(
			"defaultDirectSocketBufferBytes = %d, want 8 MiB",
			defaultDirectSocketBufferBytes,
		)
	}
	if _, err := normalizeDirectSocketBufferBytes(-1); err == nil {
		t.Fatal("negative socket buffer was accepted")
	}
	if _, err := normalizeDirectSocketBufferBytes(
		carrier.MaxRelaySocketBufferBytes + 1,
	); err == nil {
		t.Fatal("oversized socket buffer was accepted")
	}
}

func validDirectBuilderInput(
	now time.Time,
) preparation.DirectAWGPreparationInput {
	publicKey := make([]byte, 32)
	publicKey[0] = 1
	return preparation.DirectAWGPreparationInput{
		Context: preparation.CandidateContext{
			Profile:           "auto",
			Mode:              connectivity.ModeAuto,
			ManifestDigest:    strings.Repeat("b", 64),
			ManifestExpiresAt: now.Add(time.Hour),
			PSKGeneration:     1,
			PSKExpiresAt:      now.Add(time.Hour),
			Descriptor: connectivity.CandidateDescriptor{
				ID:        "direct-primary",
				Carrier:   connectivity.CarrierDirectAWG,
				NodeID:    "gateway-primary",
				ExpiresAt: now.Add(time.Hour),
			},
		},
		ManifestSequence: 1,
		ControllerID:     "controller-primary",
		Suite:            "x25519-mlkem768",
		Endpoint:         "198.51.100.10:51820",
		GatewayPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		MinInnerDatagram: 576,
		MaxInnerDatagram: 1280,
		UnderlayMark: preparation.UnderlayMarkAuthorization{
			AuthorizationID: "underlay-direct",
			InterfaceName:   "eth0",
			FirewallMark:    7,
			ExpiresAt:       now.Add(time.Hour),
		},
	}
}

type builderTestResource struct {
	closed atomic.Int64
}

type builderTestDialer struct{}

func (builderTestDialer) Dial(
	context.Context,
	string,
) (net.PacketConn, error) {
	return nil, errors.New("builder test dialer is not executed")
}

func (resource *builderTestResource) Close(context.Context) error {
	resource.closed.Add(1)
	return nil
}

type builderTestController struct{}

func (*builderTestController) Prepare(
	context.Context,
	directawg.Preparation,
) (directawg.PreparedTunnel, error) {
	return directawg.PreparedTunnel{
		Session:             &builderTestSession{health: make(chan error)},
		Baseline:            directawg.Status{},
		LocalSourceEndpoint: "127.0.0.1:1",
	}, nil
}

type builderTestSession struct {
	health chan error
}

func (*builderTestSession) Status(
	context.Context,
) (directawg.Status, error) {
	return directawg.Status{}, nil
}

func (*builderTestSession) VerifyProtectedDNS(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*builderTestSession) VerifyTunnelCanary(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*builderTestSession) Commit(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (session *builderTestSession) Health() <-chan error {
	return session.health
}

func (*builderTestSession) Close() error {
	return nil
}
