package preparation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
)

// LinuxUnderlayPolicyAnchorFactory is implemented by
// directawg.LinuxNftResolvedPolicyFactory. The interface keeps the production
// preparation boundary testable without weakening the exact kernel contract.
type LinuxUnderlayPolicyAnchorFactory interface {
	PrepareUnderlayPolicyAnchor(
		context.Context,
		directawg.LinuxUnderlayPolicyAnchorSpec,
	) (directawg.LinuxUnderlayPolicyAnchorLease, error)
}

type LinuxUnderlayPolicyAnchorLeaserConfig struct {
	Factory               LinuxUnderlayPolicyAnchorFactory
	TableName             string
	UnderlayInterface     string
	DirectAWGUnderlayMark uint32
	Now                   func() time.Time
}

// LinuxUnderlayPolicyAnchorLeaser maps a verified H3 preparation request onto
// the DirectAWG policy factory's exact fail-closed Linux anchor.
type LinuxUnderlayPolicyAnchorLeaser struct {
	factory               LinuxUnderlayPolicyAnchorFactory
	tableName             string
	underlayInterface     string
	directAWGUnderlayMark uint32
	now                   func() time.Time
	counter               atomic.Uint64
}

var _ UnderlayPolicyAnchorLeaser = (*LinuxUnderlayPolicyAnchorLeaser)(nil)

func NewLinuxUnderlayPolicyAnchorLeaser(
	config LinuxUnderlayPolicyAnchorLeaserConfig,
) (*LinuxUnderlayPolicyAnchorLeaser, error) {
	if isNil(config.Factory) ||
		!validNftIdentifier(config.TableName) ||
		!validUnderlayInterfaceName(config.UnderlayInterface) ||
		config.DirectAWGUnderlayMark == 0 {
		return nil, errors.New(
			"linux underlay policy anchor configuration is invalid",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &LinuxUnderlayPolicyAnchorLeaser{
		factory:               config.Factory,
		tableName:             config.TableName,
		underlayInterface:     config.UnderlayInterface,
		directAWGUnderlayMark: config.DirectAWGUnderlayMark,
		now:                   config.Now,
	}, nil
}

func (leaser *LinuxUnderlayPolicyAnchorLeaser) AcquireUnderlayPolicyAnchor(
	ctx context.Context,
	request UnderlayPolicyAnchorRequest,
) (UnderlayPolicyAnchorLease, error) {
	if leaser == nil {
		return UnderlayPolicyAnchorLease{},
			errors.New("linux underlay policy anchor leaser is nil")
	}
	if ctx == nil {
		return UnderlayPolicyAnchorLease{},
			errors.New("linux underlay policy anchor context is required")
	}
	now := leaser.now().UTC()
	request.ExpiresAt = request.ExpiresAt.UTC()
	if err := validateUnderlayPolicyAnchorRequest(request, now); err != nil {
		return UnderlayPolicyAnchorLease{}, err
	}
	if cause := context.Cause(ctx); cause != nil {
		return UnderlayPolicyAnchorLease{}, cause
	}

	spec := directawg.LinuxUnderlayPolicyAnchorSpec{
		TableFamily:           "inet",
		TableName:             leaser.tableName,
		OutputChain:           "output",
		UnderlayInterface:     leaser.underlayInterface,
		DirectAWGUnderlayMark: leaser.directAWGUnderlayMark,
		ExpiresAt:             request.ExpiresAt,
	}
	anchor, err := leaser.factory.PrepareUnderlayPolicyAnchor(ctx, spec)
	if err != nil {
		return UnderlayPolicyAnchorLease{}, fmt.Errorf(
			"prepare Linux underlay policy anchor: %w", err,
		)
	}
	result := UnderlayPolicyAnchorLease{
		CandidateID:      request.CandidateID,
		NodeID:           request.NodeID,
		Carrier:          request.Carrier,
		ManifestDigest:   request.ManifestDigest,
		ManifestSequence: request.ManifestSequence,
		SignedEndpoint:   request.SignedEndpoint,
		AnchorID: fmt.Sprintf(
			"linux-anchor-%s-%d",
			request.CandidateID,
			leaser.counter.Add(1),
		),
		TableFamily:           anchor.TableFamily,
		TableName:             anchor.TableName,
		OutputChain:           anchor.OutputChain,
		InterfaceName:         anchor.UnderlayInterface,
		DirectAWGFirewallMark: anchor.DirectAWGUnderlayMark,
		ExpiresAt:             anchor.ExpiresAt.UTC(),
		Resource:              anchor.Resource,
	}
	if result.TableFamily != spec.TableFamily ||
		result.TableName != spec.TableName ||
		result.OutputChain != spec.OutputChain ||
		result.InterfaceName != spec.UnderlayInterface ||
		result.DirectAWGFirewallMark != spec.DirectAWGUnderlayMark ||
		!result.ExpiresAt.Equal(spec.ExpiresAt) ||
		isNil(result.Resource) {
		cleanupErr := closeFailedPreparation([]ownedResource{{
			name:     "mismatched Linux underlay policy anchor",
			resource: result.Resource,
		}})
		return UnderlayPolicyAnchorLease{}, errors.Join(
			errors.New(
				"linux underlay policy anchor differs from requested contract",
			),
			cleanupErr,
		)
	}
	return result, nil
}

func validateUnderlayPolicyAnchorRequest(
	request UnderlayPolicyAnchorRequest,
	now time.Time,
) error {
	if !identifierPattern.MatchString(request.CandidateID) ||
		!identifierPattern.MatchString(request.NodeID) ||
		request.Carrier != connectivity.CarrierHTTP3 ||
		!digestPattern.MatchString(request.ManifestDigest) ||
		request.ManifestSequence == 0 ||
		request.SignedEndpoint == "" ||
		len(request.SignedEndpoint) > maxSignedUnderlayEndpoint ||
		strings.IndexByte(request.SignedEndpoint, 0) >= 0 ||
		!request.ExpiresAt.After(now) {
		return errors.New(
			"linux underlay policy anchor request is invalid",
		)
	}
	return nil
}
