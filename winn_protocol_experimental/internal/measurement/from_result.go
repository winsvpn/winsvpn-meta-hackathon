package measurement

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

// AttemptMetadata contains immutable build/environment facts that are outside
// the connectivity coordinator. Result-derived fields cannot be overridden.
type AttemptMetadata struct {
	SourceDigest   string
	ArtifactDigest string
	ManifestDigest string
	Platform       string
	OSVersion      string
	Device         string
	Readiness      ReadinessClass
	CandidateIDs   []string
	Network        NetworkProfile
	Metrics        Metrics

	// EvidenceStartedAt is optional. Warm measurements leave it zero and
	// therefore begin at the coordinator's click boundary. A true cold
	// measurement sets it immediately before verified preparation begins.
	// Predicate timestamps are then rebased onto that earlier boundary
	// without changing the coordinator's authoritative result.
	EvidenceStartedAt time.Time
}

// FromConnectivityResult builds one evidence record from the coordinator's
// authoritative result and measured predicate timings.
func FromConnectivityResult(
	result connectivity.Result,
	metadata AttemptMetadata,
) (Attempt, error) {
	if result.AttemptID == "" ||
		result.StartedAt.IsZero() ||
		result.FinishedAt.IsZero() {
		return Attempt{}, errors.New(
			"connectivity result lacks attempt identity or timestamps",
		)
	}
	if result.StartedAt.Location() != time.UTC ||
		result.FinishedAt.Location() != time.UTC {
		return Attempt{}, errors.New(
			"connectivity result timestamps must be UTC",
		)
	}
	if result.Timings.Outcome !=
		result.FinishedAt.Sub(result.StartedAt) {
		return Attempt{}, errors.New(
			"connectivity result outcome timing is not authoritative",
		)
	}
	evidenceStartedAt := result.StartedAt
	prefix := time.Duration(0)
	if !metadata.EvidenceStartedAt.IsZero() {
		if metadata.EvidenceStartedAt.Location() != time.UTC {
			return Attempt{}, errors.New(
				"measurement evidence start must be UTC",
			)
		}
		if metadata.EvidenceStartedAt.After(result.StartedAt) {
			return Attempt{}, errors.New(
				"measurement evidence start follows connectivity start",
			)
		}
		evidenceStartedAt = metadata.EvidenceStartedAt
		prefix = result.StartedAt.Sub(evidenceStartedAt)
	}
	outcome := OutcomeFailure
	failure := result.Failure
	if result.Success() {
		outcome = OutcomeSuccess
		failure = connectivity.FailureNone
	} else if !connectivity.ValidFailureCode(failure) {
		return Attempt{}, fmt.Errorf(
			"connectivity result failure %q is invalid",
			failure,
		)
	}
	attempt := Attempt{
		AttemptID:         result.AttemptID,
		SourceDigest:      metadata.SourceDigest,
		ArtifactDigest:    metadata.ArtifactDigest,
		ProtocolVersion:   connectivity.Version,
		ManifestDigest:    metadata.ManifestDigest,
		TrustFingerprint:  result.TrustFingerprint,
		Platform:          metadata.Platform,
		OSVersion:         metadata.OSVersion,
		Device:            metadata.Device,
		Mode:              result.Mode,
		Readiness:         metadata.Readiness,
		CandidateIDs:      slices.Clone(metadata.CandidateIDs),
		SelectedCandidate: result.CandidateID,
		Network:           metadata.Network,
		StartedAt:         evidenceStartedAt.Format(time.RFC3339Nano),
		FinishedAt:        result.FinishedAt.Format(time.RFC3339Nano),
		Outcome:           outcome,
		Failure:           failure,
		Timeline: Timeline{
			DialMicros: rebasePredicate(
				result.Timings.Dial, prefix,
			).Microseconds(),
			HandshakeMicros: rebasePredicate(
				result.Timings.Handshake, prefix,
			).Microseconds(),
			BidirectionalMicros: rebasePredicate(
				result.Timings.Bidirectional, prefix,
			).Microseconds(),
			DNSMicros: rebasePredicate(
				result.Timings.DNS, prefix,
			).Microseconds(),
			CanaryMicros: rebasePredicate(
				result.Timings.Canary, prefix,
			).Microseconds(),
			CommitMicros: rebasePredicate(
				result.Timings.Commit, prefix,
			).Microseconds(),
			OutcomeMicros: result.FinishedAt.Sub(
				evidenceStartedAt,
			).Microseconds(),
		},
		Metrics: metadata.Metrics,
	}
	if err := ValidateAttempt(attempt); err != nil {
		return Attempt{}, fmt.Errorf(
			"connectivity result cannot form measurement evidence: %w",
			err,
		)
	}
	return attempt, nil
}

func rebasePredicate(value, prefix time.Duration) time.Duration {
	if value <= 0 {
		return value
	}
	return value + prefix
}
