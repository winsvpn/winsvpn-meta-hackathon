package measurement

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const operationFailureDomain = "winn-measurement-operation-failure/v1\x00"

// FromOperationFailure creates authenticated denominator evidence when an
// attempt aborts before the connectivity coordinator can return its normal
// authoritative Result. It records no error text or secret material.
func FromOperationFailure(
	mode connectivity.Mode,
	failure connectivity.FailureCode,
	startedAt time.Time,
	finishedAt time.Time,
	metadata AttemptMetadata,
) (Attempt, error) {
	startedAt = startedAt.UTC()
	finishedAt = finishedAt.UTC()
	if startedAt.IsZero() || finishedAt.Before(startedAt) {
		return Attempt{}, errors.New(
			"operation failure timestamps are invalid",
		)
	}
	if !connectivity.ValidMode(mode) ||
		!connectivity.ValidFailureCode(failure) {
		return Attempt{}, errors.New(
			"operation failure mode or failure code is invalid",
		)
	}
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return Attempt{}, err
	}
	attemptID := hex.EncodeToString(randomID[:])
	fingerprintInput, err := json.Marshal(struct {
		Domain         string
		AttemptID      string
		SourceDigest   string
		ArtifactDigest string
		ManifestDigest string
		Mode           connectivity.Mode
		Readiness      ReadinessClass
		CandidateIDs   []string
		StartedAt      string
		FinishedAt     string
		Failure        connectivity.FailureCode
	}{
		Domain:         operationFailureDomain,
		AttemptID:      attemptID,
		SourceDigest:   metadata.SourceDigest,
		ArtifactDigest: metadata.ArtifactDigest,
		ManifestDigest: metadata.ManifestDigest,
		Mode:           mode,
		Readiness:      metadata.Readiness,
		CandidateIDs:   metadata.CandidateIDs,
		StartedAt:      startedAt.Format(time.RFC3339Nano),
		FinishedAt:     finishedAt.Format(time.RFC3339Nano),
		Failure:        failure,
	})
	if err != nil {
		return Attempt{}, err
	}
	fingerprint := sha256.Sum256(fingerprintInput)
	clear(fingerprintInput)
	attempt := Attempt{
		AttemptID:        attemptID,
		SourceDigest:     metadata.SourceDigest,
		ArtifactDigest:   metadata.ArtifactDigest,
		ProtocolVersion:  connectivity.Version,
		ManifestDigest:   metadata.ManifestDigest,
		TrustFingerprint: hex.EncodeToString(fingerprint[:]),
		Platform:         metadata.Platform,
		OSVersion:        metadata.OSVersion,
		Device:           metadata.Device,
		Mode:             mode,
		Readiness:        metadata.Readiness,
		CandidateIDs:     slices.Clone(metadata.CandidateIDs),
		Network:          metadata.Network,
		StartedAt:        startedAt.Format(time.RFC3339Nano),
		FinishedAt:       finishedAt.Format(time.RFC3339Nano),
		Outcome:          OutcomeFailure,
		Failure:          failure,
		Timeline: Timeline{
			OutcomeMicros: finishedAt.Sub(startedAt).Microseconds(),
		},
		Metrics: metadata.Metrics,
	}
	if err := ValidateAttempt(attempt); err != nil {
		return Attempt{}, err
	}
	return attempt, nil
}
