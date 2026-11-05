// Package connectivity defines Winn v3's preparation and verified connection
// contract. It deliberately depends on abstract candidate connections so the
// state machine can be tested before any platform route or tunnel integration.
package connectivity

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

const (
	Version             = "winn/3"
	DefaultDeadline     = 3 * time.Second
	MaxDeadline         = 3 * time.Second
	DefaultReadinessTTL = time.Minute
	MaxCandidates       = 8
)

type Mode string

const (
	ModeFast           Mode = "fast"
	ModeAuto           Mode = "auto"
	ModeStealth        Mode = "stealth"
	ModePrivateRelay   Mode = "private-relay"
	ModeMaximumPrivacy Mode = "maximum-privacy"
)

type Carrier string

const (
	CarrierDirectAWG     Carrier = "direct-awg"
	CarrierHTTP3         Carrier = "http3-connect-udp"
	CarrierHTTP2         Carrier = "http2-stream"
	CarrierRealityXHTTP  Carrier = "reality-xhttp"
	CarrierWebSocketTLS  Carrier = "websocket-tls"
	CarrierNativeTwoHop  Carrier = "native-two-hop"
	CarrierPrivacyTwoHop Carrier = "privacy-two-hop"
)

type State string

const (
	StateCold       State = "cold"
	StatePreparing  State = "preparing"
	StateReady      State = "ready"
	StateConnecting State = "connecting"
	StateOnline     State = "online"
	StateStopping   State = "stopping"
	StateStopped    State = "stopped"
	StateFailed     State = "failed"
)

type FailureCode string

const (
	FailureNone                    FailureCode = ""
	FailureConnectDeadlineExceeded FailureCode = "connect_deadline_exceeded"
	FailureNotReady                FailureCode = "not_ready"
	FailureManifestInvalid         FailureCode = "manifest_invalid"
	FailureCredentialsExhausted    FailureCode = "credentials_exhausted"
	FailureNoReachableCandidate    FailureCode = "no_reachable_candidate"
	FailureHandshakeFailed         FailureCode = "handshake_failed"
	FailureBidirectionalFailed     FailureCode = "bidirectional_failed"
	FailureDNSVerificationFailed   FailureCode = "dns_verification_failed"
	FailureCanaryFailed            FailureCode = "canary_failed"
	FailureCommitFailed            FailureCode = "commit_failed"
	FailureModePolicyViolation     FailureCode = "mode_policy_violation"
	FailureConnectInProgress       FailureCode = "connect_in_progress"
	FailureNetworkChanged          FailureCode = "network_changed"
	FailurePostCommitHealth        FailureCode = "post_commit_health_failed"
	FailureStoppedByUser           FailureCode = "stopped_by_user"
	FailureTeardownFailed          FailureCode = "teardown_failed"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sessionPattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type CandidateDescriptor struct {
	ID        string
	Carrier   Carrier
	NodeID    string
	ExpiresAt time.Time
}

func (descriptor CandidateDescriptor) Validate(now time.Time) error {
	if !validIdentifier(descriptor.ID) {
		return errors.New("candidate ID is invalid")
	}
	if !validIdentifier(descriptor.NodeID) {
		return errors.New("candidate node ID is invalid")
	}
	if !ValidCarrier(descriptor.Carrier) {
		return fmt.Errorf("candidate carrier %q is unsupported", descriptor.Carrier)
	}
	if descriptor.ExpiresAt.IsZero() || !descriptor.ExpiresAt.After(now) {
		return errors.New("candidate is expired")
	}
	return nil
}

type Readiness struct {
	Profile           string
	Mode              Mode
	ManifestDigest    string
	ManifestExpiresAt time.Time
	PSKGeneration     uint64
	PSKExpiresAt      time.Time
	UnusedCredentials int
	PreparedAt        time.Time
	ExpiresAt         time.Time
	Candidates        []CandidateDescriptor
	Blockers          []FailureCode
}

func (readiness Readiness) Validate(now time.Time) error {
	if !validIdentifier(readiness.Profile) {
		return errors.New("readiness profile is invalid")
	}
	if !ValidMode(readiness.Mode) {
		return errors.New("readiness mode is invalid")
	}
	if !digestPattern.MatchString(readiness.ManifestDigest) {
		return errors.New("readiness manifest digest is invalid")
	}
	if readiness.ManifestExpiresAt.IsZero() ||
		!readiness.ManifestExpiresAt.After(now) {
		return errors.New("readiness manifest is expired")
	}
	if readiness.PSKGeneration == 0 || readiness.PSKExpiresAt.IsZero() ||
		!readiness.PSKExpiresAt.After(now) {
		return errors.New("readiness PSK is missing or expired")
	}
	if readiness.UnusedCredentials < 0 || readiness.UnusedCredentials > 1024 {
		return errors.New("readiness credential count is invalid")
	}
	if readiness.PreparedAt.IsZero() || readiness.PreparedAt.After(now) ||
		readiness.ExpiresAt.IsZero() || !readiness.ExpiresAt.After(now) ||
		readiness.ExpiresAt.Sub(readiness.PreparedAt) > DefaultReadinessTTL {
		return errors.New("readiness lifetime is invalid")
	}
	if readiness.ExpiresAt.After(readiness.ManifestExpiresAt) ||
		readiness.ExpiresAt.After(readiness.PSKExpiresAt) {
		return errors.New(
			"readiness outlives manifest or PSK trust state",
		)
	}
	if len(readiness.Candidates) == 0 || len(readiness.Candidates) > MaxCandidates {
		return errors.New("readiness candidate count is invalid")
	}
	seen := make(map[string]struct{}, len(readiness.Candidates))
	for _, candidate := range readiness.Candidates {
		if err := candidate.Validate(now); err != nil {
			return fmt.Errorf("readiness candidate: %w", err)
		}
		if !readiness.Mode.Allows(candidate.Carrier) {
			return fmt.Errorf(
				"mode %q does not permit carrier %q",
				readiness.Mode, candidate.Carrier,
			)
		}
		if candidate.ExpiresAt.After(readiness.ManifestExpiresAt) ||
			candidate.ExpiresAt.After(readiness.PSKExpiresAt) {
			return errors.New(
				"readiness candidate outlives manifest or PSK",
			)
		}
		if _, duplicate := seen[candidate.ID]; duplicate {
			return fmt.Errorf("duplicate readiness candidate %q", candidate.ID)
		}
		seen[candidate.ID] = struct{}{}
	}
	if len(readiness.Blockers) != 0 {
		return fmt.Errorf("readiness is blocked: %s", readiness.Blockers[0])
	}
	return nil
}

func (readiness Readiness) CandidateIDs() []string {
	ids := make([]string, 0, len(readiness.Candidates))
	for _, candidate := range readiness.Candidates {
		ids = append(ids, candidate.ID)
	}
	slices.Sort(ids)
	return ids
}

type Predicates struct {
	FreshAWGHandshake bool
	Bidirectional     bool
	ProtectedDNS      bool
	TunnelCanary      bool
}

func (predicates Predicates) Verified() bool {
	return predicates.FreshAWGHandshake &&
		predicates.Bidirectional &&
		predicates.ProtectedDNS &&
		predicates.TunnelCanary
}

type Binding struct {
	AttemptID      string
	Profile        string
	Mode           Mode
	ManifestDigest string
	CandidateID    string
	NodeID         string
	SessionID      string
	PSKGeneration  uint64
	SequenceEpoch  uint64
	Nonce          string
	ExpiresAt      time.Time
}

func (binding Binding) Validate(now time.Time) error {
	if !sessionPattern.MatchString(binding.AttemptID) ||
		!validIdentifier(binding.Profile) ||
		!validIdentifier(binding.CandidateID) ||
		!validIdentifier(binding.NodeID) ||
		!sessionPattern.MatchString(binding.SessionID) ||
		!sessionPattern.MatchString(binding.Nonce) {
		return errors.New("candidate binding contains an invalid identifier")
	}
	if !ValidMode(binding.Mode) {
		return errors.New("candidate binding mode is invalid")
	}
	if !digestPattern.MatchString(binding.ManifestDigest) {
		return errors.New("candidate binding manifest digest is invalid")
	}
	if binding.PSKGeneration == 0 || binding.SequenceEpoch == 0 {
		return errors.New("candidate binding generation and epoch are required")
	}
	if binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(now) {
		return errors.New("candidate binding is expired")
	}
	return nil
}

type Event struct {
	AttemptID   string
	Timestamp   time.Time
	State       State
	Mode        Mode
	CandidateID string
	Reason      FailureCode
}

type Timings struct {
	Dial          time.Duration
	Handshake     time.Duration
	Bidirectional time.Duration
	DNS           time.Duration
	Canary        time.Duration
	Commit        time.Duration
	Outcome       time.Duration
}

type Result struct {
	AttemptID        string
	TrustFingerprint string
	Profile          string
	Mode             Mode
	State            State
	CandidateID      string
	Carrier          Carrier
	StartedAt        time.Time
	FinishedAt       time.Time
	Predicates       Predicates
	Timings          Timings
	Failure          FailureCode
}

func (result Result) Success() bool {
	return result.State == StateOnline &&
		result.Failure == FailureNone &&
		result.Predicates.Verified()
}

func ValidMode(mode Mode) bool {
	switch mode {
	case ModeFast, ModeAuto, ModeStealth, ModePrivateRelay, ModeMaximumPrivacy:
		return true
	default:
		return false
	}
}

func ValidCarrier(carrier Carrier) bool {
	switch carrier {
	case CarrierDirectAWG, CarrierHTTP3, CarrierHTTP2,
		CarrierRealityXHTTP, CarrierWebSocketTLS,
		CarrierNativeTwoHop, CarrierPrivacyTwoHop:
		return true
	default:
		return false
	}
}

func ValidFailureCode(code FailureCode) bool {
	switch code {
	case FailureConnectDeadlineExceeded,
		FailureNotReady,
		FailureManifestInvalid,
		FailureCredentialsExhausted,
		FailureNoReachableCandidate,
		FailureHandshakeFailed,
		FailureBidirectionalFailed,
		FailureDNSVerificationFailed,
		FailureCanaryFailed,
		FailureCommitFailed,
		FailureModePolicyViolation,
		FailureConnectInProgress,
		FailureNetworkChanged,
		FailurePostCommitHealth,
		FailureStoppedByUser,
		FailureTeardownFailed:
		return true
	default:
		return false
	}
}

func (mode Mode) Allows(carrier Carrier) bool {
	switch mode {
	case ModeFast:
		return carrier == CarrierDirectAWG
	case ModeAuto:
		return carrier == CarrierDirectAWG ||
			carrier == CarrierHTTP3 ||
			carrier == CarrierHTTP2 ||
			carrier == CarrierRealityXHTTP ||
			carrier == CarrierWebSocketTLS
	case ModeStealth:
		return carrier == CarrierRealityXHTTP ||
			carrier == CarrierWebSocketTLS
	case ModePrivateRelay:
		return carrier == CarrierNativeTwoHop
	case ModeMaximumPrivacy:
		return carrier == CarrierPrivacyTwoHop
	default:
		return false
	}
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}
