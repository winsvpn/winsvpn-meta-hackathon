package realcycle

import (
	"errors"
	"fmt"
	"slices"
)

const (
	leaseCommitObjectDomain      = "winn-real-credential-lease-object/v1"
	leaseCommitSignatureDomain   = "winn-real-credential-lease-signature/v1"
	leaseTerminalSignatureDomain = "winn-real-credential-lease-terminal-signature/v1"
)

type TokenClassCommitment struct {
	CandidateID   string `json:"candidate_id"`
	NodeID        string `json:"node_id"`
	ServiceID     string `json:"service_id"`
	Transport     string `json:"transport"`
	TokenKeyID    string `json:"token_key_id"`
	Scope         string `json:"scope"`
	IssuerDomain  string `json:"issuer_domain"`
	Count         uint64 `json:"count"`
	ConsumedCount uint64 `json:"consumed_count"`
	CommitmentSHA string `json:"commitment_sha256"`
}

type LeaseCommit struct {
	Schema                  string                 `json:"schema"`
	CycleBindingDigest      string                 `json:"cycle_binding_digest"`
	RuntimeCollectionDigest string                 `json:"runtime_collection_digest"`
	LeaseID                 string                 `json:"lease_id"`
	ReservationID           string                 `json:"reservation_id"`
	AttemptID               string                 `json:"attempt_id"`
	State                   string                 `json:"state"`
	PreparedAt              string                 `json:"prepared_at"`
	CounterDomain           string                 `json:"counter_domain"`
	PreparedCounter         uint64                 `json:"prepared_counter"`
	CommittedAt             string                 `json:"committed_at"`
	CommittedCounter        uint64                 `json:"committed_counter"`
	ExpiresAt               string                 `json:"expires_at"`
	PSKGeneration           uint64                 `json:"psk_generation"`
	PSKKeyID                string                 `json:"psk_key_id"`
	PeerPublicKey           string                 `json:"peer_public_key"`
	VaultRevisionBefore     uint64                 `json:"vault_revision_before"`
	VaultRevisionAfter      uint64                 `json:"vault_revision_after"`
	TokenClasses            []TokenClassCommitment `json:"token_classes"`
	PublisherKeyID          string                 `json:"publisher_key_id"`
	Signature               string                 `json:"signature"`
}

type LeaseTerminal struct {
	Schema             string `json:"schema"`
	CycleBindingDigest string `json:"cycle_binding_digest"`
	LeaseObjectDigest  string `json:"lease_object_digest"`
	LeaseID            string `json:"lease_id"`
	AttemptID          string `json:"attempt_id"`
	Disposition        string `json:"disposition"`
	TerminalAt         string `json:"terminal_at"`
	CounterDomain      string `json:"counter_domain"`
	TerminalCounter    uint64 `json:"terminal_counter"`
	VaultRevision      uint64 `json:"vault_revision"`
	PublisherKeyID     string `json:"publisher_key_id"`
	Signature          string `json:"signature"`
}

type LeaseEvidence struct {
	Commit   LeaseCommit   `json:"commit"`
	Terminal LeaseTerminal `json:"terminal"`
}

type leaseCommitUnsigned struct {
	Schema                  string                 `json:"schema"`
	CycleBindingDigest      string                 `json:"cycle_binding_digest"`
	RuntimeCollectionDigest string                 `json:"runtime_collection_digest"`
	LeaseID                 string                 `json:"lease_id"`
	ReservationID           string                 `json:"reservation_id"`
	AttemptID               string                 `json:"attempt_id"`
	State                   string                 `json:"state"`
	PreparedAt              string                 `json:"prepared_at"`
	CounterDomain           string                 `json:"counter_domain"`
	PreparedCounter         uint64                 `json:"prepared_counter"`
	CommittedAt             string                 `json:"committed_at"`
	CommittedCounter        uint64                 `json:"committed_counter"`
	ExpiresAt               string                 `json:"expires_at"`
	PSKGeneration           uint64                 `json:"psk_generation"`
	PSKKeyID                string                 `json:"psk_key_id"`
	PeerPublicKey           string                 `json:"peer_public_key"`
	VaultRevisionBefore     uint64                 `json:"vault_revision_before"`
	VaultRevisionAfter      uint64                 `json:"vault_revision_after"`
	TokenClasses            []TokenClassCommitment `json:"token_classes"`
	PublisherKeyID          string                 `json:"publisher_key_id"`
}

type leaseTerminalUnsigned struct {
	Schema             string `json:"schema"`
	CycleBindingDigest string `json:"cycle_binding_digest"`
	LeaseObjectDigest  string `json:"lease_object_digest"`
	LeaseID            string `json:"lease_id"`
	AttemptID          string `json:"attempt_id"`
	Disposition        string `json:"disposition"`
	TerminalAt         string `json:"terminal_at"`
	CounterDomain      string `json:"counter_domain"`
	TerminalCounter    uint64 `json:"terminal_counter"`
	VaultRevision      uint64 `json:"vault_revision"`
	PublisherKeyID     string `json:"publisher_key_id"`
}

type leaseValidation struct {
	commitDigest     string
	committedAt      int64
	committedCounter uint64
	expiresAt        int64
	terminalAt       int64
	terminalCounter  uint64
	disposition      string
	consumedByNode   map[string]uint64
}

func leaseCommitUnsignedOf(value LeaseCommit) leaseCommitUnsigned {
	return leaseCommitUnsigned{
		Schema:                  value.Schema,
		CycleBindingDigest:      value.CycleBindingDigest,
		RuntimeCollectionDigest: value.RuntimeCollectionDigest,
		LeaseID:                 value.LeaseID, ReservationID: value.ReservationID,
		AttemptID: value.AttemptID, State: value.State,
		PreparedAt: value.PreparedAt, CounterDomain: value.CounterDomain,
		PreparedCounter:  value.PreparedCounter,
		CommittedAt:      value.CommittedAt,
		CommittedCounter: value.CommittedCounter,
		ExpiresAt:        value.ExpiresAt, PSKGeneration: value.PSKGeneration,
		PSKKeyID: value.PSKKeyID, PeerPublicKey: value.PeerPublicKey,
		VaultRevisionBefore: value.VaultRevisionBefore,
		VaultRevisionAfter:  value.VaultRevisionAfter,
		TokenClasses:        slices.Clone(value.TokenClasses),
		PublisherKeyID:      value.PublisherKeyID,
	}
}

func leaseTerminalUnsignedOf(value LeaseTerminal) leaseTerminalUnsigned {
	return leaseTerminalUnsigned{
		Schema:             value.Schema,
		CycleBindingDigest: value.CycleBindingDigest,
		LeaseObjectDigest:  value.LeaseObjectDigest,
		LeaseID:            value.LeaseID, AttemptID: value.AttemptID,
		Disposition: value.Disposition, TerminalAt: value.TerminalAt,
		CounterDomain:   value.CounterDomain,
		TerminalCounter: value.TerminalCounter,
		VaultRevision:   value.VaultRevision,
		PublisherKeyID:  value.PublisherKeyID,
	}
}

func validateLease(
	evidence LeaseEvidence,
	cycle Cycle,
	runtime RuntimeSet,
	runtimeResult runtimeValidation,
	keys trustIndex,
	acceptedAt, trustExpiry int64,
) (leaseValidation, error) {
	commit := evidence.Commit
	if commit.Schema != LeaseSchema ||
		commit.CycleBindingDigest != cycle.BindingDigest ||
		commit.RuntimeCollectionDigest != runtime.CollectionDigest ||
		commit.AttemptID != cycle.AttemptID ||
		!validID(commit.LeaseID) || !validID(commit.ReservationID) ||
		commit.State != "committed" || commit.PSKGeneration == 0 ||
		!validID(commit.PSKKeyID) ||
		!validKey32(commit.PeerPublicKey) ||
		commit.CounterDomain != cycle.CounterDomain ||
		commit.PreparedCounter <= runtimeResult.latestCounter ||
		commit.CommittedCounter <= commit.PreparedCounter ||
		commit.VaultRevisionAfter <= commit.VaultRevisionBefore ||
		len(commit.TokenClasses) > MaxTokenClasses {
		return leaseValidation{}, errors.New(
			"credential lease commit fields are invalid",
		)
	}
	preparedAt, err := parseTime(commit.PreparedAt)
	if err != nil {
		return leaseValidation{}, fmt.Errorf("lease prepared_at: %w", err)
	}
	committedAt, err := parseTime(commit.CommittedAt)
	if err != nil {
		return leaseValidation{}, fmt.Errorf("lease committed_at: %w", err)
	}
	expiresAt, err := parseTime(commit.ExpiresAt)
	if err != nil ||
		preparedAt.UnixNano() < acceptedAt ||
		preparedAt.UnixNano() <= runtimeResult.latestAt ||
		!committedAt.After(preparedAt) ||
		!expiresAt.After(committedAt) ||
		expiresAt.UnixNano() >= trustExpiry {
		return leaseValidation{}, errors.New(
			"credential lease chronology is invalid",
		)
	}
	seenClasses := make(map[string]struct{}, len(commit.TokenClasses))
	exercised := make(
		map[string]DeploymentBinding, len(cycle.ExercisedNodes),
	)
	for _, row := range cycle.Deployments {
		if slices.Contains(cycle.ExercisedNodes, row.NodeID) {
			exercised[row.NodeID] = row
		}
	}
	consumedByNode := make(map[string]uint64, len(exercised))
	for _, row := range commit.TokenClasses {
		key := row.CandidateID + "\x00" + row.TokenKeyID
		if !validID(row.CandidateID) || !validID(row.NodeID) ||
			!validID(row.ServiceID) ||
			row.Transport != cycle.ExpectedTransport ||
			!validID(row.TokenKeyID) || !validID(row.Scope) ||
			!validID(row.IssuerDomain) || row.Count == 0 ||
			row.ConsumedCount > row.Count ||
			!validDigest(row.CommitmentSHA) {
			return leaseValidation{}, errors.New(
				"token class commitment is invalid",
			)
		}
		deployment, ok := exercised[row.NodeID]
		if !ok || deployment.ServiceID != row.ServiceID {
			return leaseValidation{}, errors.New(
				"token class is not bound to an exercised service",
			)
		}
		if _, duplicate := seenClasses[key]; duplicate {
			return leaseValidation{}, errors.New(
				"duplicate token class commitment",
			)
		}
		seenClasses[key] = struct{}{}
		consumedByNode[row.NodeID] += row.ConsumedCount
	}
	if cycle.ExpectedTransport == TransportH3 {
		for node := range exercised {
			if consumedByNode[node] == 0 {
				return leaseValidation{}, errors.New(
					"exercised H3 node lacks consumed token commitment",
				)
			}
		}
	} else if len(commit.TokenClasses) != 0 {
		//lint:ignore ST1005 Direct AWG is a proper product term.
		return leaseValidation{}, errors.New(
			"Direct AWG lease contains token classes",
		)
	}
	unsignedCommit := leaseCommitUnsignedOf(commit)
	if err := verifySignature(
		keys, commit.PublisherKeyID, KeyRoleLease, "",
		leaseCommitSignatureDomain, commit.Signature, unsignedCommit,
	); err != nil {
		return leaseValidation{}, fmt.Errorf(
			"credential lease commit: %w", err,
		)
	}
	commitDigest, err := digestObject(leaseCommitObjectDomain, commit)
	if err != nil {
		return leaseValidation{}, err
	}
	terminal := evidence.Terminal
	if terminal.Schema != LeaseEndSchema ||
		terminal.CycleBindingDigest != cycle.BindingDigest ||
		terminal.LeaseObjectDigest != commitDigest ||
		terminal.LeaseID != commit.LeaseID ||
		terminal.AttemptID != cycle.AttemptID ||
		!slices.Contains(
			[]string{"consumed", "burned"},
			terminal.Disposition,
		) ||
		terminal.CounterDomain != cycle.CounterDomain ||
		terminal.TerminalCounter <= commit.CommittedCounter ||
		terminal.VaultRevision < commit.VaultRevisionAfter ||
		terminal.PublisherKeyID != commit.PublisherKeyID {
		return leaseValidation{}, errors.New(
			"credential lease terminal fields are invalid",
		)
	}
	terminalAt, err := parseTime(terminal.TerminalAt)
	if err != nil || !terminalAt.After(committedAt) ||
		terminalAt.UnixNano() >= trustExpiry ||
		terminalAt.After(expiresAt) {
		return leaseValidation{}, errors.New(
			"credential lease terminal chronology is invalid",
		)
	}
	if err := verifySignature(
		keys, terminal.PublisherKeyID, KeyRoleLease, "",
		leaseTerminalSignatureDomain, terminal.Signature,
		leaseTerminalUnsignedOf(terminal),
	); err != nil {
		return leaseValidation{}, fmt.Errorf(
			"credential lease terminal: %w", err,
		)
	}
	return leaseValidation{
		commitDigest:     commitDigest,
		committedAt:      committedAt.UnixNano(),
		committedCounter: commit.CommittedCounter,
		expiresAt:        expiresAt.UnixNano(),
		terminalAt:       terminalAt.UnixNano(),
		terminalCounter:  terminal.TerminalCounter,
		disposition:      terminal.Disposition,
		consumedByNode:   consumedByNode,
	}, nil
}
