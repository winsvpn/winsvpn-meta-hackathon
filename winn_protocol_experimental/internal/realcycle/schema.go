// Package realcycle validates the public evidence contract for a future
// external Winn cycle.
//
// The package is deliberately offline and nonauthorizing. In particular, it
// treats the supplied trust bundle as an input whose acceptance must be
// established elsewhere. It never contacts a provider, reads credentials,
// starts a process, or mutates replay state.
package realcycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	TrustSchema       = "winn-real-cycle-trust/v1"
	CycleSchema       = "winn-real-cycle/v1"
	RuntimeSchema     = "winn-real-runtime-attestation/v1"
	RuntimeSetSchema  = "winn-real-runtime-attestation-set/v1"
	LeaseSchema       = "winn-real-credential-lease/v1"
	LeaseEndSchema    = "winn-real-credential-lease-terminal/v1"
	TerminalSchema    = "winn-real-terminal-receipt/v1"
	TerminalSetSchema = "winn-real-terminal-receipt-set/v1"

	CycleFile    = "cycle.json"
	RuntimeFile  = "runtime-attestations.json"
	LeaseFile    = "credential-lease.json"
	TerminalFile = "terminal-receipts.json"

	MaxEvidenceFileBytes = 2 << 20
	MaxTrustFileBytes    = 256 << 10
	MaxEvidenceBytes     = 6 << 20
	MaxStringBytes       = 512
	MaxTokenClasses      = 16
	MaxTrustKeys         = 32
	MaxJSONDepth         = 32
)

const (
	RoleControl        = "control"
	RoleEntryPrimary   = "entry-primary"
	RoleEntrySecondary = "entry-secondary"
	RoleExit           = "exit"

	KeyRoleController          = "controller"
	KeyRoleRuntime             = "runtime-attestor"
	KeyRoleLease               = "lease-publisher"
	KeyRoleTerminal            = "terminal-publisher"
	KeyRoleDispatchAuthorizer  = "dispatch-authorizer"
	KeyRoleExecutionSupervisor = "execution-supervisor"

	TransportDirect = "direct-awg"
	TransportH3     = "h3"
)

var (
	identifierPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`,
	)
	uuidPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
	)
	hex32Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

	requiredRoles = []string{
		RoleControl,
		RoleEntryPrimary,
		RoleEntrySecondary,
		RoleExit,
	}
	evidenceFiles = []string{
		LeaseFile,
		CycleFile,
		RuntimeFile,
		TerminalFile,
	}
)

// TrustBundle is a separately supplied public-key input. Validating this
// object does not establish that it is trusted; the caller must independently
// accept its exact bytes and SHA-256.
type TrustBundle struct {
	Schema       string     `json:"schema"`
	AcceptanceID string     `json:"acceptance_id"`
	AcceptedAt   string     `json:"accepted_at"`
	ExpiresAt    string     `json:"expires_at"`
	Keys         []TrustKey `json:"keys"`
}

type TrustKey struct {
	KeyID     string `json:"key_id"`
	Role      string `json:"role"`
	NodeID    string `json:"node_id,omitempty"`
	PublicKey string `json:"public_key"`
}

// DeploymentBinding repeats the public deployment identity established by E0.
// Runtime evidence must match all fields exactly.
type DeploymentBinding struct {
	Role         string `json:"role"`
	InstanceUUID string `json:"instance_uuid"`
	NodeID       string `json:"node_id"`
	ServiceID    string `json:"service_id"`
	Provider     string `json:"provider"`
	OperatorID   string `json:"operator_id"`
}

// Cycle binds the three evidence documents to one E0 identity and one attempt.
// Evidence hashes are ordinary file SHA-256 values. BindingDigest excludes
// those hashes and Signature, avoiding a digest cycle while still letting all
// evidence objects bind the immutable cycle core.
type Cycle struct {
	Schema            string              `json:"schema"`
	CycleID           string              `json:"cycle_id"`
	AttemptID         string              `json:"attempt_id"`
	TopologyID        string              `json:"topology_id"`
	DescriptorSHA256  string              `json:"descriptor_sha256"`
	BundleSHA256      string              `json:"bundle_sha256"`
	TrustSHA256       string              `json:"trust_sha256"`
	Nonce             string              `json:"nonce"`
	AcceptedAt        string              `json:"accepted_at"`
	CounterDomain     string              `json:"counter_domain"`
	AcceptedCounter   uint64              `json:"accepted_counter"`
	ExpectedTransport string              `json:"expected_transport"`
	ExercisedNodes    []string            `json:"exercised_nodes"`
	Deployments       []DeploymentBinding `json:"deployments"`
	BindingDigest     string              `json:"binding_digest"`
	RuntimeSHA256     string              `json:"runtime_sha256"`
	LeaseSHA256       string              `json:"lease_sha256"`
	TerminalSHA256    string              `json:"terminal_sha256"`
	ControllerKeyID   string              `json:"controller_key_id"`
	Signature         string              `json:"signature"`
}

type cycleCore struct {
	Schema            string              `json:"schema"`
	CycleID           string              `json:"cycle_id"`
	AttemptID         string              `json:"attempt_id"`
	TopologyID        string              `json:"topology_id"`
	DescriptorSHA256  string              `json:"descriptor_sha256"`
	BundleSHA256      string              `json:"bundle_sha256"`
	TrustSHA256       string              `json:"trust_sha256"`
	Nonce             string              `json:"nonce"`
	AcceptedAt        string              `json:"accepted_at"`
	CounterDomain     string              `json:"counter_domain"`
	AcceptedCounter   uint64              `json:"accepted_counter"`
	ExpectedTransport string              `json:"expected_transport"`
	ExercisedNodes    []string            `json:"exercised_nodes"`
	Deployments       []DeploymentBinding `json:"deployments"`
}

// Result contains only structural and cryptographic properties recomputed by
// ValidateBundle. It conveys no cloud, credential, or execution authority.
type Result struct {
	CycleID              string
	AttemptID            string
	TopologyID           string
	BindingDigest        string
	EvidenceBundleSHA256 string
	RuntimeCount         int
	TerminalCount        int
}

type trustedKey struct {
	row TrustKey
	key ed25519.PublicKey
}

type trustIndex map[string]trustedKey

func parseTrust(data []byte) (TrustBundle, trustIndex, error) {
	var trust TrustBundle
	if err := decodeCanonical(data, &trust); err != nil {
		return TrustBundle{}, nil, fmt.Errorf("decode trust bundle: %w", err)
	}
	if trust.Schema != TrustSchema ||
		!validID(trust.AcceptanceID) ||
		len(trust.Keys) == 0 || len(trust.Keys) > MaxTrustKeys {
		return TrustBundle{}, nil, errors.New("trust bundle fields are invalid")
	}
	acceptedAt, err := parseTime(trust.AcceptedAt)
	if err != nil {
		return TrustBundle{}, nil, fmt.Errorf("trust accepted_at: %w", err)
	}
	expiresAt, err := parseTime(trust.ExpiresAt)
	if err != nil || !expiresAt.After(acceptedAt) {
		return TrustBundle{}, nil, errors.New("trust expiry is invalid")
	}
	index := make(trustIndex, len(trust.Keys))
	roleNode := make(map[string]struct{}, len(trust.Keys))
	for _, row := range trust.Keys {
		if !validID(row.KeyID) ||
			!slices.Contains(
				[]string{
					KeyRoleController,
					KeyRoleRuntime,
					KeyRoleLease,
					KeyRoleTerminal,
				},
				row.Role,
			) {
			return TrustBundle{}, nil, errors.New("trust key row is invalid")
		}
		if row.Role == KeyRoleRuntime || row.Role == KeyRoleTerminal {
			if !validID(row.NodeID) {
				return TrustBundle{}, nil,
					errors.New("node-scoped trust key lacks node_id")
			}
		} else if row.NodeID != "" {
			return TrustBundle{}, nil,
				errors.New("global trust key unexpectedly has node_id")
		}
		if _, exists := index[row.KeyID]; exists {
			return TrustBundle{}, nil, errors.New("duplicate trust key_id")
		}
		scope := row.Role + "\x00" + row.NodeID
		if _, exists := roleNode[scope]; exists {
			return TrustBundle{}, nil, errors.New("duplicate trust role/node")
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(row.PublicKey)
		if decodeErr != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != row.PublicKey {
			return TrustBundle{}, nil,
				errors.New("trust public key is not canonical Ed25519")
		}
		keyCopy := make([]byte, len(decoded))
		copy(keyCopy, decoded)
		index[row.KeyID] = trustedKey{
			row: row, key: ed25519.PublicKey(keyCopy),
		}
		roleNode[scope] = struct{}{}
	}
	return trust, index, nil
}

func cycleCoreOf(cycle Cycle) cycleCore {
	return cycleCore{
		Schema:            cycle.Schema,
		CycleID:           cycle.CycleID,
		AttemptID:         cycle.AttemptID,
		TopologyID:        cycle.TopologyID,
		DescriptorSHA256:  cycle.DescriptorSHA256,
		BundleSHA256:      cycle.BundleSHA256,
		TrustSHA256:       cycle.TrustSHA256,
		Nonce:             cycle.Nonce,
		AcceptedAt:        cycle.AcceptedAt,
		CounterDomain:     cycle.CounterDomain,
		AcceptedCounter:   cycle.AcceptedCounter,
		ExpectedTransport: cycle.ExpectedTransport,
		ExercisedNodes:    slices.Clone(cycle.ExercisedNodes),
		Deployments:       slices.Clone(cycle.Deployments),
	}
}

func digestObject(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func verifySignature(
	index trustIndex,
	keyID, role, nodeID, domain, signature string,
	value any,
) error {
	entry, ok := index[keyID]
	if !ok || entry.row.Role != role || entry.row.NodeID != nodeID {
		return errors.New("signature key role or node binding is invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(decoded) != signature {
		return errors.New("signature is not canonical Ed25519")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	message := make([]byte, 0, len(domain)+1+len(encoded))
	message = append(message, domain...)
	message = append(message, 0)
	message = append(message, encoded...)
	if !ed25519.Verify(entry.key, message, decoded) {
		return errors.New("signature verification failed")
	}
	return nil
}

func decodeCanonical(data []byte, destination any) error {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("document must end in one LF")
	}
	if bytes.Contains(data[:len(data)-1], []byte{'\n', '\r', '\t'}) {
		return errors.New("document contains noncanonical whitespace")
	}
	if err := inspectJSON(data[:len(data)-1]); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("document contains multiple JSON values")
		}
		return err
	}
	encoded, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if !bytes.Equal(encoded, data) {
		return errors.New("document is not canonical Go JSON plus LF")
	}
	return nil
}

func inspectJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := inspectJSONValue(decoder, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); err == nil {
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if text, ok := token.(string); ok && len(text) > MaxStringBytes {
			return errors.New("JSON string exceeds limit")
		}
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, nameErr := decoder.Token()
			if nameErr != nil {
				return nameErr
			}
			name, ok := nameToken.(string)
			if !ok || len(name) > MaxStringBytes {
				return errors.New("JSON object name is invalid")
			}
			if _, exists := names[name]; exists {
				return fmt.Errorf("duplicate JSON object name %q", name)
			}
			names[name] = struct{}{}
			if err := inspectJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validID(value string) bool {
	return len(value) <= MaxStringBytes && identifierPattern.MatchString(value)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Format(time.RFC3339Nano) != value ||
		parsed.Location() != time.UTC {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC3339Nano")
	}
	minimum := time.Unix(0, math.MinInt64).UTC()
	maximum := time.Unix(0, math.MaxInt64).UTC()
	if parsed.Before(minimum) || parsed.After(maximum) {
		return time.Time{}, errors.New(
			"timestamp is outside the safe Unix nanosecond interval",
		)
	}
	return parsed, nil
}

func validDigest(value string) bool {
	return hex64Pattern.MatchString(value)
}

func validNonce(value string) bool {
	return hex32Pattern.MatchString(value)
}

func validEndpoint(value string) bool {
	return value != "" && len(value) <= MaxStringBytes &&
		!strings.ContainsAny(value, "\x00\r\n\t ")
}

func validKey32(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 &&
		base64.StdEncoding.EncodeToString(decoded) == value
}
