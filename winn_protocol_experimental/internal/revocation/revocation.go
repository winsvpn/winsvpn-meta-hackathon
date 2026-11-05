// Package revocation carries device revocation decisions from the Winn
// controller to the carrier data plane as a signed, sequence-pinned artifact.
//
// # Why this exists
//
// Revoking a device with winn-admin writes to the controller's
// winn_revoked_devices table, and internal/bootstrap turns that into an HTTP
// 403 on the rekey endpoint. That stops key rotation. It does not stop
// traffic: cmd/winn-carrier-server authorized purely from the static
// device-pq-registry.json file, so a revoked device kept full data-plane
// access until an operator hand-edited that file on every carrier node and
// restarted each one. For a system whose users face physical risk, "we
// revoked the compromised device" has to mean more than that.
//
// # Why a signed list and not a database read
//
// The obvious alternative is to let each carrier read the controller's
// revocation table directly over PostgreSQL. That was rejected. Carrier nodes
// are the exposed, disposable, potentially-seized assets in this threat model
// and the controller is not; giving every carrier control-plane database
// credentials means a single seized carrier yields database access. It also
// couples data-plane availability to control-plane database availability.
//
// A signed list inverts that: the carrier holds a public verification key, so
// a seized node yields nothing an adversary did not already have, and the
// distribution channel does not need to be trusted — only the signature does.
// This is the same trust model internal/gatewaymanifest already uses, and the
// list is verified against the same controller pin set.
//
// Short-lived device certificates would make most of this unnecessary and are
// the better long-term answer, but they need issuance infrastructure that does
// not exist in this tree yet. See SECURITY.md.
//
// # The freshness tradeoff, stated for auditors
//
// A revocation list can be old for two very different reasons: the operator
// has not published a new one, or an adversary is blocking distribution.
// Winn's threat model gives the adversary exactly that capability, so the
// obvious-looking rule "deny everyone when the list is stale" hands them a
// network-wide kill switch — block one fetch and every user of every carrier
// goes offline. For a censorship-circumvention network whose users are at
// physical risk when they cannot connect, that is a worse outcome than the gap
// it closes.
//
// Soft-failing is safe here for a specific structural reason: the revoked set
// is monotone. Nothing in the controller un-revokes a device, so an older
// signed list is always a subset of the true revoked set. It never wrongly
// denies a good device, and it still enforces every revocation issued before
// its KnownGoodAt instant. A stale list is not a broken list; it is a list
// with a known cutoff. Continuing to enforce it is strictly better than
// enforcing nothing, and denying everyone would not make the one missed
// revocation any more revoked.
//
// So fail-closed is applied to the artifact, never to the traffic:
//
//   - An unverifiable, malformed, wrong-controller, expired-window, or
//     rolled-back list is rejected outright and never installed. The carrier
//     keeps the last list it did verify.
//   - Sequence is pinned and monotone, so an adversary holding the channel can
//     delay a new list but can never rewind to a smaller one.
//   - Age beyond MaxAge denies nobody. It flips Status.Stale, which the
//     carrier surfaces as a metric and an audit record for the operator to
//     page on.
//
// RequireFresh inverts this for deployments that would rather go dark than
// serve a possibly-revoked device — after a known compromise, for example. It
// is off by default precisely because it re-arms the kill switch above. Turn
// it on deliberately and temporarily.
//
// # Scope
//
// This applies to identity mode only. Anonymous-token mode has no stable
// device identity to revoke by construction — that is the point of it — and
// relies on short token validity windows and single-use redemption instead.
// carrierauth.RequestVerifier.VerifyAnonymous deliberately does not consult
// this package.
package revocation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	// Format is the document type tag of a signed revocation list.
	Format = "winn-device-revocation/v1"

	// TrustStateFormat tags the carrier-retained rollback pin.
	TrustStateFormat = "winn-device-revocation-trust-state/v1"

	// MaxDocumentSize bounds a revocation list on disk.
	MaxDocumentSize = 16 << 20

	// MaxRevokedDevices bounds the number of entries in one list. The signed
	// input is a fixed-length digest, so this bounds memory and parse time
	// rather than the signature.
	MaxRevokedDevices = 1 << 20

	// MaxValidity is the longest window a list may claim between KnownGoodAt
	// and NotAfter. It matches the gateway manifest's maximum lifetime so the
	// two artifacts age on the same operational cadence.
	MaxValidity = 7 * 24 * time.Hour

	// DefaultMaxAge is how old an installed list may get before it is reported
	// stale. Staleness is an alerting signal, not a denial - see the package
	// comment.
	DefaultMaxAge = 24 * time.Hour

	// DefaultClockSkew tolerates modest controller/carrier clock disagreement
	// when checking the validity window.
	DefaultClockSkew = 5 * time.Minute

	saltSize      = 32
	deviceHashTag = "winn-device-revocation-hash/v1"
)

// ErrNoList reports that no revocation source has been installed.
var ErrNoList = errors.New("no device revocation list is installed")

// List is the signed artifact a controller publishes and a carrier verifies.
//
// KnownGoodAt is the load-bearing field: it is the controller's signed
// assertion that this is the complete set of devices it had revoked as of that
// instant. It is what lets a carrier reason about exactly which revocations it
// might be missing, rather than guessing.
//
// Device identifiers appear only as salted hashes. A carrier is the seizable
// asset here, and a plaintext roster of revoked devices sitting on every
// carrier node is an intelligence artifact worth more to an adversary than the
// list is to them operationally. The salt is fresh per list, so two captured
// lists cannot be diffed to learn who was revoked in between.
//
// That is a cost increase, not a privacy guarantee, and it should not be
// described as one. Device IDs are operator-chosen strings that
// protocol.ValidDeviceID allows to be short and guessable, so an adversary who
// can enumerate a plausible namespace can still test candidates against the
// hashes. It defeats bulk correlation and casual reading of a seized disk; it
// does not defeat a targeted guess.
type List struct {
	Format        string   `json:"format"`
	ControllerID  string   `json:"controller_id"`
	Sequence      uint64   `json:"sequence"`
	KnownGoodAt   string   `json:"known_good_at"`
	NotAfter      string   `json:"not_after"`
	Salt          string   `json:"salt"`
	RevokedHashes []string `json:"revoked_device_hashes"`
	AuthAlgorithm string   `json:"auth_algorithm"`
	AuthKeyID     string   `json:"auth_key_id"`
	AuthSignature string   `json:"auth_signature"`
}

// TrustState is the carrier-retained rollback pin. Persist the next state only
// after the corresponding list has been installed successfully.
type TrustState struct {
	Format          string `json:"format"`
	ControllerID    string `json:"controller_id"`
	HighestSequence uint64 `json:"highest_sequence"`
	ListDigest      string `json:"list_digest"`
}

// Status is a point-in-time description of what a carrier is enforcing. It
// exists so the operator can distinguish "revocation is current" from
// "revocation is being enforced from an old list" from "revocation is not
// enforced at all", which are three very different security postures that a
// single boolean would flatten.
type Status struct {
	Installed    bool
	Sequence     uint64
	KnownGoodAt  time.Time
	NotAfter     time.Time
	Age          time.Duration
	Stale        bool
	Expired      bool
	RequireFresh bool
	// DenyingAll is true only when RequireFresh is set and the list is no
	// longer fresh. It is the one configuration in which this package denies
	// devices it has no evidence against.
	DenyingAll bool
	Count      int
}

// NewSalt returns a fresh per-list salt.
func NewSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate revocation list salt: %w", err)
	}
	return salt, nil
}

// DeviceHash maps a device identifier to its salted hash. It is deterministic
// for a given salt so a carrier can hash the identity it just authenticated
// and compare, without the list ever naming the device.
func DeviceHash(salt []byte, deviceID string) string {
	digest := sha256.New()
	digest.Write([]byte(deviceHashTag))
	digest.Write([]byte{0})
	digest.Write(salt)
	digest.Write([]byte{0})
	digest.Write([]byte(deviceID))
	return hex.EncodeToString(digest.Sum(nil))
}

// Build assembles an unsigned list from plaintext device identifiers. The
// caller supplies KnownGoodAt as the instant the underlying controller
// snapshot was taken, not the instant of publication, so the assertion the
// list makes stays true.
func Build(controllerID string, sequence uint64, knownGoodAt time.Time, validity time.Duration, deviceIDs []string) (List, error) {
	if controllerID == "" || len(controllerID) > 512 {
		return List{}, errors.New("revocation list requires a controller ID")
	}
	if sequence == 0 {
		return List{}, errors.New("revocation list sequence must be positive")
	}
	if validity <= 0 || validity > MaxValidity {
		return List{}, fmt.Errorf(
			"revocation list validity must be between 0 and %s", MaxValidity,
		)
	}
	if len(deviceIDs) > MaxRevokedDevices {
		return List{}, errors.New("revocation list exceeds device limit")
	}
	salt, err := NewSalt()
	if err != nil {
		return List{}, err
	}
	hashes := make([]string, 0, len(deviceIDs))
	seen := make(map[string]struct{}, len(deviceIDs))
	for _, deviceID := range deviceIDs {
		if !protocol.ValidDeviceID(deviceID) {
			return List{}, fmt.Errorf("invalid revoked device ID %q", deviceID)
		}
		hash := DeviceHash(salt, deviceID)
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
	}
	// Sorting keeps the document canonical for a given input set, so two
	// controllers reading the same snapshot produce byte-identical bodies
	// apart from the salt.
	slices.Sort(hashes)
	knownGood := knownGoodAt.UTC()
	return List{
		Format:        Format,
		ControllerID:  controllerID,
		Sequence:      sequence,
		KnownGoodAt:   knownGood.Format(time.RFC3339Nano),
		NotAfter:      knownGood.Add(validity).Format(time.RFC3339Nano),
		Salt:          base64.StdEncoding.EncodeToString(salt),
		RevokedHashes: hashes,
	}, nil
}

// Sign fills in the controller's algorithm, key ID, and signature.
func Sign(list *List, signer *pqauth.Signer) error {
	if list == nil || signer == nil {
		return errors.New("revocation list and controller signer are required")
	}
	list.AuthAlgorithm = signer.Algorithm()
	list.AuthKeyID = signer.KeyID()
	list.AuthSignature = ""
	if err := validate(*list, time.Time{}, 0, false); err != nil {
		return err
	}
	message, err := unsignedCanonical(*list)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	clear(message)
	signature, err := pqauth.SignDomainMessage(
		pqauth.RevocationListSignatureDomain, digest[:], signer,
	)
	clear(digest[:])
	if err != nil {
		return err
	}
	defer clear(signature)
	list.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// Verify checks structure, the controller binding, the validity window, and
// the signature. It deliberately does not consider staleness: a list that is
// old but authentic is a usable under-approximation of the revoked set, and
// treating it as a verification failure is what would hand an adversary a
// network-wide kill switch. See the package comment.
func Verify(list List, controllerID string, pins *pqauth.VerifierSet, now time.Time) error {
	if pins == nil {
		return errors.New("revocation list controller pins are required")
	}
	if controllerID != "" && list.ControllerID != controllerID {
		return errors.New("revocation list controller mismatch")
	}
	if err := validate(list, now, DefaultClockSkew, true); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(
		list.AuthSignature,
	)
	if err != nil || len(signature) == 0 {
		return errors.New("invalid revocation list signature encoding")
	}
	defer clear(signature)
	verifier, err := pins.Verifier(list.AuthAlgorithm, list.AuthKeyID)
	if err != nil {
		return err
	}
	message, err := unsignedCanonical(list)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	clear(message)
	defer clear(digest[:])
	if err := pqauth.VerifyDomainMessage(
		pqauth.RevocationListSignatureDomain, digest[:], signature, verifier,
	); err != nil {
		return fmt.Errorf("verify device revocation list: %w", err)
	}
	return nil
}

// Digest returns the canonical digest of a signed list, used as the rollback
// pin's equivocation check.
func Digest(list List) (string, error) {
	encoded, err := canonical(list)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Encode renders a signed list for publication.
func Encode(list List) ([]byte, error) {
	encoded, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// Load reads and parses a revocation list without verifying it.
func Load(path string) (List, error) {
	data, err := securefile.ReadPublicIntegrity(path, MaxDocumentSize)
	if err != nil {
		return List{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var list List
	if err := decoder.Decode(&list); err != nil {
		return List{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return List{}, errors.New("revocation list contains extra JSON")
	}
	return list, nil
}

// EncodeTrustState renders the rollback pin for atomic persistence.
func EncodeTrustState(state TrustState) ([]byte, error) {
	if err := validateTrustState(state); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// LoadTrustState reads a retained rollback pin.
func LoadTrustState(path string) (TrustState, error) {
	data, err := securefile.ReadPublicIntegrity(path, 64<<10)
	if err != nil {
		return TrustState{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state TrustState
	if err := decoder.Decode(&state); err != nil {
		return TrustState{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return TrustState{}, errors.New("revocation trust state contains extra JSON")
	}
	if err := validateTrustState(state); err != nil {
		return TrustState{}, err
	}
	return state, nil
}

// LoadVerified verifies a list and enforces the monotone sequence pin against
// retained trust state. statePath may name a file that does not exist yet, in
// which case the first verified list bootstraps the pin.
//
// Bootstrapping without out-of-band confirmation is acceptable here in a way
// it is not for the gateway manifest, and the asymmetry is deliberate: the
// worst a forged first revocation list can do is deny service to devices named
// in it, which is exactly what an adversary who controls the channel could
// achieve anyway by dropping traffic. It cannot grant access, because access
// still requires mTLS plus a registered ML-DSA key. A forged manifest, by
// contrast, redirects users to attacker-controlled endpoints, which is why
// gatewaymanifest.BootstrapTrustStateV2 refuses to trust on first use.
//
// The returned state is not persisted automatically.
func LoadVerified(path, statePath, controllerID string, pins *pqauth.VerifierSet, now time.Time) (List, TrustState, error) {
	if path == "" || pins == nil {
		return List{}, TrustState{}, errors.New(
			"revocation list path and controller pins are required",
		)
	}
	list, err := Load(path)
	if err != nil {
		return List{}, TrustState{}, err
	}
	if err := Verify(list, controllerID, pins, now); err != nil {
		return List{}, TrustState{}, err
	}
	digest, err := Digest(list)
	if err != nil {
		return List{}, TrustState{}, err
	}
	if statePath != "" {
		previous, loadErr := LoadTrustState(statePath)
		switch {
		case loadErr == nil:
			if previous.ControllerID != list.ControllerID {
				return List{}, TrustState{}, errors.New(
					"revocation trust state belongs to a different controller",
				)
			}
			switch {
			case list.Sequence < previous.HighestSequence:
				return List{}, TrustState{}, errors.New(
					"revocation list sequence rollback detected",
				)
			case list.Sequence == previous.HighestSequence &&
				digest != previous.ListDigest:
				return List{}, TrustState{}, errors.New(
					"revocation list sequence was equivocated",
				)
			}
		case errors.Is(loadErr, fs.ErrNotExist):
			// First list on this node bootstraps the pin. See the doc comment
			// for why trust-on-first-use is acceptable for this artifact.
		default:
			return List{}, TrustState{}, loadErr
		}
	}
	return list, TrustState{
		Format:          TrustStateFormat,
		ControllerID:    list.ControllerID,
		HighestSequence: list.Sequence,
		ListDigest:      digest,
	}, nil
}

// Checker answers the data plane's one question - is this device revoked -
// and reports the posture it answered from. The installed list is swapped
// atomically so a future reload path can replace it without locking the
// per-request path.
type Checker struct {
	current      atomic.Pointer[snapshot]
	maxAge       time.Duration
	requireFresh bool
	now          func() time.Time
}

type snapshot struct {
	list        List
	digest      string
	salt        []byte
	hashes      map[string]struct{}
	knownGoodAt time.Time
	notAfter    time.Time
}

// NewChecker builds a checker over an already-verified list.
//
// requireFresh selects the hard fail-closed posture: once the list ages past
// maxAge the checker denies every device, including ones it holds no evidence
// against. That converts an adversary's ability to block distribution into an
// ability to take the whole network offline, which is why it defaults off. It
// exists for the deployment that has decided, for a bounded period, that a
// possibly-revoked device is the worse risk.
func NewChecker(list List, maxAge time.Duration, requireFresh bool) (*Checker, error) {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	checker := &Checker{maxAge: maxAge, requireFresh: requireFresh}
	if err := checker.Install(list); err != nil {
		return nil, err
	}
	return checker, nil
}

// Install replaces the enforced list. The caller is responsible for having
// verified it first; Install re-checks structure so a caller cannot install a
// malformed list by mistake, and it pins sequence against the list already
// installed, so a Refresh without a retained state file (or with one that
// lags the process) can never roll back or equivocate the live set.
func (c *Checker) Install(list List) error {
	if c == nil {
		return errors.New("revocation checker is not configured")
	}
	if err := validate(list, time.Time{}, 0, true); err != nil {
		return err
	}
	digest, err := Digest(list)
	if err != nil {
		return err
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(list.Salt)
	if err != nil || len(salt) != saltSize {
		return errors.New("invalid revocation list salt")
	}
	knownGoodAt, notAfter, err := parseWindow(
		list.KnownGoodAt, list.NotAfter, time.Time{}, 0,
	)
	if err != nil {
		return err
	}
	hashes := make(map[string]struct{}, len(list.RevokedHashes))
	for _, hash := range list.RevokedHashes {
		hashes[hash] = struct{}{}
	}
	next := &snapshot{
		list:        list,
		digest:      digest,
		salt:        salt,
		hashes:      hashes,
		knownGoodAt: knownGoodAt.UTC(),
		notAfter:    notAfter.UTC(),
	}
	for {
		installed := c.current.Load()
		if installed != nil {
			switch {
			case installed.list.ControllerID != list.ControllerID:
				return errors.New(
					"revocation list belongs to a different controller",
				)
			case list.Sequence < installed.list.Sequence:
				return errors.New(
					"revocation list sequence rollback detected",
				)
			case list.Sequence == installed.list.Sequence &&
				digest != installed.digest:
				return errors.New(
					"revocation list sequence was equivocated",
				)
			}
		}
		if c.current.CompareAndSwap(installed, next) {
			return nil
		}
	}
}

// RevokedDevice reports whether the carrier must refuse this device. It
// satisfies carrierauth.DeviceRevocations.
//
// With no list installed it returns false, because a checker that was never
// given a list has no evidence against anyone; the carrier refuses to start in
// that configuration rather than silently serving, so this path is reachable
// only in tests.
func (c *Checker) RevokedDevice(deviceID string) bool {
	if c == nil {
		return false
	}
	installed := c.current.Load()
	if installed == nil {
		return false
	}
	if c.requireFresh && c.staleAt(installed, c.currentTime()) {
		return true
	}
	_, revoked := installed.hashes[DeviceHash(installed.salt, deviceID)]
	return revoked
}

// Source describes where a carrier re-reads its revocation list.
type Source struct {
	ListPath     string
	StatePath    string
	ControllerID string
	Pins         *pqauth.VerifierSet
}

// Refresh re-reads, re-verifies, and installs the list, advancing the
// retained rollback pin when the sequence moves forward. It reports whether
// the installed list changed.
//
// Every failure path leaves the previously installed list in force. That is
// the whole point: a carrier that cannot fetch or cannot verify a new list is
// in exactly the situation where continuing to enforce the old one is the
// safe behaviour, and where discarding it would turn a distribution outage
// into a service outage. Callers should surface the error as an alert, not as
// a reason to stop serving.
func (c *Checker) Refresh(source Source, now time.Time) (bool, error) {
	if c == nil {
		return false, errors.New("revocation checker is not configured")
	}
	list, nextState, err := LoadVerified(
		source.ListPath, source.StatePath, source.ControllerID,
		source.Pins, now,
	)
	if err != nil {
		return false, err
	}
	installed := c.current.Load()
	if installed != nil &&
		installed.list.ControllerID == list.ControllerID &&
		installed.list.Sequence == list.Sequence &&
		installed.digest == nextState.ListDigest {
		return false, nil
	}
	if err := c.Install(list); err != nil {
		return false, err
	}
	if source.StatePath != "" {
		encoded, encodeErr := EncodeTrustState(nextState)
		if encodeErr != nil {
			return true, encodeErr
		}
		defer clear(encoded)
		if writeErr := securefile.AtomicWrite(
			source.StatePath, encoded, 0o600,
		); writeErr != nil {
			return true, writeErr
		}
	}
	return true, nil
}

// Status describes what is currently being enforced, for metrics and audit.
func (c *Checker) Status() Status {
	if c == nil {
		return Status{}
	}
	installed := c.current.Load()
	if installed == nil {
		return Status{RequireFresh: c.requireFresh}
	}
	now := c.currentTime()
	stale := c.staleAt(installed, now)
	return Status{
		Installed:    true,
		Sequence:     installed.list.Sequence,
		KnownGoodAt:  installed.knownGoodAt,
		NotAfter:     installed.notAfter,
		Age:          now.Sub(installed.knownGoodAt),
		Stale:        stale,
		Expired:      now.After(installed.notAfter),
		RequireFresh: c.requireFresh,
		DenyingAll:   c.requireFresh && stale,
		Count:        len(installed.hashes),
	}
}

// SetNow overrides the checker's clock. Tests only.
func (c *Checker) SetNow(now func() time.Time) {
	if c != nil {
		c.now = now
	}
}

func (c *Checker) currentTime() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

// staleAt treats a list as no longer fresh once it is older than maxAge or
// past its own signed window, whichever comes first. Both are reported; only
// requireFresh turns either into a denial.
func (c *Checker) staleAt(installed *snapshot, now time.Time) bool {
	return now.Sub(installed.knownGoodAt) > c.maxAge ||
		now.After(installed.notAfter)
}

func unsignedCanonical(list List) ([]byte, error) {
	list.AuthSignature = ""
	return canonical(list)
}

func canonical(list List) ([]byte, error) {
	return json.Marshal(list)
}

func validate(list List, now time.Time, maxSkew time.Duration, requireSignature bool) error {
	if list.Format != Format {
		return errors.New("unsupported device revocation list format")
	}
	if list.ControllerID == "" || len(list.ControllerID) > 512 {
		return errors.New("invalid revocation list controller ID")
	}
	if list.Sequence == 0 {
		return errors.New("revocation list sequence must be positive")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(list.Salt)
	if err != nil || len(salt) != saltSize {
		return errors.New("invalid revocation list salt")
	}
	clear(salt)
	if len(list.RevokedHashes) > MaxRevokedDevices {
		return errors.New("revocation list exceeds device limit")
	}
	if !slices.IsSorted(list.RevokedHashes) {
		return errors.New("revocation list hashes are not canonically ordered")
	}
	for index, hash := range list.RevokedHashes {
		if !validDigest(hash) {
			return errors.New("invalid revoked device hash")
		}
		if index > 0 && hash == list.RevokedHashes[index-1] {
			return errors.New("duplicate revoked device hash")
		}
	}
	if _, _, err := parseWindow(
		list.KnownGoodAt, list.NotAfter, now, maxSkew,
	); err != nil {
		return err
	}
	if requireSignature {
		if list.AuthAlgorithm == "" || list.AuthKeyID == "" ||
			list.AuthSignature == "" {
			return errors.New("revocation list is missing its controller signature")
		}
	}
	return nil
}

// parseWindow mirrors the v2 manifest's lifetime validation: RFC3339Nano UTC
// only, a frozen skew ceiling, and a bounded window.
//
// It deliberately does not reject a list whose NotAfter has already passed.
// Expiry of a revocation list is not the same event as expiry of a manifest.
// An expired manifest points at endpoints that may no longer be the
// operator's, so serving on it is unsafe; an expired revocation list still
// names devices the controller really did revoke, so refusing to load it
// would discard true information and enforce nothing instead. Currency is
// reported through Status.Expired and handled by the freshness policy in
// Checker, not by rejecting the document. See the package comment.
func parseWindow(knownGoodText, notAfterText string, now time.Time, maxSkew time.Duration) (time.Time, time.Time, error) {
	if maxSkew < 0 || maxSkew > DefaultClockSkew {
		return time.Time{}, time.Time{},
			errors.New("revocation list clock skew exceeds the frozen limit")
	}
	knownGoodAt, err := time.Parse(time.RFC3339Nano, knownGoodText)
	if err != nil || knownGoodAt.Location() != time.UTC {
		return time.Time{}, time.Time{},
			errors.New("revocation list known_good_at must be RFC3339Nano UTC")
	}
	notAfter, err := time.Parse(time.RFC3339Nano, notAfterText)
	if err != nil || notAfter.Location() != time.UTC {
		return time.Time{}, time.Time{},
			errors.New("revocation list not_after must be RFC3339Nano UTC")
	}
	if !notAfter.After(knownGoodAt) ||
		notAfter.Sub(knownGoodAt) > MaxValidity {
		return time.Time{}, time.Time{},
			errors.New("revocation list validity window is invalid")
	}
	if !now.IsZero() && now.Before(knownGoodAt.Add(-maxSkew)) {
		return time.Time{}, time.Time{},
			errors.New("revocation list is not yet valid")
	}
	return knownGoodAt, notAfter, nil
}

func validateTrustState(state TrustState) error {
	if state.Format != TrustStateFormat || state.ControllerID == "" ||
		state.HighestSequence == 0 || !validDigest(state.ListDigest) {
		return errors.New("device revocation trust state is invalid")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
