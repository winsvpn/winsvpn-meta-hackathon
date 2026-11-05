package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Carrier conservation law.
//
// A carrier request that presents a valid single-use privacy token creates a
// durable redemption row before the carrier has produced any HTTP result. The
// request may still fail afterwards, but it may not vanish from the sealed
// audit trail. Promotional evidence therefore has to satisfy, exactly:
//
//	durable redemptions == anonymous authenticated events
//	authenticated       == auth_only + open + aborted   (per carrier)
//	open                == closed                       (per carrier)
//
// An equality observed by the live harness is not the same thing as an
// enforced conservation law. The harness runs on the machine that produced the
// evidence, at the moment it was produced, with the database still reachable;
// it cannot be replayed by an auditor and it cannot detect anything that was
// changed after it finished. Everything below is therefore recomputed here,
// offline, from files the evidence manifest covers and the signed dual-provider
// anchor request transitively commits to through the batch archive digest.
//
// This verifier deliberately does not trust the harness's own arithmetic: it
// recomputes every count from carrier-audit.jsonl and then requires the
// harness's sealed claim in carrier-conservation.txt to match, so a harness
// that asserted one set of numbers and sealed another fails here.
const (
	carrierAuditFileName        = "carrier-audit.jsonl"
	redemptionCountFileName     = "redemption-count.txt"
	carrierConservationFileName = "carrier-conservation.txt"

	carrierAuditLogFormat = "winn-audit-hmac-sha256/v1"

	// carrierTerminalSchema mirrors carrier.CarrierTerminalSchema. It is
	// duplicated rather than imported so that a change to the carrier's
	// encoding cannot silently become a change to the verifier's expectation:
	// the two have to be edited together, and evidence carrying any other
	// schema token is rejected.
	carrierTerminalSchema = "carrier-terminal/v1"

	carrierZeroMAC = "0000000000000000000000000000000000000000000000000000000000000000"

	maximumCarrierAuditBytes  = 512 << 20
	maximumCarrierAuditLine   = 64 << 10
	maximumCarrierAuditEvents = 4_000_000
)

// carrierFamily names one carrier protocol. Conservation holds per carrier;
// the redemption equality holds across both, because one redemption store
// serves both carriers.
type carrierFamily string

const (
	carrierFamilyH3 carrierFamily = "h3"
	carrierFamilyH2 carrierFamily = "h2"
)

// carrierTerminalEvent binds an audit event name to the terminal class its
// detail must declare. An event whose name and declared class disagree has
// been reclassified and is rejected.
type carrierTerminalEvent struct {
	family carrierFamily
	class  string
}

const (
	carrierClassAuthenticated = "authenticated"
	carrierClassAuthOnly      = "auth_only"
	carrierClassOpen          = "open"
	carrierClassClosed        = "closed"
	carrierClassAborted       = "aborted"
)

var carrierTerminalEvents = map[string]carrierTerminalEvent{
	"carrier_h3_authenticated": {carrierFamilyH3, carrierClassAuthenticated},
	"carrier_h3_auth_only":     {carrierFamilyH3, carrierClassAuthOnly},
	"carrier_h3_open":          {carrierFamilyH3, carrierClassOpen},
	"carrier_h3_closed":        {carrierFamilyH3, carrierClassClosed},
	"carrier_h3_aborted":       {carrierFamilyH3, carrierClassAborted},
	"carrier_h2_authenticated": {carrierFamilyH2, carrierClassAuthenticated},
	"carrier_h2_open":          {carrierFamilyH2, carrierClassOpen},
	"carrier_h2_closed":        {carrierFamilyH2, carrierClassClosed},
	"carrier_h2_aborted":       {carrierFamilyH2, carrierClassAborted},
}

// carrierAbortReasons is the closed, versioned abort-reason enum of
// carrierTerminalSchema. An aborted event carrying anything else — including a
// reason a newer carrier build introduced — fails verification rather than
// being accepted as an uninterpreted terminal class.
var carrierAbortReasons = []string{
	"audit_unavailable",
	"awg_backend_unavailable",
	"carrier_rate_limited",
	"invalid_carrier_mtu",
	"response_auth_failed",
}

var carrierAuthorizationModes = []string{"anonymous-token", "identity"}

// carrierAuditRecord mirrors internal/audit's on-disk record exactly. Decoding
// with DisallowUnknownFields means an added field is a rejection, not a
// silently ignored annotation.
type carrierAuditRecord struct {
	Format         string `json:"format"`
	Sequence       uint64 `json:"sequence"`
	Timestamp      string `json:"timestamp"`
	Event          string `json:"event"`
	DeviceHash     string `json:"device_hash,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Detail         string `json:"detail,omitempty"`
	PreviousMAC    string `json:"previous_mac"`
	Authentication string `json:"authentication"`
}

// carrierCounts is one carrier's recomputed event tally.
type carrierCounts struct {
	authenticated          int
	anonymousAuthenticated int
	authOnly               int
	open                   int
	closed                 int
	aborted                int
}

// carrierCorrelation is the per-redemption state machine. Exactly one
// authenticated record opens it and exactly one terminal record closes it.
//
// mode, session, and deviceHash are pinned from the authenticated event and
// checked against every later event under the same correlation ID. A unique,
// unforgeable correlation ID rules out one request's events being credited to
// another's tally by accident, but it does not by itself prove that every
// event actually describes the same request: a bug or a forged event could
// carry a live correlation ID with different identity metadata. Pinning and
// re-checking mode/session/device turns "the ID matches" into "the request
// matches," which is what a metadata substitution or reclassification attack
// would have to defeat.
type carrierCorrelation struct {
	family        carrierFamily
	authenticated bool
	mode          string
	session       string
	deviceHash    string
	terminalClass string
	closed        bool
}

// verifyCarrierConservation recomputes the carrier conservation law for one
// sealed batch and rejects a missing terminal event, a duplicate terminal
// event, an unknown abort reason, a reclassified terminal event, an
// uncorrelated or correlation-free event, a tampered redemption snapshot, and
// a harness claim that disagrees with the sealed trail.
func verifyCarrierConservation(evidenceDirectory string) error {
	environment, err := parseKeyValueFile(
		filepath.Join(evidenceDirectory, "environment.txt"),
	)
	if err != nil {
		return err
	}
	return verifyCarrierConservationWithMode(
		evidenceDirectory, environment["carrier_authorization_mode"],
	)
}

// verifyCarrierConservationWithMode takes the carrier authorization mode the
// sealing harness recorded. Requiring the key to be present makes the
// recording itself the evidence, exactly as verifyExperimentKnobs does for
// force_carrier: only a harness that would have disclosed an identity-mode
// carrier can produce a batch that passes here.
func verifyCarrierConservationWithMode(
	evidenceDirectory string,
	recordedMode string,
) error {
	// Only anonymous-token is an accepted sealed configuration today. Any
	// other value — including absence — fails closed rather than silently
	// admitting a run whose authenticated requests never redeemed a token.
	if recordedMode != "anonymous-token" {
		return fmt.Errorf(
			"evidence records carrier authorization mode %q, want "+
				"anonymous-token",
			recordedMode,
		)
	}
	covered, err := evidenceManifestPaths(evidenceDirectory)
	if err != nil {
		return err
	}
	// Requiring these three names to be *listed in the manifest* — not merely
	// present on disk — is what makes the check unskippable. A harness that
	// never wrote the redemption snapshot would otherwise produce evidence
	// byte-indistinguishable from one that had nothing to hide, exactly the
	// hole verifyExperimentKnobs closes for force_carrier.
	// environment.txt is required here as well: the recorded authorization
	// mode above, and the experiment knobs verifyExperimentKnobs reads, are
	// only trustworthy if that file is itself covered by the manifest the
	// anchor request commits to.
	for _, required := range []string{
		carrierAuditFileName,
		redemptionCountFileName,
		carrierConservationFileName,
		"environment.txt",
	} {
		if _, ok := covered[required]; !ok {
			return fmt.Errorf(
				"evidence manifest does not cover %s", required,
			)
		}
	}

	counts, err := recomputeCarrierAudit(
		filepath.Join(evidenceDirectory, carrierAuditFileName),
	)
	if err != nil {
		return err
	}

	redemptions, err := readCarrierCount(
		filepath.Join(evidenceDirectory, redemptionCountFileName),
	)
	if err != nil {
		return fmt.Errorf("durable redemption snapshot: %w", err)
	}

	h3 := counts[carrierFamilyH3]
	h2 := counts[carrierFamilyH2]

	for family, count := range counts {
		if count.authenticated !=
			count.authOnly+count.open+count.aborted {
			return fmt.Errorf(
				"%s carrier conservation failed: authenticated=%d, "+
					"auth_only=%d + open=%d + aborted=%d",
				family, count.authenticated,
				count.authOnly, count.open, count.aborted,
			)
		}
		if count.open != count.closed {
			return fmt.Errorf(
				"%s carrier open=%d does not equal closed=%d",
				family, count.open, count.closed,
			)
		}
	}

	anonymous := h3.anonymousAuthenticated + h2.anonymousAuthenticated
	// Only anonymous-token authentications redeem a single-use token, so only
	// they belong on the redemption side of the equation. Identity-mode
	// carrier requests still reach a terminal class through the per-carrier
	// equation above; they simply do not create a redemption row.
	//
	// The recorded configuration is anonymous-token, so on this evidence the
	// two sets have to coincide. Checking that explicitly closes the only gap
	// the mode-aware form would otherwise open: an authenticated record that
	// declared identity mode would drop off the redemption side of the
	// equation while still balancing the terminal-class side.
	if anonymous != h3.authenticated+h2.authenticated {
		return fmt.Errorf(
			"anonymous-token evidence contains %d authenticated carrier "+
				"requests but only %d redeemed a token",
			h3.authenticated+h2.authenticated, anonymous,
		)
	}
	if redemptions != anonymous {
		return fmt.Errorf(
			"durable redemptions=%d does not equal anonymous authenticated "+
				"carrier requests=%d",
			redemptions, anonymous,
		)
	}

	claimed, err := parseKeyValueFile(
		filepath.Join(evidenceDirectory, carrierConservationFileName),
	)
	if err != nil {
		return fmt.Errorf("carrier conservation snapshot: %w", err)
	}
	expected := map[string]int{
		"redemptions":             redemptions,
		"anonymous_authenticated": anonymous,
		"h3_authenticated":        h3.authenticated,
		"h3_auth_only":            h3.authOnly,
		"h3_open":                 h3.open,
		"h3_closed":               h3.closed,
		"h3_aborted":              h3.aborted,
		"h2_authenticated":        h2.authenticated,
		"h2_auth_only":            h2.authOnly,
		"h2_open":                 h2.open,
		"h2_closed":               h2.closed,
		"h2_aborted":              h2.aborted,
	}
	if claimed["schema"] != carrierTerminalSchema {
		return errors.New(
			"carrier conservation snapshot declares an unknown schema",
		)
	}
	// The snapshot is a closed schema: "schema" plus exactly the keys in
	// expected, nothing else. parseKeyValueFile already rejects a duplicate
	// key within the file; this rejects a key the schema does not define at
	// all, so a field smuggled in under a look-alike name (or a stale key
	// left over from a future or reverted schema version) cannot ride along
	// unexamined the way an unknown-fields decoder would refuse to.
	if len(claimed) != len(expected)+1 {
		for key := range claimed {
			if key == "schema" {
				continue
			}
			if _, ok := expected[key]; !ok {
				return fmt.Errorf(
					"carrier conservation snapshot declares unknown key %q",
					key,
				)
			}
		}
		return errors.New(
			"carrier conservation snapshot key count does not match its schema",
		)
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		recorded, present := claimed[key]
		if !present {
			return fmt.Errorf(
				"carrier conservation snapshot omits %s", key,
			)
		}
		value, err := strconv.Atoi(recorded)
		if err != nil || value != expected[key] {
			return fmt.Errorf(
				"carrier conservation snapshot claims %s=%q, sealed trail "+
					"recomputes %d",
				key, recorded, expected[key],
			)
		}
	}
	return nil
}

// recomputeCarrierAudit parses the sealed carrier audit log and rebuilds every
// count from scratch.
func recomputeCarrierAudit(
	path string,
) (map[carrierFamily]carrierCounts, error) {
	return recomputeCarrierAuditBounded(path, maximumCarrierAuditBytes)
}

// recomputeCarrierAuditBounded takes the limit as a PARAMETER.
//
// It is a parameter and not a package variable. A mutable global would be
// shared by every concurrent caller, so a test lowering it would perturb
// unrelated work and two parallel tests would race under -race — and no comment
// asserting "production never assigns it" would make that safe, it would only
// invite someone to rely on the claim while writing new code. Production passes
// the compile-time constant; tests pass their own small value.
func recomputeCarrierAuditBounded(
	path string,
	limit int64,
) (map[carrierFamily]carrierCounts, error) {
	file, err := openSecureRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	counts := map[carrierFamily]carrierCounts{
		carrierFamilyH3: {},
		carrierFamilyH2: {},
	}
	correlations := make(map[string]*carrierCorrelation)

	bounded := newBoundedReader(file, limit)
	scanner := bufio.NewScanner(bounded)
	scanner.Buffer(make([]byte, 4096), maximumCarrierAuditLine)
	var expectedSequence uint64 = 1
	previousMAC := carrierZeroMAC
	// The first structural chain violation is remembered rather than returned,
	// and reported only if the conservation reconciliation itself passes. A
	// mutation that both breaks the chain and breaks conservation has to fail
	// for its conservation reason: an operator who is told only "the chain is
	// broken" learns nothing about which invariant the run actually violated,
	// and a check that reports an unrelated integrity failure first is exactly
	// the kind of check that lets a semantic defect hide behind a digest.
	var chainErr error
	lines := 0
	for scanner.Scan() {
		// The bound first: an oversized trail is cut mid-record, and the record
		// parser would otherwise report malformed JSON for a file whose real
		// defect is that the verifier only saw part of it.
		if bounded.exceeded() {
			return nil, bounded.check("the carrier audit trail")
		}
		lines++
		if lines > maximumCarrierAuditEvents {
			return nil, errors.New("carrier audit log is implausibly long")
		}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var entry carrierAuditRecord
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("carrier audit line %d: %w", lines, err)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, fmt.Errorf("carrier audit line %d: %w", lines, err)
		}
		// Structural chain integrity, independent of the HMAC key, which the
		// evidence deliberately does not carry. Sequence continuity plus
		// previous-MAC linkage means a deleted or inserted record breaks the
		// chain here even before the manifest digest is considered.
		if chainErr == nil &&
			(entry.Format != carrierAuditLogFormat ||
				entry.Sequence != expectedSequence ||
				!lowerHex(entry.Authentication, len(carrierZeroMAC)) ||
				entry.PreviousMAC != previousMAC) {
			chainErr = fmt.Errorf(
				"carrier audit line %d breaks the sealed record chain", lines,
			)
		}
		// Resynchronise so one break does not cascade; only the first is kept.
		previousMAC = entry.Authentication
		expectedSequence = entry.Sequence + 1

		descriptor, tracked := carrierTerminalEvents[entry.Event]
		if !tracked {
			// Lifecycle events such as carrier_server_starting carry no
			// correlation identity and take part in no terminal class.
			if entry.RequestID != "" &&
				strings.HasPrefix(entry.Detail, carrierTerminalSchema) {
				return nil, fmt.Errorf(
					"carrier audit line %d carries terminal-schema detail "+
						"under unknown event %q",
					lines, entry.Event,
				)
			}
			continue
		}
		if err := applyCarrierTerminalRecord(
			counts, correlations, descriptor, entry, lines,
		); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read carrier audit log: %w", err)
	}
	if err := bounded.check("the carrier audit trail"); err != nil {
		return nil, err
	}

	// Every redemption must have reached exactly one terminal class. A
	// correlation left open here is precisely the defect this whole design
	// exists to catch: a request that authenticated, burned a durable token,
	// and then disappeared.
	for correlation, state := range correlations {
		if !state.authenticated {
			return nil, fmt.Errorf(
				"carrier correlation %s has terminal events but no "+
					"authenticated event",
				correlation,
			)
		}
		if state.terminalClass == "" {
			return nil, fmt.Errorf(
				"carrier correlation %s authenticated but reached no "+
					"terminal class",
				correlation,
			)
		}
		if state.closed && state.terminalClass != carrierClassOpen {
			return nil, fmt.Errorf(
				"carrier correlation %s recorded a close for terminal "+
					"class %s",
				correlation, state.terminalClass,
			)
		}
		if state.terminalClass == carrierClassOpen && !state.closed {
			return nil, fmt.Errorf(
				"carrier correlation %s opened a carrier that never closed",
				correlation,
			)
		}
	}
	if chainErr != nil {
		return nil, chainErr
	}
	return counts, nil
}

func applyCarrierTerminalRecord(
	counts map[carrierFamily]carrierCounts,
	correlations map[string]*carrierCorrelation,
	descriptor carrierTerminalEvent,
	entry carrierAuditRecord,
	line int,
) error {
	// A correlation identity is 128 server-minted random bits in lower hex.
	// An event without one cannot be reconciled against anything and is
	// rejected outright rather than counted.
	if !lowerHex(entry.RequestID, 32) {
		return fmt.Errorf(
			"carrier audit line %d has no usable correlation identity", line,
		)
	}
	// device_hash is internal/audit's own HMAC(audit_key, deviceID) — a fixed
	// 32-byte digest, 64 lower-hex characters. Requiring the shape before
	// using it for pinning means a malformed, truncated, or absent value is
	// rejected outright rather than silently compared as an opaque string
	// (two malformed values could otherwise compare equal to each other by
	// accident, e.g. two empty strings).
	if !lowerHex(entry.DeviceHash, 64) {
		return fmt.Errorf(
			"carrier audit line %d has no usable device hash", line,
		)
	}
	class, mode, session, reason, err := parseCarrierTerminalDetail(entry.Detail)
	if err != nil {
		return fmt.Errorf("carrier audit line %d: %w", line, err)
	}
	// The event name and the sealed detail must agree about what this record
	// is. Reclassifying one without the other fails here.
	if class != descriptor.class {
		return fmt.Errorf(
			"carrier audit line %d event %q declares class %q",
			line, entry.Event, class,
		)
	}
	if descriptor.class == carrierClassAborted {
		if !slices.Contains(carrierAbortReasons, reason) {
			return fmt.Errorf(
				"carrier audit line %d aborted with unrecognised reason %q",
				line, reason,
			)
		}
	} else if reason != "none" {
		return fmt.Errorf(
			"carrier audit line %d class %q carries abort reason %q",
			line, class, reason,
		)
	}

	state, known := correlations[entry.RequestID]
	if !known {
		state = &carrierCorrelation{family: descriptor.family}
		correlations[entry.RequestID] = state
	}
	if state.family != descriptor.family {
		return fmt.Errorf(
			"carrier correlation %s appears under both carriers",
			entry.RequestID,
		)
	}
	// Every event under a correlation ID must describe the same request, not
	// merely share its ID. Checked against whatever the authenticated event
	// pinned, for every class including the authenticated event itself (which
	// pins on its own first appearance and so trivially matches).
	if state.authenticated {
		if mode != state.mode {
			return fmt.Errorf(
				"carrier correlation %s authenticated mode %q but this "+
					"event declares %q", entry.RequestID, state.mode, mode,
			)
		}
		if session != state.session {
			return fmt.Errorf(
				"carrier correlation %s authenticated session %q but this "+
					"event declares %q", entry.RequestID, state.session,
				session,
			)
		}
		if entry.DeviceHash != state.deviceHash {
			return fmt.Errorf(
				"carrier correlation %s authenticated device %q but this "+
					"event declares %q", entry.RequestID, state.deviceHash,
				entry.DeviceHash,
			)
		}
	}
	count := counts[descriptor.family]

	switch descriptor.class {
	case carrierClassAuthenticated:
		if state.authenticated {
			return fmt.Errorf(
				"carrier correlation %s authenticated more than once",
				entry.RequestID,
			)
		}
		if state.terminalClass != "" || state.closed {
			return fmt.Errorf(
				"carrier correlation %s authenticated after its terminal "+
					"event",
				entry.RequestID,
			)
		}
		state.authenticated = true
		state.mode = mode
		state.session = session
		state.deviceHash = entry.DeviceHash
		count.authenticated++
		if mode == "anonymous-token" {
			count.anonymousAuthenticated++
		}
	case carrierClassAuthOnly, carrierClassOpen, carrierClassAborted:
		if !state.authenticated {
			return fmt.Errorf(
				"carrier correlation %s reached class %s without an "+
					"authenticated event",
				entry.RequestID, descriptor.class,
			)
		}
		if state.terminalClass != "" {
			return fmt.Errorf(
				"carrier correlation %s terminalized twice (%s then %s)",
				entry.RequestID, state.terminalClass, descriptor.class,
			)
		}
		state.terminalClass = descriptor.class
		switch descriptor.class {
		case carrierClassAuthOnly:
			count.authOnly++
		case carrierClassOpen:
			count.open++
		case carrierClassAborted:
			count.aborted++
		}
	case carrierClassClosed:
		if state.terminalClass != carrierClassOpen {
			return fmt.Errorf(
				"carrier correlation %s closed without an open terminal class",
				entry.RequestID,
			)
		}
		if state.closed {
			return fmt.Errorf(
				"carrier correlation %s closed more than once",
				entry.RequestID,
			)
		}
		state.closed = true
		count.closed++
	default:
		return fmt.Errorf(
			"carrier audit line %d has unhandled class %q", line, class,
		)
	}
	counts[descriptor.family] = count
	return nil
}

// parseCarrierTerminalDetail decodes the fixed five-token carrier terminal
// encoding:
//
//	carrier-terminal/v1 class=<class> mode=<mode> session=<id> reason=<reason>
//
// The token count, order, and key names are all fixed, so anything the carrier
// did not produce in this exact shape is a rejection rather than a partial
// parse.
func parseCarrierTerminalDetail(
	detail string,
) (class, mode, session, reason string, err error) {
	fields := strings.Split(detail, " ")
	if len(fields) != 5 {
		return "", "", "", "", errors.New(
			"carrier terminal detail is not the versioned five-token form",
		)
	}
	if fields[0] != carrierTerminalSchema {
		return "", "", "", "", fmt.Errorf(
			"carrier terminal detail declares unknown schema %q", fields[0],
		)
	}
	values := make([]string, 4)
	for index, key := range []string{"class", "mode", "session", "reason"} {
		value, found := strings.CutPrefix(fields[index+1], key+"=")
		if !found || value == "" {
			return "", "", "", "", fmt.Errorf(
				"carrier terminal detail lacks a %s token", key,
			)
		}
		values[index] = value
	}
	class, mode, session, reason = values[0], values[1], values[2], values[3]
	if !slices.Contains(carrierAuthorizationModes, mode) {
		return "", "", "", "", fmt.Errorf(
			"carrier terminal detail declares unknown authorization mode %q",
			mode,
		)
	}
	if !lowerHex(session, 32) {
		return "", "", "", "", errors.New(
			"carrier terminal detail carries no valid session identity",
		)
	}
	return class, mode, session, reason, nil
}

// readCarrierCount reads a single non-negative decimal count written by the
// harness. Leading zeros, signs, and any trailing content are rejected so that
// two different byte strings can never describe the same count.
func readCarrierCount(path string) (int, error) {
	content, err := readSecureRegular(path, 1<<10)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(content))
	if text == "" {
		return 0, errors.New("count file is empty")
	}
	for index := 0; index < len(text); index++ {
		if text[index] < '0' || text[index] > '9' {
			return 0, errors.New("count file is not a plain decimal integer")
		}
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, errors.New("count file has a non-canonical leading zero")
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < 0 || value > maximumCarrierAuditEvents {
		return 0, errors.New("count file is out of range")
	}
	return value, nil
}

// evidenceManifestPaths returns the manifest-relative paths the evidence
// manifest covers. verifyEvidenceManifest has already proved every one of them
// matches its recorded digest before this is consulted.
func evidenceManifestPaths(
	evidenceDirectory string,
) (map[string]struct{}, error) {
	content, err := readSecureRegular(
		filepath.Join(evidenceDirectory, "evidence-manifest.sha256"),
		4<<20,
	)
	if err != nil {
		return nil, err
	}
	paths := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), maximumCarrierAuditLine)
	for scanner.Scan() {
		line := scanner.Text()
		_, path, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, errors.New("evidence manifest line is invalid")
		}
		paths[strings.TrimPrefix(path, "./")] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}
