// Command winn-phase1-conservation-smoke forces every closed carrier abort
// reason through the real H3Server and H2Server handlers, alongside genuinely
// successful requests on both carriers, and seals the resulting mixed run as
// evidence in the exact shape cmd/winn-phase1-matrix-verify recomputes the
// carrier conservation law from.
//
// This is Codex's gate-order step 4: "Exercise a small AICORE synthetic smoke
// that forces every abort reason and proves exact conservation."
//
// Nothing here is a hand-built audit fixture. Every event in the sealed
// carrier-audit.jsonl is written by internal/carrier's own record path, driven
// by a real anonymous-token CONNECT that redeemed a real single-use privacy
// token over a real TLS 1.3 QUIC (H3) or TCP (H2) connection to a real
// in-process carrier. The five abort reasons are produced by breaking the
// carrier in five different real ways:
//
//	carrier_rate_limited    a real ratelimit.BucketLimiter whose key table is
//	                        full. Anonymous principals are per-token
//	                        pseudonyms, so a per-principal token bucket can
//	                        never reject a second distinct principal; the
//	                        limiter's bounded key table is the reachable
//	                        rejection, and it is a real production condition.
//	invalid_carrier_mtu     a server whose MaxOuterDatagram cannot carry the
//	                        negotiated inner datagram: a real misconfiguration.
//	response_auth_failed    a server whose MaxDatagram sits below the
//	                        protocol's 576-byte floor, so the controller
//	                        response claims fail their own validation inside
//	                        carrierauth.NewResponseClaimsWithMaximum. No
//	                        signing path is stubbed.
//	awg_backend_unavailable a fixed AWG backend address the kernel genuinely
//	                        cannot route to, dialed by the carrier's own
//	                        unmodified dialer. The precondition is asserted
//	                        before the run: if the dial unexpectedly succeeds,
//	                        the smoke fails loudly rather than faking it.
//	audit_unavailable       a one-shot fault-injecting audit.Sink wrapper that
//	                        refuses exactly one Record() call, then delegates
//	                        normally. This is the only Go-level fake in the
//	                        run, and it is unavoidable: the reason exists
//	                        precisely to describe a transient evidence-sink
//	                        write failure, and forcing a real one (ENOSPC, a
//	                        revoked descriptor) would damage the very log the
//	                        rest of the evidence lives in. The wrapper never
//	                        writes anything, so the HMAC chain is untouched,
//	                        and it counts its own refusals so the run can prove
//	                        the injection actually fired.
//
// SELF-VERIFICATION. A smoke that only reported what it *attempted* would be
// worthless as evidence: a regression that recorded five copies of one abort
// reason, reclassified a terminal event, or dropped a correlation would still
// let it print success. So every claim this program makes is recomputed by
// parsing its own sealed carrier-audit.jsonl after the fact:
//
//  1. Per driven request, the records the carrier appended since the previous
//     request are read back and required to be exactly the expected event
//     sequence, under exactly one correlation identity and one device hash,
//     with a settle window that rejects any extra record. This is what stops
//     the program's own idea of "which reason I triggered, in what order" from
//     drifting from what was actually sealed.
//  2. Across the whole run, each carrier's terminal-class counts and its
//     multiset of abort reasons are recomputed and required to match exactly:
//     every member of carrier.AbortReasons() exactly once, per carrier.
//  3. The fault injectors count their own activations, so "the reason was
//     recorded" is backed by "the mechanism meant to cause it actually fired".
//     The injector set itself is count-pinned to a canonical two-entry schema,
//     so an unregistered, renamed, or extra injector fails explicitly instead
//     of quietly omitting its own proof.
//  4. The assertion set is pinned to an exact canonical name list, so an
//     assertion that is deleted or renamed rather than weakened in place also
//     fails the run. A missing assertion is otherwise indistinguishable from a
//     rejecting one to anything that looks results up by name.
//
// BINDING. The run refuses to create anything at all unless the runner names
// both the reviewed artifact digest (-expected-binary-sha256) and the SHA-256
// it computed over the deployed source manifest (-expected-source-digest), and
// unless this executable's own ldflags-stamped source digest equals the
// latter. An unstamped build cannot produce evidence.
//
// The result is written to carrier-abort-coverage.json, computed entirely from
// the sealed events, and sealed in the evidence manifest with everything else.
// If any assertion fails the manifest is deliberately NOT sealed, so a failed
// run cannot be mistaken for evidence.
//
// The audit HMAC key is deliberately NOT sealed into the evidence directory.
// It lives in the work directory, exactly as the live carrier's does: sealing
// the MAC key beside the log it authenticates would let anyone holding the
// evidence forge entries.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pki"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/ratelimit"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

// sourceDigest is stamped at build time by scripts/build_conservation_smoke_linux.sh
// (-ldflags "-X main.sourceDigest=..."), so the sealed evidence names the exact
// source tree that produced it.
var sourceDigest = ""

const (
	controllerID     = "lab-controller"
	publicTarget     = "winn.invalid:443"
	suiteName        = "x25519-mlkem768"
	labDeviceID      = "android-lab-1"
	carrierAuthMode  = "anonymous-token"
	auditLogName     = "carrier-audit.jsonl"
	redemptionName   = "redemption-count.txt"
	conservationName = "carrier-conservation.txt"
	environmentName  = "environment.txt"
	coverageName     = "carrier-abort-coverage.json"
	manifestName     = "evidence-manifest.sha256"
	schemaToken      = "carrier-terminal/v1"
	coverageSchema   = "winn-carrier-abort-coverage/v2"

	// belowProtocolFloorDatagram is under carrierauth's 576-byte minimum, so
	// the controller response claims a server configured this way would have
	// to sign fail their own validation. Real configuration, real failure.
	belowProtocolFloorDatagram = 500

	// truncatedOuterDatagram cannot carry any legal inner datagram plus the
	// 16-byte Winn envelope header.
	truncatedOuterDatagram = 100

	// defaultSettleWindow is how long the reconciler waits after collecting a
	// request's expected records before declaring that no further record
	// followed. Without it, a duplicate or late terminal event written just
	// after the check would go unnoticed.
	defaultSettleWindow = 500 * time.Millisecond

	// defaultRecordWait bounds how long one request's records may take to
	// appear. The closed record in particular is written by the carrier only
	// after the client tears the relay down.
	defaultRecordWait = 20 * time.Second
)

// canonicalAssertionNames is the exact, ordered set of recomputed assertions a
// run must produce, and it is itself asserted (by the last entry) against what
// the assertion layer actually emitted.
//
// This exists because "assertion X did not pass" and "assertion X was deleted"
// are indistinguishable to any consumer that only looks up results by name: a
// missing key reads as a zero value, which reads as a rejection. Pinning the
// exact name list turns a deleted or renamed production assertion into a loud
// failure of this run rather than a silently smaller proof.
var canonicalAssertionNames = []string{
	"h3_terminal_counts_exact",
	"h3_abort_reason_set_exact",
	"h3_conservation_identity",
	"h3_open_equals_closed",
	"h2_terminal_counts_exact",
	"h2_abort_reason_set_exact",
	"h2_conservation_identity",
	"h2_open_equals_closed",
	"h2_has_no_auth_only_class",
	"h3_plan_matches_expectation_table",
	"h2_plan_matches_expectation_table",
	"every_trigger_reconciled_against_the_sealed_trail",
	"every_request_has_its_own_correlation_identity",
	"sealed_correlations_match_driven_requests",
	"redemptions_equal_authenticated",
	"fault_injector_schema_exact",
	"fault_injector_fired_h3_audit_unavailable_sink",
	"fault_injector_fired_h2_audit_unavailable_sink",
	"assertion_set_is_exactly_canonical",
}

// assertionSetName is the meta-assertion's own name. It is appended to the
// produced list before the comparison, so the canonical list above describes
// the complete emitted set including this entry.
const assertionSetName = "assertion_set_is_exactly_canonical"

// injectorPlan is one canonical fault injector: which record it refuses, and
// how many times it must have refused by the end of the run.
type injectorPlan struct {
	Name             string `json:"name"`
	FailEvent        string `json:"fail_event"`
	ExpectedRefusals int64  `json:"expected_refusals"`
}

// expectedInjectors pins the fault-injection surface exactly: two injectors,
// these names, these fail events, exactly one refusal each.
//
// Count-pinning matters because the injector list is what turns "the abort
// reason appears in the trail" into "the mechanism meant to cause it actually
// fired". An injector attached to a handler but never registered here would
// otherwise simply omit its own proof, and a third injector added later would
// go unremarked. Both are now explicit failures.
var expectedInjectors = []injectorPlan{
	{
		Name:             "h3_audit_unavailable_sink",
		FailEvent:        carrier.EventH3AuthOnly,
		ExpectedRefusals: 1,
	},
	{
		Name:             "h2_audit_unavailable_sink",
		FailEvent:        carrier.EventH2Open,
		ExpectedRefusals: 1,
	},
}

// Expected per-carrier terminal-class totals for this fixed plan. They are
// stated here as a flat, reviewable table and are ALSO derived independently
// from the per-trigger expectations below; the two are required to agree, so a
// silent edit to either one fails the run.
//
// H2 has no auth_only class at all — the "authenticate without allocating a
// backend" purpose exists only on H3 — so its expected auth_only count is zero
// and the run additionally asserts no carrier_h2_auth_only event exists.
var expectedFamilyTotals = map[string]familyExpectation{
	"h3": {Authenticated: 7, AuthOnly: 1, Open: 1, Closed: 1, Aborted: 5},
	"h2": {Authenticated: 6, AuthOnly: 0, Open: 1, Closed: 1, Aborted: 5},
}

type familyExpectation struct {
	Authenticated int `json:"authenticated"`
	AuthOnly      int `json:"auth_only"`
	Open          int `json:"open"`
	Closed        int `json:"closed"`
	Aborted       int `json:"aborted"`
}

func main() {
	evidenceDirectory := flag.String(
		"evidence-dir", "", "new sealed evidence directory to create",
	)
	workDirectory := flag.String(
		"work-dir", "",
		"private working directory for PKI and the audit HMAC key; "+
			"never inside the evidence directory",
	)
	unroutableBackend := flag.String(
		"unroutable-backend", "[100::1]:443",
		"fixed AWG backend address the kernel must genuinely fail to reach",
	)
	expectedBinary := flag.String(
		"expected-binary-sha256", "",
		"REQUIRED. SHA-256 the running executable must have, supplied by the "+
			"runner, so the sealed evidence is bound to the artifact that was "+
			"reviewed. Without it nothing may be sealed",
	)
	expectedSource := flag.String(
		"expected-source-digest", "",
		"REQUIRED. SHA-256 of the deployed .source.sha256 manifest, computed "+
			"by the runner from the file on disk, and required to equal this "+
			"executable's own ldflags-stamped source digest",
	)
	flag.Parse()

	if err := run(
		*evidenceDirectory, *workDirectory, *unroutableBackend,
		*expectedBinary, *expectedSource,
	); err != nil {
		fmt.Fprintln(os.Stderr, "CONSERVATION_SMOKE_FAIL:", err)
		os.Exit(1)
	}
}

// expectedEvent is one record a driven request must cause the carrier to seal,
// in order.
type expectedEvent struct {
	Event  string `json:"event"`
	Class  string `json:"class"`
	Reason string `json:"reason"`
}

// trigger is one driven request: what was deliberately broken, which carrier
// code path that reaches, the records it must produce, and — filled in after
// the fact by parsing the sealed trail — the records it actually produced.
type trigger struct {
	Name           string          `json:"name"`
	Carrier        string          `json:"carrier"`
	DeclaredHow    string          `json:"declared_how"`
	DeclaredWhere  string          `json:"declared_where"`
	ExpectedEvents []expectedEvent `json:"expected_events"`
	ObservedEvents []expectedEvent `json:"observed_events"`
	Correlation    string          `json:"correlation_id"`
	DeviceHash     string          `json:"device_hash"`
	Session        string          `json:"session"`
	Sequences      []uint64        `json:"audit_sequences"`
	Reconciled     bool            `json:"reconciled"`
}

// sealedRecord is one parsed line of the sealed carrier audit trail.
type sealedRecord struct {
	Sequence   uint64
	Event      string
	DeviceHash string
	RequestID  string
	Detail     string
	Class      string
	Mode       string
	Session    string
	Reason     string
	Terminal   bool
}

type smoke struct {
	evidenceDirectory string
	workDirectory     string
	expectedBinary    string
	expectedSource    string
	binaryDigest      string
	settleWindow      time.Duration
	recordWait        time.Duration
	suite             tlsconfig.Suite
	lab               pki.Paths
	log               *audit.Log
	issuer            *rsa.PrivateKey
	issuerKeyID       string
	redemptions       *countingRedemptionStore
	replay            *carrierauth.ReplayCache
	controllerSigner  *pqauth.Signer
	deviceSigner      *pqauth.Signer
	controllerPins    *pqauth.VerifierSet
	serverTLSH3       *tls.Config
	clientTLSH3       *tls.Config
	serverTLSH2       *tls.Config
	clientTLSH2       *tls.Config
	echoAddress       string
	unroutableBackend string
	triggers          []*trigger
	injectors         []*oneShotFailingSink
	consumed          int
	shutdown          []func()
}

func run(
	evidenceDirectory string,
	workDirectory string,
	unroutableBackend string,
	expectedBinary string,
	expectedSource string,
) error {
	// Artifact and source binding come first, before this program inspects,
	// creates, or drives anything at all. A build that cannot name both the
	// exact executable under review and the exact source tree it was compiled
	// from is not permitted to produce evidence, and "not permitted" has to
	// mean "fails before any evidence exists", not "seals an honest note that
	// the binding was absent".
	if err := requireBinding(expectedBinary, expectedSource); err != nil {
		return err
	}
	binaryDigest, err := selfDigest()
	if err != nil {
		return err
	}
	if expectedBinary != binaryDigest {
		return fmt.Errorf(
			"running executable SHA-256 is %s, runner expected %s",
			binaryDigest, expectedBinary,
		)
	}

	if evidenceDirectory == "" || workDirectory == "" {
		return errors.New("-evidence-dir and -work-dir are required")
	}
	absoluteEvidence, err := filepath.Abs(evidenceDirectory)
	if err != nil {
		return err
	}
	absoluteWork, err := filepath.Abs(workDirectory)
	if err != nil {
		return err
	}
	if absoluteWork == absoluteEvidence ||
		strings.HasPrefix(absoluteWork+string(os.PathSeparator),
			absoluteEvidence+string(os.PathSeparator)) {
		return errors.New(
			"the work directory holds the audit HMAC key and must never be " +
				"inside the sealed evidence directory",
		)
	}
	if _, err := os.Stat(absoluteEvidence); err == nil {
		return fmt.Errorf(
			"evidence directory already exists: %s", absoluteEvidence,
		)
	}

	// Precondition, asserted rather than assumed: the "unreachable" AWG
	// backend must genuinely be unreachable on this host. A smoke that
	// silently dialed a reachable address and then reported
	// awg_backend_unavailable would be fabricating the finding.
	if err := requireUnreachable(unroutableBackend); err != nil {
		return err
	}

	if err := os.MkdirAll(absoluteEvidence, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(absoluteWork, 0o700); err != nil {
		return err
	}

	current := &smoke{
		evidenceDirectory: absoluteEvidence,
		workDirectory:     absoluteWork,
		expectedBinary:    expectedBinary,
		expectedSource:    expectedSource,
		binaryDigest:      binaryDigest,
		settleWindow:      defaultSettleWindow,
		recordWait:        defaultRecordWait,
		unroutableBackend: unroutableBackend,
	}
	defer current.stop()
	if err := current.setup(); err != nil {
		return err
	}
	if err := current.driveH3(); err != nil {
		return err
	}
	if err := current.driveH2(); err != nil {
		return err
	}
	return current.seal()
}

// requireBinding refuses to let an unbound or unstamped build get as far as
// creating a directory.
//
// Three separate things have to hold, and every one of them used to be sealed
// honestly but never enforced: the runner has to state which artifact digest it
// reviewed; the runner has to state the SHA-256 it computed over the deployed
// source manifest; and this executable has to carry a real ldflags-stamped
// source digest that equals the runner's. A build produced by plain `go build`
// carries an empty stamp and now fails here instead of sealing evidence that
// admits, in prose, that nobody knows what source produced it.
func requireBinding(expectedBinary, expectedSource string) error {
	if !lowerHex(expectedBinary, 64) {
		return fmt.Errorf(
			"-expected-binary-sha256 is required: pass the reviewed "+
				"artifact's SHA-256 as 64 lower-hex characters, got %q",
			expectedBinary,
		)
	}
	if !lowerHex(expectedSource, 64) {
		return fmt.Errorf(
			"-expected-source-digest is required: pass the SHA-256 the runner "+
				"computed over the deployed .source.sha256 manifest as 64 "+
				"lower-hex characters, got %q",
			expectedSource,
		)
	}
	if !lowerHex(sourceDigest, 64) {
		return fmt.Errorf(
			"this executable carries source digest %q: it was not stamped by "+
				"scripts/build_conservation_smoke_linux.sh, so it may not "+
				"produce evidence",
			sourceDigest,
		)
	}
	if expectedSource != sourceDigest {
		return fmt.Errorf(
			"the deployed source manifest hashes to %s but this executable "+
				"was built from source manifest %s",
			expectedSource, sourceDigest,
		)
	}
	return nil
}

// requireUnreachable proves the kernel refuses to create a connected UDP
// socket to the configured backend before any evidence is produced.
func requireUnreachable(address string) error {
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("resolve unroutable backend %s: %w", address, err)
	}
	var dialer net.Dialer
	connection, err := dialer.Dial("udp", resolved.String())
	if err != nil {
		return nil
	}
	_ = connection.Close()
	return fmt.Errorf(
		"the configured unroutable backend %s is reachable on this host, so "+
			"awg_backend_unavailable cannot be forced for real here; pass a "+
			"genuinely unroutable -unroutable-backend instead of accepting a "+
			"simulated failure",
		address,
	)
}

func selfDigest() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return sha256File(executable)
}

func (s *smoke) setup() error {
	suite, err := tlsconfig.ParseSuite(suiteName)
	if err != nil {
		return err
	}
	s.suite = suite
	lab, err := pki.GenerateLab(
		filepath.Join(s.workDirectory, "pki"),
		"127.0.0.1",
		labDeviceID,
		time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("generate lab PKI: %w", err)
	}
	s.lab = lab

	// The HMAC writer key stays in the PKI directory, outside the evidence
	// directory, exactly as the live carrier keeps it.
	log, err := audit.Open(
		filepath.Join(s.evidenceDirectory, auditLogName), lab.AuditKey,
	)
	if err != nil {
		return fmt.Errorf("open carrier audit log: %w", err)
	}
	s.log = log
	s.shutdown = append(s.shutdown, func() { _ = log.Close() })

	issuer, err := privacytoken.GenerateIssuerKey(3072)
	if err != nil {
		return err
	}
	s.issuer = issuer
	keyID, err := privacytoken.IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		return err
	}
	s.issuerKeyID = keyID
	cache, err := privacytoken.NewRedemptionCache(1024)
	if err != nil {
		return err
	}
	s.redemptions = &countingRedemptionStore{inner: cache}
	replay, err := carrierauth.NewReplayCache(1024)
	if err != nil {
		return err
	}
	s.replay = replay
	s.controllerSigner, err = pqauth.LoadSigner(
		pqauth.MLDSA87, lab.ControllerPQ87Seed,
	)
	if err != nil {
		return err
	}
	s.controllerPins, err = pqauth.LoadVerifierSet(lab.ControllerPQPins)
	if err != nil {
		return err
	}
	// NewH3Dialer/NewH2Dialer require a complete identity-mode configuration
	// before the caller may switch the dialer to anonymous-token mode, exactly
	// as internal/carrier's own integration tests do. The signer below is
	// discarded on every dialer the smoke builds; every request is
	// anonymous-token and signs with its token's committed ephemeral key.
	s.deviceSigner, err = pqauth.LoadSigner(
		pqauth.MLDSA65, lab.DevicePQ65Seed,
	)
	if err != nil {
		return err
	}
	if s.serverTLSH3, err = tlsconfig.ServerAnonymousForALPN(
		lab.ServerCert, lab.ServerKey, suite, http3.NextProtoH3,
	); err != nil {
		return err
	}
	if s.clientTLSH3, err = tlsconfig.ClientAnonymousForALPN(
		lab.CACert, "127.0.0.1", suite, http3.NextProtoH3,
	); err != nil {
		return err
	}
	if s.serverTLSH2, err = tlsconfig.ServerAnonymousForALPN(
		lab.ServerCert, lab.ServerKey, suite, http2.NextProtoTLS,
	); err != nil {
		return err
	}
	if s.clientTLSH2, err = tlsconfig.ClientAnonymousForALPN(
		lab.CACert, "127.0.0.1", suite, http2.NextProtoTLS,
	); err != nil {
		return err
	}
	echoAddress, stopEcho, err := startUDPEcho()
	if err != nil {
		return err
	}
	s.echoAddress = echoAddress
	s.shutdown = append(s.shutdown, stopEcho)
	return nil
}

func (s *smoke) stop() {
	for index := len(s.shutdown) - 1; index >= 0; index-- {
		s.shutdown[index]()
	}
}

func (s *smoke) requestVerifier() *carrierauth.RequestVerifier {
	return &carrierauth.RequestVerifier{
		Replay:  s.replay,
		Suite:   s.suite.Name,
		MaxSkew: time.Minute,
	}
}

func (s *smoke) tokenVerifier() *carrier.PrivacyTokenVerifier {
	now := time.Now().UTC()
	return &carrier.PrivacyTokenVerifier{
		PublicKey:   &s.issuer.PublicKey,
		KeyID:       s.issuerKeyID,
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		Redemptions: s.redemptions,
		LabMode:     true,
	}
}

// --- expectation builders -------------------------------------------------

func successEvents(family string) []expectedEvent {
	prefix := "carrier_" + family + "_"
	return []expectedEvent{
		{prefix + "authenticated", "authenticated", "none"},
		{prefix + "open", "open", "none"},
		{prefix + "closed", "closed", "none"},
	}
}

func authOnlyEvents() []expectedEvent {
	return []expectedEvent{
		{"carrier_h3_authenticated", "authenticated", "none"},
		{"carrier_h3_auth_only", "auth_only", "none"},
	}
}

func abortEvents(family, reason string) []expectedEvent {
	prefix := "carrier_" + family + "_"
	return []expectedEvent{
		{prefix + "authenticated", "authenticated", "none"},
		{prefix + "aborted", "aborted", reason},
	}
}

// --- H3 -------------------------------------------------------------------

// h3Instance is one live H3Server plus the URI template a client must use to
// reach it.
type h3Instance struct {
	handler  *carrier.H3Server
	template string
}

func (s *smoke) startH3(
	backend string,
	configure func(*carrier.H3Server),
) (*h3Instance, error) {
	packetListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	template := "https://" + packetListener.LocalAddr().String() +
		"/.well-known/masque/udp/{target_host}/{target_port}/"
	handler, err := carrier.NewH3Server(
		template, publicTarget, backend, s.suite,
		s.requestVerifier(), s.controllerSigner, controllerID,
	)
	if err != nil {
		_ = packetListener.Close()
		return nil, err
	}
	handler.Audit = s.log
	handler.PrivacyTokens = s.tokenVerifier()
	if configure != nil {
		configure(handler)
	}
	server := &http3.Server{
		TLSConfig:       s.serverTLSH3,
		Handler:         handler,
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			Allow0RTT:       false,
			InitialPacketSize: carrier.H3InitialPacketSize(
				carrier.DefaultMaxDatagram + carrier.CarrierEnvelopeOverhead,
			),
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
		},
	}
	go func() { _ = server.Serve(packetListener) }()
	s.shutdown = append(s.shutdown, func() {
		_ = server.Close()
		_ = packetListener.Close()
		_ = handler.Close()
	})
	return &h3Instance{handler: handler, template: template}, nil
}

func (s *smoke) newH3Dialer(template string) (*carrier.H3Dialer, error) {
	sessionID, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	epoch, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	dialer, err := carrier.NewH3Dialer(
		template, publicTarget, s.lab.DeviceID, sessionID, s.suite,
		s.clientTLSH3, s.deviceSigner, &carrierauth.ResponseVerifier{
			Verifiers:    s.controllerPins,
			ControllerID: controllerID,
			Suite:        s.suite.Name,
			MaxSkew:      time.Minute,
		},
	)
	if err != nil {
		return nil, err
	}
	dialer.SequenceEpoch = epoch
	dialer.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	dialer.DeviceID = ""
	dialer.DeviceSigner = nil
	credential, err := s.newAnonymousCredential()
	if err != nil {
		return nil, err
	}
	dialer.AnonymousCredentials = &oneCredentialSource{credential: credential}
	return dialer, nil
}

// h3AuthenticateOnly drives one real authentication-only CONNECT-UDP request:
// a live QUIC/TLS handshake, one redeemed anonymous token, and a controller
// response the client verifies. It allocates no AWG backend.
func (s *smoke) h3AuthenticateOnly(
	ctx context.Context,
	instance *h3Instance,
) error {
	dialer, err := s.newH3Dialer(instance.template)
	if err != nil {
		return err
	}
	prepared, err := dialer.PrepareH3Path(ctx)
	if err != nil {
		return err
	}
	defer prepared.Close()
	return dialer.AuthenticatePreparedH3Path(ctx, prepared)
}

// h3Data drives one real data-purpose CONNECT-UDP request.
func (s *smoke) h3Data(
	ctx context.Context,
	instance *h3Instance,
) (net.PacketConn, error) {
	dialer, err := s.newH3Dialer(instance.template)
	if err != nil {
		return nil, err
	}
	return dialer.Dial(ctx)
}

func (s *smoke) driveH3() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. A clean, fully successful authentication-only request: the H3
	//    auth_only terminal class.
	base, err := s.startH3(s.echoAddress, nil)
	if err != nil {
		return err
	}
	if err := s.h3AuthenticateOnly(ctx, base); err != nil {
		return fmt.Errorf("H3 auth-only success: %w", err)
	}
	if err := s.reconcile(&trigger{
		Name:        "h3_auth_only_success",
		Carrier:     "h3",
		DeclaredHow: "clean server, authenticate-only CONNECT-UDP over live QUIC",
		DeclaredWhere: "internal/carrier/h3.go ServeHTTP " +
			"purpose==authenticate-only",
		ExpectedEvents: authOnlyEvents(),
	}); err != nil {
		return err
	}

	// 2. A clean, fully successful data request: the H3 open/closed pair,
	//    including a real datagram round trip through the AWG backend.
	connection, err := s.h3Data(ctx, base)
	if err != nil {
		return fmt.Errorf("H3 data success: %w", err)
	}
	if err := echoRoundTrip(connection); err != nil {
		_ = connection.Close()
		return fmt.Errorf("H3 data round trip: %w", err)
	}
	_ = connection.Close()
	if err := s.reconcile(&trigger{
		Name:           "h3_open_closed_success",
		Carrier:        "h3",
		DeclaredHow:    "clean server, data CONNECT-UDP with a real datagram echo",
		DeclaredWhere:  "internal/carrier/h3.go ServeHTTP relay path",
		ExpectedEvents: successEvents("h3"),
	}); err != nil {
		return err
	}

	// 3+4. One server whose outer datagram cannot carry any inner datagram and
	//      whose rate limiter can hold exactly one principal. The first request
	//      passes the limiter and dies on the MTU check; the second cannot be
	//      admitted to the limiter's key table at all.
	constrained, err := s.startH3(s.echoAddress, func(handler *carrier.H3Server) {
		handler.MaxOuterDatagram = truncatedOuterDatagram
		limiter, limiterErr := ratelimit.New(1, 60, 1)
		if limiterErr != nil {
			panic(limiterErr)
		}
		handler.Limiter = limiter
	})
	if err != nil {
		return err
	}
	if err := s.h3AuthenticateOnly(ctx, constrained); err == nil {
		return errors.New("H3 invalid-MTU request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h3_invalid_carrier_mtu",
		Carrier: "h3",
		DeclaredHow: fmt.Sprintf(
			"server MaxOuterDatagram=%d, below inner+envelope header",
			truncatedOuterDatagram,
		),
		DeclaredWhere: "internal/carrier/h3.go ServeHTTP maxOuter bound check " +
			"-> abortAuthenticated(AbortReasonInvalidCarrierMTU)",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonInvalidCarrierMTU),
	}); err != nil {
		return err
	}
	if err := s.h3AuthenticateOnly(ctx, constrained); err == nil {
		return errors.New("H3 rate-limited request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h3_carrier_rate_limited",
		Carrier: "h3",
		DeclaredHow: "real ratelimit.BucketLimiter with a one-key table " +
			"already occupied by the previous anonymous principal",
		DeclaredWhere: "internal/carrier/h3.go ServeHTTP Limiter.Allow " +
			"-> abortAuthenticated(AbortReasonRateLimited)",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonRateLimited),
	}); err != nil {
		return err
	}

	// 5. A server whose negotiated maximum datagram is below the protocol
	//    floor, so the controller response claims fail their own validation.
	responseAuth, err := s.startH3(s.echoAddress, func(handler *carrier.H3Server) {
		handler.MaxDatagram = belowProtocolFloorDatagram
	})
	if err != nil {
		return err
	}
	if _, err := s.h3Data(ctx, responseAuth); err == nil {
		return errors.New("H3 response-auth request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h3_response_auth_failed",
		Carrier: "h3",
		DeclaredHow: fmt.Sprintf(
			"server MaxDatagram=%d, below carrierauth's 576-byte floor",
			belowProtocolFloorDatagram,
		),
		DeclaredWhere: "internal/carrier/h3.go ServeHTTP " +
			"carrierauth.NewResponseClaimsWithMaximum -> " +
			"abortAuthenticated(AbortReasonResponseAuthFailed)",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonResponseAuthFailed),
	}); err != nil {
		return err
	}

	// 6. A fixed AWG backend the kernel cannot route to, dialed by the
	//    carrier's own unmodified dialer.
	backendDown, err := s.startH3(s.unroutableBackend, nil)
	if err != nil {
		return err
	}
	if _, err := s.h3Data(ctx, backendDown); err == nil {
		return errors.New("H3 backend-down request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h3_awg_backend_unavailable",
		Carrier: "h3",
		DeclaredHow: "fixed AWG backend " + s.unroutableBackend +
			", kernel-unroutable; carrier's own net.Dialer fails",
		DeclaredWhere: "internal/carrier/h3.go dialBackend -> " +
			"abortAuthenticated(AbortReasonBackendUnavailable)",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonBackendUnavailable),
	}); err != nil {
		return err
	}

	// 7. An audit sink that refuses exactly one write: the auth_only terminal
	//    record. The abort record that follows is accepted, which is what a
	//    transient sink failure looks like from the carrier's side.
	auditFail, err := s.startH3(s.echoAddress, nil)
	if err != nil {
		return err
	}
	injector, err := s.newInjector("h3_audit_unavailable_sink")
	if err != nil {
		return err
	}
	auditFail.handler.Audit = injector
	if err := s.h3AuthenticateOnly(ctx, auditFail); err == nil {
		return errors.New("H3 audit-unavailable request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h3_audit_unavailable",
		Carrier: "h3",
		DeclaredHow: "audit.Sink wrapper refuses exactly one Record() call, " +
			"the carrier_h3_auth_only terminal record, then delegates normally",
		DeclaredWhere: "internal/carrier/h3.go sealTerminal -> " +
			"abortAuthenticated(AbortReasonAuditUnavailable)",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonAuditUnavailable),
	}); err != nil {
		return err
	}
	return nil
}

// --- H2 -------------------------------------------------------------------

type h2Instance struct {
	handler *carrier.H2Server
	url     string
}

func (s *smoke) startH2(
	backend string,
	configure func(*carrier.H2Server),
) (*h2Instance, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	handler, err := carrier.NewH2Server(
		publicTarget, backend, s.suite,
		s.requestVerifier(), s.controllerSigner, controllerID,
	)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	handler.Audit = s.log
	handler.PrivacyTokens = s.tokenVerifier()
	if configure != nil {
		configure(handler)
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         s.serverTLSH2,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 64,
		IdleTimeout:          30 * time.Second,
	}); err != nil {
		_ = listener.Close()
		return nil, err
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	s.shutdown = append(s.shutdown, func() {
		shutdownContext, cancel := context.WithTimeout(
			context.Background(), 3*time.Second,
		)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
		_ = listener.Close()
	})
	return &h2Instance{
		handler: handler,
		url:     "https://" + listener.Addr().String() + carrier.H2Path,
	}, nil
}

func (s *smoke) h2Dial(
	ctx context.Context,
	instance *h2Instance,
) (net.PacketConn, error) {
	sessionID, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	epoch, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	dialer, err := carrier.NewH2Dialer(
		instance.url, publicTarget, s.lab.DeviceID, sessionID, s.suite,
		s.clientTLSH2, s.deviceSigner, &carrierauth.ResponseVerifier{
			Verifiers:    s.controllerPins,
			ControllerID: controllerID,
			Suite:        s.suite.Name,
			MaxSkew:      time.Minute,
		},
	)
	if err != nil {
		return nil, err
	}
	dialer.SequenceEpoch = epoch
	dialer.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	dialer.DeviceID = ""
	dialer.DeviceSigner = nil
	credential, err := s.newAnonymousCredential()
	if err != nil {
		return nil, err
	}
	dialer.AnonymousCredentials = &oneCredentialSource{credential: credential}
	return dialer.Dial(ctx)
}

func (s *smoke) driveH2() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. A clean, fully successful H2 request: open/closed with a real
	//    datagram round trip. H2 has no auth_only class.
	base, err := s.startH2(s.echoAddress, nil)
	if err != nil {
		return err
	}
	connection, err := s.h2Dial(ctx, base)
	if err != nil {
		return fmt.Errorf("H2 success: %w", err)
	}
	if err := echoRoundTrip(connection); err != nil {
		_ = connection.Close()
		return fmt.Errorf("H2 round trip: %w", err)
	}
	_ = connection.Close()
	if err := s.reconcile(&trigger{
		Name:    "h2_open_closed_success",
		Carrier: "h2",
		DeclaredHow: "clean server, POST /winn/v2/udp-stream with a real " +
			"datagram echo",
		DeclaredWhere:  "internal/carrier/h2.go ServeHTTP relay path",
		ExpectedEvents: successEvents("h2"),
	}); err != nil {
		return err
	}

	// 2+3. Same constrained-server construction as H3, exercising H2's own
	//      independent abortAuthenticatedH2 implementation.
	constrained, err := s.startH2(s.echoAddress, func(handler *carrier.H2Server) {
		handler.MaxOuterDatagram = truncatedOuterDatagram
		limiter, limiterErr := ratelimit.New(1, 60, 1)
		if limiterErr != nil {
			panic(limiterErr)
		}
		handler.Limiter = limiter
	})
	if err != nil {
		return err
	}
	if _, err := s.h2Dial(ctx, constrained); err == nil {
		return errors.New("H2 invalid-MTU request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h2_invalid_carrier_mtu",
		Carrier: "h2",
		DeclaredHow: fmt.Sprintf(
			"server MaxOuterDatagram=%d, below inner+envelope header",
			truncatedOuterDatagram,
		),
		DeclaredWhere: "internal/carrier/h2.go ServeHTTP maxOuter bound check " +
			"-> abortAuthenticatedH2(AbortReasonInvalidCarrierMTU)",
		ExpectedEvents: abortEvents("h2", carrier.AbortReasonInvalidCarrierMTU),
	}); err != nil {
		return err
	}
	if _, err := s.h2Dial(ctx, constrained); err == nil {
		return errors.New("H2 rate-limited request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h2_carrier_rate_limited",
		Carrier: "h2",
		DeclaredHow: "real ratelimit.BucketLimiter with a one-key table " +
			"already occupied by the previous anonymous principal",
		DeclaredWhere: "internal/carrier/h2.go ServeHTTP Limiter.Allow " +
			"-> abortAuthenticatedH2(AbortReasonRateLimited)",
		ExpectedEvents: abortEvents("h2", carrier.AbortReasonRateLimited),
	}); err != nil {
		return err
	}

	responseAuth, err := s.startH2(s.echoAddress, func(handler *carrier.H2Server) {
		handler.MaxDatagram = belowProtocolFloorDatagram
	})
	if err != nil {
		return err
	}
	if _, err := s.h2Dial(ctx, responseAuth); err == nil {
		return errors.New("H2 response-auth request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h2_response_auth_failed",
		Carrier: "h2",
		DeclaredHow: fmt.Sprintf(
			"server MaxDatagram=%d, below carrierauth's 576-byte floor",
			belowProtocolFloorDatagram,
		),
		DeclaredWhere: "internal/carrier/h2.go ServeHTTP " +
			"carrierauth.NewResponseClaimsWithMaximum -> " +
			"abortAuthenticatedH2(AbortReasonResponseAuthFailed)",
		ExpectedEvents: abortEvents("h2", carrier.AbortReasonResponseAuthFailed),
	}); err != nil {
		return err
	}

	backendDown, err := s.startH2(s.unroutableBackend, nil)
	if err != nil {
		return err
	}
	if _, err := s.h2Dial(ctx, backendDown); err == nil {
		return errors.New("H2 backend-down request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h2_awg_backend_unavailable",
		Carrier: "h2",
		DeclaredHow: "fixed AWG backend " + s.unroutableBackend +
			", kernel-unroutable; carrier's own net.Dialer fails",
		DeclaredWhere: "internal/carrier/h2.go dialH2Backend -> " +
			"abortAuthenticatedH2(AbortReasonBackendUnavailable)",
		ExpectedEvents: abortEvents("h2", carrier.AbortReasonBackendUnavailable),
	}); err != nil {
		return err
	}

	auditFail, err := s.startH2(s.echoAddress, nil)
	if err != nil {
		return err
	}
	injector, err := s.newInjector("h2_audit_unavailable_sink")
	if err != nil {
		return err
	}
	auditFail.handler.Audit = injector
	if _, err := s.h2Dial(ctx, auditFail); err == nil {
		return errors.New("H2 audit-unavailable request unexpectedly succeeded")
	}
	if err := s.reconcile(&trigger{
		Name:    "h2_audit_unavailable",
		Carrier: "h2",
		DeclaredHow: "audit.Sink wrapper refuses exactly one Record() call, " +
			"the carrier_h2_open terminal record, then delegates normally",
		DeclaredWhere: "internal/carrier/h2.go sealTerminalH2 -> " +
			"abortAuthenticatedH2(AbortReasonAuditUnavailable)",
		ExpectedEvents: abortEvents("h2", carrier.AbortReasonAuditUnavailable),
	}); err != nil {
		return err
	}
	return nil
}

// newInjector builds the one canonical injector registered under this name and
// records it. Constructing injectors only from expectedInjectors means the
// registered list and the pinned schema cannot drift: a renamed injector, or
// one wired to a different fail event, cannot be created at all.
func (s *smoke) newInjector(name string) (*oneShotFailingSink, error) {
	index := slices.IndexFunc(
		expectedInjectors,
		func(plan injectorPlan) bool { return plan.Name == name },
	)
	if index < 0 {
		return nil, fmt.Errorf(
			"%q is not one of the canonical fault injectors", name,
		)
	}
	plan := expectedInjectors[index]
	injector := &oneShotFailingSink{
		name:      plan.Name,
		inner:     s.log,
		failEvent: plan.FailEvent,
	}
	s.injectors = append(s.injectors, injector)
	return injector, nil
}

// --- per-request reconciliation -------------------------------------------

// reconcile reads back the records the carrier appended for the request just
// driven and requires them to be exactly what this trigger declared, in order,
// under one correlation identity.
//
// This is the check that stops the program's own bookkeeping from drifting
// from the sealed trail. Driving a request and then merely printing "expected
// carrier_rate_limited" would prove nothing: the record could carry a
// different reason, a different class, an extra duplicate terminal, or belong
// to another correlation entirely, and a self-congratulatory trigger loop
// would never notice.
func (s *smoke) reconcile(entry *trigger) error {
	want := len(entry.ExpectedEvents)
	records, err := s.awaitRecords(want)
	if err != nil {
		return fmt.Errorf("%s: %w", entry.Name, err)
	}
	// No further record may follow. A duplicate or late terminal event written
	// just after the count was satisfied is exactly the defect the whole
	// conservation design exists to catch.
	time.Sleep(s.settleFor())
	extra, err := s.readRecords()
	if err != nil {
		return fmt.Errorf("%s: %w", entry.Name, err)
	}
	if len(extra) != s.consumed+want {
		return fmt.Errorf(
			"%s sealed %d records, expected exactly %d",
			entry.Name, len(extra)-s.consumed, want,
		)
	}
	s.consumed += want

	correlation := records[0].RequestID
	deviceHash := records[0].DeviceHash
	session := records[0].Session
	if !lowerHex(correlation, 32) {
		return fmt.Errorf(
			"%s sealed correlation identity %q is not 128 hex bits",
			entry.Name, correlation,
		)
	}
	if !lowerHex(deviceHash, 64) {
		return fmt.Errorf(
			"%s sealed device hash %q is not a 32-byte digest",
			entry.Name, deviceHash,
		)
	}
	for index, record := range records {
		expected := entry.ExpectedEvents[index]
		if record.Event != expected.Event ||
			record.Class != expected.Class ||
			record.Reason != expected.Reason {
			return fmt.Errorf(
				"%s record %d is %s/%s/%s, expected %s/%s/%s",
				entry.Name, index+1,
				record.Event, record.Class, record.Reason,
				expected.Event, expected.Class, expected.Reason,
			)
		}
		if record.Mode != carrierAuthMode {
			return fmt.Errorf(
				"%s record %d declares authorization mode %q",
				entry.Name, index+1, record.Mode,
			)
		}
		if record.RequestID != correlation ||
			record.DeviceHash != deviceHash ||
			record.Session != session {
			return fmt.Errorf(
				"%s record %d belongs to a different correlation identity",
				entry.Name, index+1,
			)
		}
		entry.ObservedEvents = append(entry.ObservedEvents, expectedEvent{
			Event: record.Event, Class: record.Class, Reason: record.Reason,
		})
		entry.Sequences = append(entry.Sequences, record.Sequence)
	}
	entry.Correlation = correlation
	entry.DeviceHash = deviceHash
	entry.Session = session
	entry.Reconciled = true
	s.triggers = append(s.triggers, entry)

	fmt.Printf(
		"%-28s %-4s %-24s correlation=%s sealed=%s\n",
		entry.Name, entry.Carrier,
		entry.ExpectedEvents[len(entry.ExpectedEvents)-1].Class+"/"+
			entry.ExpectedEvents[len(entry.ExpectedEvents)-1].Reason,
		correlation[:8], eventSummary(entry.ObservedEvents),
	)
	return nil
}

func eventSummary(events []expectedEvent) string {
	names := make([]string, 0, len(events))
	for _, event := range events {
		names = append(names, event.Class)
	}
	return strings.Join(names, "+")
}

// settleFor and waitFor are the reconciler's two timing bounds. They are
// fields rather than bare constants only so the reconciliation tests can drive
// the real reconcile() against a temp sealed trail in bounded time; an unset
// or non-positive value always falls back to the production default, so a
// caller cannot accidentally disable either window.
func (s *smoke) settleFor() time.Duration {
	if s.settleWindow <= 0 {
		return defaultSettleWindow
	}
	return s.settleWindow
}

func (s *smoke) waitFor() time.Duration {
	if s.recordWait <= 0 {
		return defaultRecordWait
	}
	return s.recordWait
}

// awaitRecords blocks until the sealed trail holds at least count records
// beyond the ones already reconciled, and returns exactly those.
func (s *smoke) awaitRecords(count int) ([]sealedRecord, error) {
	deadline := time.Now().Add(s.waitFor())
	for {
		records, err := s.readRecords()
		if err != nil {
			return nil, err
		}
		if len(records) >= s.consumed+count {
			return records[s.consumed : s.consumed+count], nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf(
				"timed out waiting for %d sealed records (saw %d)",
				count, len(records)-s.consumed,
			)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// readRecords parses the whole sealed trail as it stands on disk.
func (s *smoke) readRecords() ([]sealedRecord, error) {
	return readSealedRecords(
		filepath.Join(s.evidenceDirectory, auditLogName),
	)
}

func readSealedRecords(path string) ([]sealedRecord, error) {
	file, err := os.Open(path) // #nosec G304 -- this process's own audit log.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var records []sealedRecord
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		var entry struct {
			Sequence   uint64 `json:"sequence"`
			Event      string `json:"event"`
			DeviceHash string `json:"device_hash"`
			RequestID  string `json:"request_id"`
			Detail     string `json:"detail"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse sealed carrier audit trail: %w", err)
		}
		record := sealedRecord{
			Sequence:   entry.Sequence,
			Event:      entry.Event,
			DeviceHash: entry.DeviceHash,
			RequestID:  entry.RequestID,
			Detail:     entry.Detail,
		}
		if strings.HasPrefix(entry.Detail, schemaToken+" ") {
			class, mode, session, reason, err := parseTerminalDetail(entry.Detail)
			if err != nil {
				return nil, fmt.Errorf(
					"sealed record %d: %w", entry.Sequence, err,
				)
			}
			record.Class, record.Mode = class, mode
			record.Session, record.Reason = session, reason
			record.Terminal = true
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// parseTerminalDetail decodes the fixed five-token carrier terminal encoding
// independently of internal/carrier, mirroring the offline verifier's own
// duplication: a parser that imported the producer could not catch the two
// drifting apart.
func parseTerminalDetail(detail string) (
	class, mode, session, reason string, err error,
) {
	fields := strings.Split(detail, " ")
	if len(fields) != 5 || fields[0] != schemaToken {
		return "", "", "", "", errors.New(
			"detail is not the versioned five-token carrier terminal form",
		)
	}
	values := make([]string, 4)
	for index, key := range []string{"class", "mode", "session", "reason"} {
		value, found := strings.CutPrefix(fields[index+1], key+"=")
		if !found || value == "" {
			return "", "", "", "", fmt.Errorf("detail lacks a %s token", key)
		}
		values[index] = value
	}
	return values[0], values[1], values[2], values[3], nil
}

// --- coverage -------------------------------------------------------------

type familyCoverage struct {
	Observed        familyExpectation `json:"observed"`
	Expected        familyExpectation `json:"expected"`
	Matches         bool              `json:"matches_expected"`
	AbortReasons    map[string]int    `json:"abort_reasons"`
	ReasonSetExact  bool              `json:"abort_reason_set_is_exactly_the_enum"`
	ReasonSetDetail string            `json:"abort_reason_set_detail"`
}

// injectorCoverage is one canonical injector's outcome. It is built from
// expectedInjectors, not from whatever happened to be registered, so a missing
// injector produces a present-and-failing entry rather than a silently absent
// one.
type injectorCoverage struct {
	Name              string `json:"name"`
	Registered        bool   `json:"registered"`
	FailEvent         string `json:"fail_event"`
	ExpectedFailEvent string `json:"expected_fail_event"`
	Refusals          int64  `json:"refusals"`
	ExpectedRefusals  int64  `json:"expected_refusals"`
	Fired             bool   `json:"fired"`
}

type assertion struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type coverageReport struct {
	Schema               string                    `json:"schema"`
	TerminalSchema       string                    `json:"terminal_schema"`
	DerivedFrom          string                    `json:"derived_from"`
	Note                 string                    `json:"note"`
	ClosedAbortReasons   []string                  `json:"closed_abort_reason_enum"`
	Families             map[string]familyCoverage `json:"families"`
	Correlations         int                       `json:"correlations"`
	Redemptions          int64                     `json:"redemptions"`
	CanonicalInjectors   []injectorPlan            `json:"canonical_fault_injectors"`
	FaultInjectors       []injectorCoverage        `json:"fault_injectors"`
	CanonicalAssertions  []string                  `json:"canonical_assertion_names"`
	Triggers             []*trigger                `json:"triggers"`
	Assertions           []assertion               `json:"assertions"`
	AllAssertionsPassed  bool                      `json:"all_assertions_passed"`
	SmokeBinarySHA256    string                    `json:"smoke_binary_sha256"`
	SmokeSourceDigest    string                    `json:"smoke_source_digest"`
	RunnerExpectedBinary string                    `json:"runner_expected_binary_sha256"`
	RunnerExpectedSource string                    `json:"runner_expected_source_digest"`
}

// buildCoverage recomputes every claim from the sealed trail. Nothing in the
// returned report is copied from the trigger loop's intentions except the
// declared how/where prose, which is labelled as declared and is never used in
// an assertion.
func (s *smoke) buildCoverage() (*coverageReport, error) {
	records, err := s.readRecords()
	if err != nil {
		return nil, err
	}
	report := &coverageReport{
		Schema:         coverageSchema,
		TerminalSchema: schemaToken,
		DerivedFrom:    auditLogName,
		Note: "Every count, reason, and correlation below is recomputed by " +
			"parsing the sealed carrier audit trail after the run, not " +
			"recorded by the code that drove it.",
		ClosedAbortReasons:   carrier.AbortReasons(),
		Families:             map[string]familyCoverage{},
		Redemptions:          s.redemptions.count(),
		CanonicalInjectors:   expectedInjectors,
		CanonicalAssertions:  canonicalAssertionNames,
		Triggers:             s.triggers,
		SmokeBinarySHA256:    s.binaryDigest,
		SmokeSourceDigest:    sourceDigest,
		RunnerExpectedBinary: s.expectedBinary,
		RunnerExpectedSource: s.expectedSource,
	}

	counts := map[string]*familyExpectation{
		"h3": {}, "h2": {},
	}
	reasons := map[string]map[string]int{
		"h3": {}, "h2": {},
	}
	correlations := map[string]int{}
	for _, record := range records {
		family := ""
		switch {
		case strings.HasPrefix(record.Event, "carrier_h3_"):
			family = "h3"
		case strings.HasPrefix(record.Event, "carrier_h2_"):
			family = "h2"
		default:
			// Same fail-closed rule as an unknown terminal class: a line
			// the classifier does not understand must not disappear from
			// the conservation proof. continue would let a renamed or
			// extra event keep every count-based assertion green.
			return nil, fmt.Errorf(
				"sealed record %d has unhandled event %q",
				record.Sequence, record.Event,
			)
		}
		correlations[record.RequestID]++
		switch record.Class {
		case "authenticated":
			counts[family].Authenticated++
		case "auth_only":
			counts[family].AuthOnly++
		case "open":
			counts[family].Open++
		case "closed":
			counts[family].Closed++
		case "aborted":
			counts[family].Aborted++
			reasons[family][record.Reason]++
		default:
			return nil, fmt.Errorf(
				"sealed record %d has unhandled class %q",
				record.Sequence, record.Class,
			)
		}
	}
	report.Correlations = len(correlations)

	enum := carrier.AbortReasons()
	for _, family := range []string{"h3", "h2"} {
		observed := *counts[family]
		expected := expectedFamilyTotals[family]
		exact, detail := reasonSetIsExactly(reasons[family], enum)
		report.Families[family] = familyCoverage{
			Observed:        observed,
			Expected:        expected,
			Matches:         observed == expected,
			AbortReasons:    reasons[family],
			ReasonSetExact:  exact,
			ReasonSetDetail: detail,
		}
	}

	// Driven from the canonical plan, so a canonical injector that was never
	// registered still gets an entry — and a failing one — instead of quietly
	// dropping its own proof out of the report.
	for _, plan := range expectedInjectors {
		entry := injectorCoverage{
			Name:              plan.Name,
			ExpectedFailEvent: plan.FailEvent,
			ExpectedRefusals:  plan.ExpectedRefusals,
		}
		for _, injector := range s.injectors {
			if injector.name != plan.Name {
				continue
			}
			entry.Registered = true
			entry.FailEvent = injector.failEvent
			entry.Refusals = injector.refusals.Load()
		}
		entry.Fired = entry.Registered &&
			entry.FailEvent == plan.FailEvent &&
			entry.Refusals == plan.ExpectedRefusals
		report.FaultInjectors = append(report.FaultInjectors, entry)
	}

	report.Assertions = s.assertions(report, records)
	report.AllAssertionsPassed = true
	for _, current := range report.Assertions {
		if !current.Passed {
			report.AllAssertionsPassed = false
		}
	}
	return report, nil
}

func (s *smoke) assertions(
	report *coverageReport,
	records []sealedRecord,
) []assertion {
	var results []assertion
	add := func(name string, passed bool, format string, args ...any) {
		results = append(results, assertion{
			Name: name, Passed: passed, Detail: fmt.Sprintf(format, args...),
		})
	}

	for _, family := range []string{"h3", "h2"} {
		coverage := report.Families[family]
		add(
			family+"_terminal_counts_exact",
			coverage.Matches,
			"observed %+v, expected %+v", coverage.Observed, coverage.Expected,
		)
		add(
			family+"_abort_reason_set_exact",
			coverage.ReasonSetExact,
			"%s", coverage.ReasonSetDetail,
		)
		add(
			family+"_conservation_identity",
			coverage.Observed.Authenticated ==
				coverage.Observed.AuthOnly+coverage.Observed.Open+
					coverage.Observed.Aborted,
			"authenticated=%d, auth_only+open+aborted=%d",
			coverage.Observed.Authenticated,
			coverage.Observed.AuthOnly+coverage.Observed.Open+
				coverage.Observed.Aborted,
		)
		add(
			family+"_open_equals_closed",
			coverage.Observed.Open == coverage.Observed.Closed,
			"open=%d, closed=%d",
			coverage.Observed.Open, coverage.Observed.Closed,
		)
	}

	// H2 has no auth_only class in the protocol at all. Asserted on the raw
	// event name rather than only on the count, so an event that existed but
	// was mis-parsed could not hide.
	h2AuthOnly := 0
	for _, record := range records {
		if record.Event == "carrier_h2_auth_only" {
			h2AuthOnly++
		}
	}
	add(
		"h2_has_no_auth_only_class",
		h2AuthOnly == 0,
		"carrier_h2_auth_only events=%d", h2AuthOnly,
	)

	// The trigger plan and the flat expectation table must agree, so neither
	// can be edited into agreement with a broken run on its own.
	planned := map[string]*familyExpectation{"h3": {}, "h2": {}}
	for _, entry := range s.triggers {
		for _, event := range entry.ExpectedEvents {
			switch event.Class {
			case "authenticated":
				planned[entry.Carrier].Authenticated++
			case "auth_only":
				planned[entry.Carrier].AuthOnly++
			case "open":
				planned[entry.Carrier].Open++
			case "closed":
				planned[entry.Carrier].Closed++
			case "aborted":
				planned[entry.Carrier].Aborted++
			}
		}
	}
	for _, family := range []string{"h3", "h2"} {
		add(
			family+"_plan_matches_expectation_table",
			*planned[family] == expectedFamilyTotals[family],
			"driven plan %+v, expectation table %+v",
			*planned[family], expectedFamilyTotals[family],
		)
	}

	reconciled := 0
	for _, entry := range s.triggers {
		if entry.Reconciled {
			reconciled++
		}
	}
	add(
		"every_trigger_reconciled_against_the_sealed_trail",
		reconciled == len(s.triggers) && len(s.triggers) == 13,
		"%d of %d triggers reconciled", reconciled, len(s.triggers),
	)

	distinct := map[string]bool{}
	for _, entry := range s.triggers {
		distinct[entry.Correlation] = true
	}
	add(
		"every_request_has_its_own_correlation_identity",
		len(distinct) == len(s.triggers),
		"%d distinct correlation identities across %d requests",
		len(distinct), len(s.triggers),
	)
	add(
		"sealed_correlations_match_driven_requests",
		report.Correlations == len(s.triggers),
		"%d correlations in the sealed trail, %d requests driven",
		report.Correlations, len(s.triggers),
	)

	total := report.Families["h3"].Observed.Authenticated +
		report.Families["h2"].Observed.Authenticated
	add(
		"redemptions_equal_authenticated",
		report.Redemptions == int64(total),
		"redemptions=%d, authenticated=%d", report.Redemptions, total,
	)

	// The registered injector list must be exactly the canonical plan: same
	// count, same order, same names, same fail events, exactly one refusal
	// each. A third injector, a missing one, or a misnamed one fails here
	// explicitly rather than merely omitting a "fired" assertion.
	schemaExact := len(s.injectors) == len(expectedInjectors)
	if schemaExact {
		for index, injector := range s.injectors {
			plan := expectedInjectors[index]
			if injector.name != plan.Name ||
				injector.failEvent != plan.FailEvent ||
				injector.refusals.Load() != plan.ExpectedRefusals {
				schemaExact = false
				break
			}
		}
	}
	add(
		"fault_injector_schema_exact",
		schemaExact,
		"registered [%s], canonical [%s]",
		describeInjectors(s.injectors), describeInjectorPlans(expectedInjectors),
	)

	for _, injector := range report.FaultInjectors {
		if !injector.Registered {
			add(
				"fault_injector_fired_"+injector.Name,
				false,
				"canonical injector %s was never registered by the run",
				injector.Name,
			)
			continue
		}
		add(
			"fault_injector_fired_"+injector.Name,
			injector.Fired,
			"%s refused %d records of %s, expected exactly %d of %s",
			injector.Name, injector.Refusals, injector.FailEvent,
			injector.ExpectedRefusals, injector.ExpectedFailEvent,
		)
	}

	// Finally, the assertion set itself. Everything above can be weakened by
	// deletion rather than by editing, and a deleted assertion is invisible to
	// any consumer that looks results up by name. Emitting the produced name
	// list — including this entry — and requiring it to equal the canonical
	// list exactly turns a deletion or a rename into a failure of this run.
	produced := make([]string, 0, len(results)+1)
	for _, current := range results {
		produced = append(produced, current.Name)
	}
	produced = append(produced, assertionSetName)
	add(
		assertionSetName,
		slices.Equal(produced, canonicalAssertionNames),
		"produced [%s], canonical [%s]",
		strings.Join(produced, " "),
		strings.Join(canonicalAssertionNames, " "),
	)
	return results
}

func describeInjectors(injectors []*oneShotFailingSink) string {
	described := make([]string, 0, len(injectors))
	for _, injector := range injectors {
		described = append(described, fmt.Sprintf(
			"%s:%s:%d",
			injector.name, injector.failEvent, injector.refusals.Load(),
		))
	}
	return strings.Join(described, " ")
}

func describeInjectorPlans(plans []injectorPlan) string {
	described := make([]string, 0, len(plans))
	for _, plan := range plans {
		described = append(described, fmt.Sprintf(
			"%s:%s:%d", plan.Name, plan.FailEvent, plan.ExpectedRefusals,
		))
	}
	return strings.Join(described, " ")
}

// reasonSetIsExactly reports whether observed contains every member of the
// closed enum exactly once and nothing else. "Five abort events" is not the
// same claim: a regression that emitted five copies of one reason would
// satisfy a count and fail here.
func reasonSetIsExactly(
	observed map[string]int,
	enum []string,
) (bool, string) {
	var problems []string
	for _, reason := range enum {
		switch observed[reason] {
		case 1:
		case 0:
			problems = append(problems, "missing "+reason)
		default:
			problems = append(problems, fmt.Sprintf(
				"%s recorded %d times", reason, observed[reason],
			))
		}
	}
	seen := make([]string, 0, len(observed))
	for reason := range observed {
		if !slices.Contains(enum, reason) {
			problems = append(problems, "unknown reason "+reason)
		}
		seen = append(seen, reason)
	}
	sort.Strings(seen)
	if len(problems) == 0 {
		return true, "exactly one of each: " + strings.Join(enum, ", ")
	}
	sort.Strings(problems)
	return false, "observed [" + strings.Join(seen, ", ") + "]: " +
		strings.Join(problems, "; ")
}

// --- sealing --------------------------------------------------------------

// seal closes the audit log, recomputes every claim from the sealed trail, and
// writes the evidence files. The manifest is sealed only if every recomputed
// assertion passed, so a failed run cannot be mistaken for evidence.
func (s *smoke) seal() error {
	if err := s.log.Close(); err != nil {
		return fmt.Errorf("close carrier audit log: %w", err)
	}
	coverage, err := s.buildCoverage()
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(coverage, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(
		filepath.Join(s.evidenceDirectory, coverageName),
		append(encoded, '\n'), 0o600,
	); err != nil {
		return err
	}
	fmt.Println()
	for _, current := range coverage.Assertions {
		status := "PASS"
		if !current.Passed {
			status = "FAIL"
		}
		fmt.Printf("%s %-52s %s\n", status, current.Name, current.Detail)
	}
	if !coverage.AllAssertionsPassed {
		return errors.New(
			"recomputed coverage assertions failed; the evidence manifest was " +
				"deliberately not sealed",
		)
	}

	h3 := coverage.Families["h3"].Observed
	h2 := coverage.Families["h2"].Observed

	// The DB-redemption side of the equation. This smoke has no PostgreSQL
	// behind it, so the count is the number of single-use privacy tokens the
	// carrier's redemption store actually consumed during this run, counted
	// independently of the audit trail by countingRedemptionStore. It is a
	// real count of real redemptions, and the recorded redemption mode in
	// environment.txt says exactly what produced it.
	if err := os.WriteFile(
		filepath.Join(s.evidenceDirectory, redemptionName),
		[]byte(fmt.Sprintf("%d\n", coverage.Redemptions)),
		0o600,
	); err != nil {
		return err
	}

	snapshot := fmt.Sprintf(
		"schema=%s\n"+
			"redemptions=%d\n"+
			"anonymous_authenticated=%d\n"+
			"h3_authenticated=%d\nh3_auth_only=%d\nh3_open=%d\n"+
			"h3_closed=%d\nh3_aborted=%d\n"+
			"h2_authenticated=%d\nh2_auth_only=%d\nh2_open=%d\n"+
			"h2_closed=%d\nh2_aborted=%d\n",
		schemaToken,
		coverage.Redemptions,
		h3.Authenticated+h2.Authenticated,
		h3.Authenticated, h3.AuthOnly, h3.Open, h3.Closed, h3.Aborted,
		h2.Authenticated, h2.AuthOnly, h2.Open, h2.Closed, h2.Aborted,
	)
	if err := os.WriteFile(
		filepath.Join(s.evidenceDirectory, conservationName),
		[]byte(snapshot), 0o600,
	); err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	// No fallback for an unstamped build: requireBinding refused to let one
	// reach this point at all, so the digest sealed here is always the real
	// ldflags stamp of a build script's output.
	environment := strings.Join([]string{
		"schema=winn-conservation-smoke/v1",
		"captured_at_utc=" + time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"hostname=" + hostname,
		"kernel=" + runtime.GOOS + "/" + runtime.GOARCH,
		"protocol_version=winn/3",
		"carrier_authorization_mode=" + carrierAuthMode,
		"carrier_transport=real-in-process-H3Server-and-H2Server",
		"tls_profile=TLS1.3 X25519+ML-KEM-768",
		"zero_rtt=false",
		"redemption=single-use-blind-token-in-process-lab-cache",
		"redemption_count_source=carrier-side-successful-redemptions-counted-by-the-smoke",
		"redemption_count_is_postgresql=false",
		"audit_key_location=work-directory-outside-this-evidence-directory",
		"smoke_binary_sha256=" + s.binaryDigest,
		"smoke_source_digest=" + sourceDigest,
		"smoke_runner_expected_binary_sha256=" + s.expectedBinary,
		"smoke_runner_expected_source_digest=" + s.expectedSource,
		"smoke_unroutable_backend=" + s.unroutableBackend,
		"abort_coverage=" + coverageName,
		"purpose=forced-abort-conservation-smoke-not-promotional-measurement",
	}, "\n") + "\n"
	if err := os.WriteFile(
		filepath.Join(s.evidenceDirectory, environmentName),
		[]byte(environment), 0o600,
	); err != nil {
		return err
	}

	if err := sealManifest(s.evidenceDirectory); err != nil {
		return err
	}
	fmt.Print("\n", snapshot)
	fmt.Println("EVIDENCE_DIR=" + s.evidenceDirectory)
	return nil
}

// sealManifest writes evidence-manifest.sha256 over every regular file except
// itself, in the exact "<sha256>  ./<relative>" shape the verifier accepts —
// the same rule scripts/aicore_auto_e2e.sh applies.
func sealManifest(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Name() == manifestName {
			continue
		}
		if strings.Contains(entry.Name(), "key") {
			return fmt.Errorf(
				"refusing to seal key-named file %s: the audit HMAC key must "+
					"never be sealed alongside the evidence it authenticates",
				entry.Name(),
			)
		}
		digest, err := sha256File(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		lines = append(lines, digest+"  ./"+entry.Name())
	}
	sort.Strings(lines)
	return os.WriteFile(
		filepath.Join(directory, manifestName),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	)
}

// --- helpers --------------------------------------------------------------

// countingRedemptionStore counts successful single-use token redemptions
// independently of the audit trail, so the DB side of the conservation
// equation is not derived from the very log it is meant to reconcile against.
type countingRedemptionStore struct {
	inner    privacytoken.RedemptionStore
	redeemed atomic.Int64
	mu       sync.Mutex
}

func (store *countingRedemptionStore) Redeem(
	ctx context.Context,
	tokenID string,
	expiresAt time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.inner.Redeem(ctx, tokenID, expiresAt); err != nil {
		return err
	}
	store.redeemed.Add(1)
	return nil
}

func (store *countingRedemptionStore) count() int64 {
	return store.redeemed.Load()
}

// oneShotFailingSink refuses exactly one Record() call for one event name and
// then delegates every call to the real log. The refused record is never
// written, so the sealed HMAC chain has no gap: the terminal event simply does
// not exist, which is precisely what the carrier's audit_unavailable abort
// path is there to account for.
//
// It counts its refusals so the run can prove the injection actually fired
// rather than assuming the code path it was attached to was reached.
type oneShotFailingSink struct {
	name      string
	inner     audit.Sink
	failEvent string
	fired     atomic.Bool
	refusals  atomic.Int64
}

func (sink *oneShotFailingSink) Record(
	event, deviceID, requestID, detail string,
) error {
	if event == sink.failEvent && sink.fired.CompareAndSwap(false, true) {
		sink.refusals.Add(1)
		return errors.New("injected transient carrier audit sink failure")
	}
	return sink.inner.Record(event, deviceID, requestID, detail)
}

func (sink *oneShotFailingSink) Healthy() bool { return sink.inner.Healthy() }

type oneCredentialSource struct {
	mu         sync.Mutex
	credential *carrier.AnonymousCredential
}

func (source *oneCredentialSource) NextAnonymousCredential() (
	carrier.AnonymousCredential,
	error,
) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.credential == nil {
		return carrier.AnonymousCredential{}, errors.New(
			"anonymous credential already consumed",
		)
	}
	credential := *source.credential
	source.credential = nil
	return credential, nil
}

// newAnonymousCredential issues one real blind-signed privacy token through
// the full BeginIssue/BlindSign/Finalize exchange and binds it to its
// committed ephemeral ML-DSA key.
func (s *smoke) newAnonymousCredential() (
	*carrier.AnonymousCredential,
	error,
) {
	request, state, err := privacytoken.BeginIssue(
		&s.issuer.PublicKey, pqauth.MLDSA65,
	)
	if err != nil {
		return nil, err
	}
	response, err := privacytoken.BlindSign(request, s.issuer)
	if err != nil {
		return nil, err
	}
	bundle, err := state.Finalize(response)
	if err != nil {
		return nil, err
	}
	verified, err := privacytoken.Verify(
		bundle.PublicToken(), &s.issuer.PublicKey, s.issuerKeyID,
	)
	if err != nil {
		return nil, err
	}
	signer, err := bundle.Signer()
	if err != nil {
		return nil, err
	}
	return &carrier.AnonymousCredential{
		Pseudonym: verified.Pseudonym,
		Signer:    signer,
		Token:     bundle.PublicToken(),
	}, nil
}

func echoRoundTrip(connection net.PacketConn) error {
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	payload := []byte("conservation-smoke-datagram")
	written, err := connection.WriteTo(payload, nil)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return fmt.Errorf("wrote %d bytes, want %d", written, len(payload))
	}
	buffer := make([]byte, carrier.DefaultMaxDatagram)
	read, _, err := connection.ReadFrom(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:read]) != string(payload) {
		return fmt.Errorf("echo %q, want %q", buffer[:read], payload)
	}
	return nil
}

func startUDPEcho() (string, func(), error) {
	connection, err := net.ListenUDP(
		"udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		return "", nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, carrier.AbsoluteMaxDatagram+1)
		for {
			count, peer, readErr := connection.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = connection.WriteToUDP(buffer[:count], peer)
		}
	}()
	return connection.LocalAddr().String(), func() {
		_ = connection.Close()
		<-done
	}, nil
}

func randomSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func sha256File(path string) (string, error) {
	// #nosec G304 -- path is either this process's own executable or a file it
	// just created inside the directory it was told to populate.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
