package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/measurement"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/producersnapshot"
)

const anchorSlotTimestamp = "2026-07-25T00:00:00Z"

// anchorSlotFixture builds a disposable, fully valid committed anchor slot in
// a temporary directory so that every tamper case below mutates a throwaway
// copy and never a sealed evidence root.
type anchorSlotFixture struct {
	directory   string
	request     phase1anchor.Request
	trust       anchorTrust
	privateOne  ed25519.PrivateKey
	privateTwo  ed25519.PrivateKey
	publicOne   ed25519.PublicKey
	publicTwo   ed25519.PublicKey
	previousOne string
	previousTwo string
	// profile selects which artifact set the slot must contain. Empty means
	// the legacy producer-anchored layout, which is what these fixtures build.
	profile anchorSlotProfile
}

func anchorSlotRequest(kind string, ordinal int) phase1anchor.Request {
	request := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		Kind:               kind,
		MatrixID:           "matrix-one",
		SourceDigest:       strings.Repeat("1", sha256.Size*2),
		AutoArtifactDigest: strings.Repeat("2", sha256.Size*2),
		ProfileDigest:      strings.Repeat("3", sha256.Size*2),
		ScheduleDigest:     strings.Repeat("4", sha256.Size*2),
		ExpectedBatchCount: 2,
		Ordinal:            ordinal,
	}
	switch kind {
	case phase1anchor.KindBatch:
		request.BatchKey = "edge--warm--b001"
		request.ScheduleRowDigest = strings.Repeat("5", sha256.Size*2)
		request.Profile = "edge"
		request.Readiness = "warm"
		request.AttemptCount = 100
		request.ArchiveDigest = strings.Repeat("6", sha256.Size*2)
		request.EvidenceManifestDigest = strings.Repeat("7", sha256.Size*2)
		request.AttemptLogDigest = strings.Repeat("8", sha256.Size*2)
		request.AttemptAnchorDigest = strings.Repeat("9", sha256.Size*2)
	case phase1anchor.KindSeal:
		request.AggregateDigest = strings.Repeat("a", sha256.Size*2)
	}
	return request
}

func newAnchorSlotFixture(
	t *testing.T,
	kind string,
	ordinal int,
	previousOne string,
	previousTwo string,
) *anchorSlotFixture {
	t.Helper()
	return newAnchorSlotFixtureIn(
		t,
		t.TempDir(),
		anchorSlotRequest(kind, ordinal),
		previousOne,
		previousTwo,
		anchorSlotLegacyV2,
	)
}

// newAnchorSlotFixtureIn seals one slot into a caller-chosen directory for a
// caller-chosen request, so the same builder produces both the standalone slots
// the tamper table uses and the committed slots of a whole matrix root.
func newAnchorSlotFixtureIn(
	t *testing.T,
	directory string,
	request phase1anchor.Request,
	previousOne string,
	previousTwo string,
	profile anchorSlotProfile,
) *anchorSlotFixture {
	t.Helper()
	fixture := &anchorSlotFixture{
		directory: directory,
		request:   request,
		profile:   profile,
		trust: anchorTrust{
			providerOneID: "provider-one",
			providerTwoID: "provider-two",
		},
		privateOne: ed25519.NewKeyFromSeed(
			[]byte("0123456789abcdef0123456789abcdef"),
		),
		privateTwo: ed25519.NewKeyFromSeed(
			[]byte("fedcba9876543210fedcba9876543210"),
		),
		previousOne: previousOne,
		previousTwo: previousTwo,
	}
	fixture.publicOne = fixture.privateOne.Public().(ed25519.PublicKey)
	fixture.publicTwo = fixture.privateTwo.Public().(ed25519.PublicKey)
	fixture.writeConfiguration(t, phase1anchor.SlotConfig{
		Schema:           "winn-phase1-anchor-pending-config/v1",
		KnownHostsDigest: fixtureKnownHostsDigest,
		ProviderOneID:    fixture.trust.providerOneID,
		ProviderOneHost:  "203.0.113.10",
		ProviderOneKeyID: phase1anchor.PublicKeyID(fixture.publicOne),
		ProviderOnePrior: previousOne,
		ProviderTwoID:    fixture.trust.providerTwoID,
		ProviderTwoHost:  "203.0.113.20",
		ProviderTwoKeyID: phase1anchor.PublicKeyID(fixture.publicTwo),
		ProviderTwoPrior: previousTwo,
	})
	canonical, err := fixture.request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	fixture.write(t, "request.json", append(canonical, '\n'))
	requestDigest, err := fixture.request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.write(t, "request.json.sha256", []byte(requestDigest+"\n"))
	fixture.writeReceipt(
		t, "provider-one.receipt.json",
		fixture.signReceipt(
			t, fixture.trust.providerOneID, previousOne, fixture.privateOne,
		),
	)
	fixture.writeReceipt(
		t, "provider-two.receipt.json",
		fixture.signReceipt(
			t, fixture.trust.providerTwoID, previousTwo, fixture.privateTwo,
		),
	)
	// batch-meta.env belongs to the legacy producer-anchored layout only. The
	// controller path's pin tool never wrote it, so a v3 fixture that did would
	// be testing a slot no tool produces.
	if fixture.profile != anchorSlotControllerV3 &&
		fixture.request.Kind == phase1anchor.KindBatch {
		fixture.write(t, "batch-meta.env", []byte("anchor_mode=dual-provider-v1\n"))
	}
	return fixture
}

// receiptDigests returns the two provider receipt digests this slot publishes,
// which are the predecessor values the next slot in the chain has to be sealed
// against.
func (fixture *anchorSlotFixture) receiptDigests(
	t *testing.T,
) (string, string) {
	t.Helper()
	one, err := fixture.readReceipt(t, "provider-one.receipt.json").Digest()
	if err != nil {
		t.Fatal(err)
	}
	two, err := fixture.readReceipt(t, "provider-two.receipt.json").Digest()
	if err != nil {
		t.Fatal(err)
	}
	return one, two
}

func (fixture *anchorSlotFixture) signReceipt(
	t *testing.T,
	providerID string,
	previous string,
	private ed25519.PrivateKey,
) phase1anchor.Receipt {
	t.Helper()
	receipt, err := phase1anchor.NewReceipt(
		fixture.request, providerID, previous,
		anchorSlotTimestamp, private,
	)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func (fixture *anchorSlotFixture) write(
	t *testing.T,
	name string,
	content []byte,
) {
	t.Helper()
	// #nosec G703 -- name is a fixed slot filename and the directory is a
	// disposable per-test temporary slot.
	if err := os.WriteFile(
		filepath.Join(fixture.directory, name), content, 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func (fixture *anchorSlotFixture) writeConfiguration(
	t *testing.T,
	configuration phase1anchor.SlotConfig,
) {
	t.Helper()
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	fixture.write(t, "provider-config.json", append(encoded, '\n'))
}

// writeReceipt stores the receipt together with the sidecar digest the
// verifier cross-checks, so a tamper case has to defeat both.
func (fixture *anchorSlotFixture) writeReceipt(
	t *testing.T,
	name string,
	receipt phase1anchor.Receipt,
) {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	fixture.write(t, name, append(encoded, '\n'))
	digest, err := receipt.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.write(t, name+".sha256", []byte(digest+"\n"))
}

func (fixture *anchorSlotFixture) readReceipt(
	t *testing.T,
	name string,
) phase1anchor.Receipt {
	t.Helper()
	// #nosec G304 -- the slot is a disposable per-test temporary directory.
	data, err := os.ReadFile(filepath.Join(fixture.directory, name))
	if err != nil {
		t.Fatal(err)
	}
	var receipt phase1anchor.Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

// verifyAnchorSlotAtPath adapts a pathname to the confined-parent contract the
// production caller uses.
//
// verifyAnchorSlot no longer accepts a pathname at all: verifyAnchorChain holds
// an open handle on anchors/committed and reaches each slot by NAME through it,
// so that a symbolic link at anchors, pending or committed cannot place the
// slots outside the audited root. Tests that build one throwaway slot open its
// parent the same way rather than reintroducing an ambient path into the
// production signature.
func verifyAnchorSlotAtPath(
	directory string,
	expected phase1anchor.Request,
	trust anchorTrust,
	publicOne ed25519.PublicKey,
	publicTwo ed25519.PublicKey,
	previousOne string,
	previousTwo string,
	profile anchorSlotProfile,
	knownHostsDigest string,
) (string, string, string, error) {
	parent, err := os.OpenRoot(filepath.Dir(directory))
	if err != nil {
		return "", "", "", err
	}
	defer parent.Close()
	return verifyAnchorSlot(
		parent,
		filepath.Base(directory),
		expected,
		trust,
		publicOne,
		publicTwo,
		previousOne,
		previousTwo,
		profile,
		knownHostsDigest,
	)
}

func (fixture *anchorSlotFixture) verify() (string, string, string, error) {
	profile := fixture.profile
	if profile == "" {
		profile = anchorSlotLegacyV2
	}
	return verifyAnchorSlotAtPath(
		fixture.directory,
		fixture.request,
		fixture.trust,
		fixture.publicOne,
		fixture.publicTwo,
		fixture.previousOne,
		fixture.previousTwo,
		profile,
		// The authenticated known-hosts digest the surrounding chain check
		// binds. The fixture writes this same value into every slot config, so
		// a case that rewrites it is testing the binding rather than a typo.
		fixtureKnownHostsDigest,
	)
}

// fixtureKnownHosts is the frozen anchor known-hosts file every fixture in this
// package uses, and fixtureKnownHostsDigest is its actual digest.
//
// Derived rather than written by hand, because the verifier now requires each
// slot configuration's claimed digest to equal the authenticated one. A
// placeholder digest beside a real known_hosts file is an internally
// inconsistent fixture — the earlier shape-only check tolerated it, and the
// binding does not.
var fixtureKnownHosts = []byte("203.0.113.10 ssh-ed25519 AAAA\n")

var fixtureKnownHostsDigest = func() string {
	sum := sha256.Sum256(fixtureKnownHosts)
	return hex.EncodeToString(sum[:])
}()

// slotPredecessor is a canonical mid-chain predecessor digest, used wherever a
// fixture sits at a non-genesis ordinal.
const slotPredecessor = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
	"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

func TestVerifyAnchorSlotAcceptsAnIntactDualProviderSlot(t *testing.T) {
	for _, kind := range []string{
		phase1anchor.KindGenesis,
		phase1anchor.KindBatch,
		phase1anchor.KindSeal,
	} {
		t.Run(kind, func(t *testing.T) {
			ordinal := map[string]int{
				phase1anchor.KindGenesis: 0,
				phase1anchor.KindBatch:   1,
				phase1anchor.KindSeal:    3,
			}[kind]
			// The predecessor a slot at this position is permitted to carry:
			// the zero digest belongs to genesis and nowhere else.
			previous := anchorZeroDigest
			if ordinal > 0 {
				previous = slotPredecessor
			}
			fixture := newAnchorSlotFixture(
				t, kind, ordinal, previous, previous,
			)
			one, two, requestDigest, err := fixture.verify()
			if err != nil {
				t.Fatal(err)
			}
			if !lowerHex(one, sha256.Size*2) ||
				!lowerHex(two, sha256.Size*2) ||
				!lowerHex(requestDigest, sha256.Size*2) ||
				one == two {
				t.Fatalf(
					"slot digests one=%q two=%q request=%q",
					one, two, requestDigest,
				)
			}
		})
	}
}

func TestVerifyAnchorSlotRejectsAlteredReceiptsAndSignatures(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(*testing.T, *anchorSlotFixture)
		want   string
	}{
		{
			// received_at_utc is the one receipt field no metadata check
			// pins, so this case exercises the Ed25519 verification itself.
			name: "receipt_timestamp_forged",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				receipt := f.readReceipt(t, "provider-one.receipt.json")
				receipt.ReceivedAtUTC = "2026-07-25T00:00:05Z"
				f.writeReceipt(t, "provider-one.receipt.json", receipt)
			},
			want: "signature verification failed",
		},
		{
			name: "receipt_signature_byte_flipped",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				receipt := f.readReceipt(t, "provider-one.receipt.json")
				raw, err := base64.StdEncoding.DecodeString(receipt.Signature)
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 0x01
				receipt.Signature = base64.StdEncoding.EncodeToString(raw)
				f.writeReceipt(t, "provider-one.receipt.json", receipt)
			},
			want: "signature verification failed",
		},
		{
			name: "receipt_resigned_by_the_other_provider",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.writeReceipt(
					t,
					"provider-one.receipt.json",
					f.signReceipt(
						t,
						f.trust.providerOneID,
						f.previousOne,
						f.privateTwo,
					),
				)
			},
			want: "metadata does not match",
		},
		{
			name: "provider_receipts_swapped_between_slots",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				one := f.readReceipt(t, "provider-one.receipt.json")
				two := f.readReceipt(t, "provider-two.receipt.json")
				f.writeReceipt(t, "provider-one.receipt.json", two)
				f.writeReceipt(t, "provider-two.receipt.json", one)
			},
			want: "metadata does not match",
		},
		{
			name: "receipt_replayed_from_a_later_ordinal",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				later := *f
				later.request = anchorSlotRequest(phase1anchor.KindBatch, 2)
				later.request.BatchKey = "edge--cold--b001"
				later.request.Readiness = "cold"
				f.writeReceipt(
					t,
					"provider-one.receipt.json",
					later.signReceipt(
						t,
						f.trust.providerOneID,
						f.previousOne,
						f.privateOne,
					),
				)
			},
			want: "metadata does not match",
		},
		{
			name: "receipt_previous_link_broken",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.writeReceipt(
					t,
					"provider-one.receipt.json",
					f.signReceipt(
						t,
						f.trust.providerOneID,
						strings.Repeat("c", sha256.Size*2),
						f.privateOne,
					),
				)
			},
			want: "metadata does not match",
		},
		{
			name: "receipt_unknown_field_injected",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				path := filepath.Join(
					f.directory, "provider-one.receipt.json",
				)
				// #nosec G304 -- disposable per-test temporary slot.
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				injected := strings.Replace(
					string(data),
					`{"schema":`,
					`{"anchor_override":"trusted","schema":`,
					1,
				)
				if injected == string(data) {
					t.Fatal("injection fixture did not apply")
				}
				f.write(t, "provider-one.receipt.json", []byte(injected))
			},
			want: "unknown field",
		},
		{
			name: "receipt_file_truncated",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				path := filepath.Join(
					f.directory, "provider-two.receipt.json",
				)
				// #nosec G304 -- disposable per-test temporary slot.
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				f.write(
					t, "provider-two.receipt.json", data[:len(data)/2],
				)
			},
			want: "unexpected EOF",
		},
		{
			name: "receipt_file_extended_with_a_second_receipt",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				path := filepath.Join(
					f.directory, "provider-two.receipt.json",
				)
				// #nosec G304 -- disposable per-test temporary slot.
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				f.write(
					t, "provider-two.receipt.json", append(data, data...),
				)
			},
			want: "trailing JSON value",
		},
		{
			name: "receipt_sidecar_digest_rewritten",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.write(
					t,
					"provider-one.receipt.json.sha256",
					[]byte(strings.Repeat("d", sha256.Size*2)+"\n"),
				)
			},
			want: "first provider receipt digest mismatch",
		},
		{
			name: "request_payload_byte_flipped",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				altered := f.request
				altered.SourceDigest = strings.Repeat("e", sha256.Size*2)
				canonical, err := altered.Canonical()
				if err != nil {
					t.Fatal(err)
				}
				f.write(t, "request.json", append(canonical, '\n'))
			},
			want: "differs from expected evidence",
		},
		{
			name: "request_sidecar_digest_rewritten",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.write(
					t,
					"request.json.sha256",
					[]byte(strings.Repeat("f", sha256.Size*2)+"\n"),
				)
			},
			want: "stored anchor request digest mismatch",
		},
		{
			name: "request_unknown_field_injected",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				canonical, err := f.request.Canonical()
				if err != nil {
					t.Fatal(err)
				}
				injected := strings.Replace(
					string(canonical),
					`{"schema":`,
					`{"expected_batch_count_override":9,"schema":`,
					1,
				)
				if injected == string(canonical) {
					t.Fatal("injection fixture did not apply")
				}
				f.write(t, "request.json", []byte(injected))
			},
			want: "unknown field",
		},
		{
			name: "provider_config_priors_rewritten",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.writeConfiguration(t, phase1anchor.SlotConfig{
					Schema:           "winn-phase1-anchor-pending-config/v1",
					KnownHostsDigest: fixtureKnownHostsDigest,
					ProviderOneID:    f.trust.providerOneID,
					ProviderOneHost:  "203.0.113.10",
					ProviderOneKeyID: phase1anchor.PublicKeyID(f.publicOne),
					ProviderOnePrior: strings.Repeat("9", sha256.Size*2),
					ProviderTwoID:    f.trust.providerTwoID,
					ProviderTwoHost:  "203.0.113.20",
					ProviderTwoKeyID: phase1anchor.PublicKeyID(f.publicTwo),
					ProviderTwoPrior: f.previousTwo,
				})
			},
			want: "different predecessor receipts",
		},
		{
			name: "provider_config_identities_swapped",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.writeConfiguration(t, phase1anchor.SlotConfig{
					Schema:           "winn-phase1-anchor-pending-config/v1",
					KnownHostsDigest: fixtureKnownHostsDigest,
					ProviderOneID:    f.trust.providerTwoID,
					ProviderOneHost:  "203.0.113.20",
					ProviderOneKeyID: phase1anchor.PublicKeyID(f.publicTwo),
					ProviderOnePrior: f.previousOne,
					ProviderTwoID:    f.trust.providerOneID,
					ProviderTwoHost:  "203.0.113.10",
					ProviderTwoKeyID: phase1anchor.PublicKeyID(f.publicOne),
					ProviderTwoPrior: f.previousTwo,
				})
			},
			want: "different provider pair",
		},
		{
			name: "provider_config_collapses_both_hosts",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.writeConfiguration(t, phase1anchor.SlotConfig{
					Schema:           "winn-phase1-anchor-pending-config/v1",
					KnownHostsDigest: fixtureKnownHostsDigest,
					ProviderOneID:    f.trust.providerOneID,
					ProviderOneHost:  "203.0.113.10",
					ProviderOneKeyID: phase1anchor.PublicKeyID(f.publicOne),
					ProviderOnePrior: f.previousOne,
					ProviderTwoID:    f.trust.providerTwoID,
					ProviderTwoHost:  "203.0.113.10",
					ProviderTwoKeyID: phase1anchor.PublicKeyID(f.publicTwo),
					ProviderTwoPrior: f.previousTwo,
				})
			},
			want: "contacted at the same host",
		},
		{
			name: "provider_config_unknown_field_injected",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.write(t, "provider-config.json", []byte(
					`{"schema":"winn-phase1-anchor-pending-config/v1",`+
						`"anchor_override":true}`+"\n",
				))
			},
			want: "unknown field",
		},
		{
			name: "slot_gains_an_extra_file",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				f.write(t, "provider-three.receipt.json", []byte("{}\n"))
			},
			want: "requires exactly",
		},
		{
			name: "slot_loses_a_receipt",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				if err := os.Remove(filepath.Join(
					f.directory, "provider-two.receipt.json",
				)); err != nil {
					t.Fatal(err)
				}
			},
			want: "requires exactly",
		},
		{
			name: "slot_renames_a_receipt",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				if err := os.Rename(
					filepath.Join(
						f.directory, "provider-two.receipt.json",
					),
					filepath.Join(f.directory, "provider-2.receipt.json"),
				); err != nil {
					t.Fatal(err)
				}
			},
			want: "is not part of the",
		},
		{
			name: "slot_hides_a_receipt_inside_a_directory",
			tamper: func(t *testing.T, f *anchorSlotFixture) {
				path := filepath.Join(
					f.directory, "provider-two.receipt.json",
				)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			// The refusal is now specific about WHY: the member is present
			// under an expected name but is not a regular file. The previous
			// wording came from the exact-set check treating a directory as an
			// unexpected entry, which said less about what was wrong.
			want: "is not a regular file",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAnchorSlotFixture(
				t,
				phase1anchor.KindBatch,
				1,
				strings.Repeat("7", sha256.Size*2),
				strings.Repeat("8", sha256.Size*2),
			)
			if _, _, _, err := fixture.verify(); err != nil {
				t.Fatalf("the untampered fixture failed: %v", err)
			}
			test.tamper(t, fixture)
			_, _, _, err := fixture.verify()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"tampered anchor slot error = %v, want %q",
					err, test.want,
				)
			}
		})
	}
}

func TestVerifyAnchorSlotRejectsABrokenChainLink(t *testing.T) {
	fixture := newAnchorSlotFixture(
		t,
		phase1anchor.KindBatch,
		1,
		strings.Repeat("7", sha256.Size*2),
		strings.Repeat("8", sha256.Size*2),
	)
	if _, _, _, err := fixture.verify(); err != nil {
		t.Fatal(err)
	}
	// The caller threads the previous slot's receipt digests in. Presenting
	// this slot under any other predecessor must fail, in both provider
	// chains independently.
	fixture.previousOne = strings.Repeat("0", sha256.Size*2)
	if _, _, _, err := fixture.verify(); err == nil {
		t.Fatal("the first provider chain accepted a foreign predecessor")
	}
	fixture.previousOne = strings.Repeat("7", sha256.Size*2)
	fixture.previousTwo = strings.Repeat("0", sha256.Size*2)
	if _, _, _, err := fixture.verify(); err == nil {
		t.Fatal("the second provider chain accepted a foreign predecessor")
	}
}

// fixtureFinalizerKeyID is the audit finalizer identity these fixtures pin. It
// is supplied externally, exactly as an auditor supplies it on the command
// line, never read back out of the artifacts being verified.
const fixtureFinalizerKeyID = "9999999999999999999999999999999999999999" +
	"999999999999999999999999"

func TestVerifyDualProviderAnchorsRequiresIndependentTrustRoots(t *testing.T) {
	environment := map[string]string{
		"schema":               matrixSchemaV3,
		"partial":              "0",
		"anchor_mode":          deferredAnchorMode,
		"intended_anchor_mode": anchorModeDualProvider,
		"anchor_schema":        phase1anchor.RequestSchema,
	}
	complete := map[string]string{"anchor_mode": anchorModeDualProvider}
	private := ed25519.NewKeyFromSeed(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	public := private.Public().(ed25519.PublicKey)
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "shared.ed25519.pub")
	if err := os.WriteFile(
		keyPath,
		[]byte(base64.StdEncoding.EncodeToString(public)+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		trust anchorTrust
		want  string
	}{
		{
			"missing_second_trust_root",
			anchorTrust{
				providerOneID:        "provider-one",
				providerOnePublicKey: keyPath,
			},
			"independent external anchor trust roots",
		},
		{
			"one_provider_wearing_two_hats",
			anchorTrust{
				providerOneID:        "provider-one",
				providerOnePublicKey: keyPath,
				providerTwoID:        "provider-one",
				providerTwoPublicKey: keyPath,
			},
			"independent external anchor trust roots",
		},
		{
			"two_identities_sharing_one_signing_key",
			anchorTrust{
				providerOneID:        "provider-one",
				providerOnePublicKey: keyPath,
				providerTwoID:        "provider-two",
				providerTwoPublicKey: keyPath,
			},
			"same signing key",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyDualProviderAnchors(
				directory,
				profileDocument{},
				environment,
				complete,
				nil,
				false,
				test.trust,
				false,
				auditCheckpointPin{finalizerKeyID: fixtureFinalizerKeyID},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("trust-root error = %v, want %q", err, test.want)
			}
		})
	}
}

// matrixRootFixture seals a complete, minimal, dual-provider-anchored matrix
// root: one profile, one readiness class, one 100-attempt batch, genesis slot,
// batch slot, terminal seal, terminal aggregate. It exists so a whole sealed
// root can be copied byte for byte to an unrelated location and re-verified
// there, which is the property an auditor handed a copy depends on.
//
// It reuses newAnchorSlotFixtureIn for all three committed slots, so the slots
// inside it are sealed by exactly the code the standalone tamper table above
// exercises.
type matrixRootFixture struct {
	root        string
	matrixID    string
	batchKey    string
	profileID   string
	readiness   string
	archiveName string
	relative    bool
	trust       anchorTrust
	profiles    profileDocument
	// finalizerKeyID is the identity of the real ML-DSA key this fixture signs
	// CONTROLLER_START with, and the value an auditor pins.
	finalizerKeyID string
}

func fixtureDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// newMatrixRootFixture seals a root under a fresh temporary directory. With
// relative set the root is sealed as schema v3 and records its archive path
// relative to the matrix root; otherwise it is sealed as legacy v2, which
// records only the absolute path of this machine and forces the verifier to
// derive the archive name from authenticated identity.
func newMatrixRootFixture(t *testing.T, relative bool) *matrixRootFixture {
	t.Helper()
	fixture := &matrixRootFixture{
		root:      t.TempDir(),
		matrixID:  "phase1-relocation-v1",
		batchKey:  "edge--warm--b001",
		profileID: "edge",
		readiness: string(measurement.ReadinessWarm),
		relative:  relative,
	}
	fixture.archiveName = "auto-e2e-" + fixture.matrixID + "-" +
		fixture.batchKey + ".tar.gz"
	for _, directory := range []string{
		"evidence",
		"batches",
		"exclusions",
		filepath.Join("anchors", "pending"),
		filepath.Join("anchors", "committed"),
		filepath.Join(
			"evidence", strings.TrimSuffix(fixture.archiveName, ".tar.gz"),
		),
	} {
		if err := os.MkdirAll(
			filepath.Join(fixture.root, directory), 0o700,
		); err != nil {
			t.Fatal(err)
		}
	}

	archiveBody := []byte("sealed archive of " + fixture.batchKey + "\n")
	writeFixtureFile(
		t,
		filepath.Join(fixture.root, "evidence", fixture.archiveName),
		archiveBody,
	)
	evidenceDirectory := filepath.Join(
		fixture.root,
		"evidence",
		strings.TrimSuffix(fixture.archiveName, ".tar.gz"),
	)
	// The manifest records the REAL digests of the members it lists, and lists
	// exactly them. A placeholder digest here would make the fixture an example
	// of the internally inconsistent manifest the producer snapshot refuses —
	// it would be testing that a broken root is rejected, not that a sound one
	// verifies.
	attemptsBody := []byte("{\"attempt_id\":\"a-0001\"}\n")
	attemptsAnchorBody := []byte("anchored\n")
	attemptsSum := sha256.Sum256(attemptsBody)
	attemptsAnchorSum := sha256.Sum256(attemptsAnchorBody)
	manifestBody := []byte(
		hex.EncodeToString(attemptsSum[:]) + "  ./attempts.jsonl\n" +
			hex.EncodeToString(attemptsAnchorSum[:]) +
			"  ./attempts.jsonl.anchor\n",
	)
	evidenceFiles := map[string][]byte{
		"evidence-manifest.sha256": manifestBody,
		"attempts.jsonl":           attemptsBody,
		"attempts.jsonl.anchor":    attemptsAnchorBody,
	}
	evidenceDigests := make(map[string]string, len(evidenceFiles))
	for name, content := range evidenceFiles {
		writeFixtureFile(t, filepath.Join(evidenceDirectory, name), content)
		sum := sha256.Sum256(content)
		evidenceDigests[name] = hex.EncodeToString(sum[:])
	}
	archiveSum := sha256.Sum256(archiveBody)
	archiveDigest := hex.EncodeToString(archiveSum[:])

	privateOne := ed25519.NewKeyFromSeed(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	privateTwo := ed25519.NewKeyFromSeed(
		[]byte("fedcba9876543210fedcba9876543210"),
	)
	publicOne := privateOne.Public().(ed25519.PublicKey)
	publicTwo := privateTwo.Public().(ed25519.PublicKey)
	// The trust roots are the auditor's own copies and deliberately live
	// outside the matrix root, so relocating or destroying the root never
	// disturbs them.
	trustDirectory := t.TempDir()
	fixture.trust = anchorTrust{
		providerOneID: "provider-one",
		providerOnePublicKey: filepath.Join(
			trustDirectory, "provider-one.ed25519.pub",
		),
		providerTwoID: "provider-two",
		providerTwoPublicKey: filepath.Join(
			trustDirectory, "provider-two.ed25519.pub",
		),
	}
	for _, key := range []struct {
		name   string
		public ed25519.PublicKey
	}{
		{"provider-one.ed25519.pub", publicOne},
		{"provider-two.ed25519.pub", publicTwo},
	} {
		encoded := []byte(base64.StdEncoding.EncodeToString(key.public) + "\n")
		writeFixtureFile(t, filepath.Join(trustDirectory, key.name), encoded)
		writeFixtureFile(
			t, filepath.Join(fixture.root, "anchors", key.name), encoded,
		)
	}
	knownHosts := fixtureKnownHosts
	writeFixtureFile(
		t, filepath.Join(fixture.root, "anchors", "known_hosts"), knownHosts,
	)
	knownHostsSum := sha256.Sum256(knownHosts)

	scheduleSeed := fixtureDigest("schedule-seed")
	orderDigest := fixtureDigest(fmt.Sprintf(
		"%s:%d:%s:%s", scheduleSeed, 1, fixture.profileID, fixture.readiness,
	))
	row := fmt.Sprintf(
		"%06d\t%s\t%s\t%s\t%s\t%d\n",
		1, orderDigest, fixture.batchKey, fixture.profileID,
		fixture.readiness, 100,
	)
	writeFixtureFile(t, filepath.Join(fixture.root, "schedule.tsv"), []byte(row))
	scheduleSum := sha256.Sum256([]byte(row))
	rowSum := sha256.Sum256([]byte(row))

	fixture.profiles = profileDocument{
		Schema:                         profileSchemaV2,
		ProtocolVersion:                connectivity.Version,
		AttemptsPerReadinessPerProfile: 100,
		BatchSize:                      100,
		ScheduleSeed:                   scheduleSeed,
		ReadinessClasses:               []string{fixture.readiness},
		Profiles:                       []networkProfile{{ID: fixture.profileID}},
	}

	identity := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		MatrixID:           fixture.matrixID,
		SourceDigest:       fixtureDigest("source"),
		AutoArtifactDigest: fixtureDigest("artifact"),
		ProfileDigest:      fixtureDigest("profiles"),
		ScheduleDigest:     hex.EncodeToString(scheduleSum[:]),
		ExpectedBatchCount: 1,
	}
	committed := filepath.Join(fixture.root, "anchors", "committed")
	genesis := identity
	genesis.Kind = phase1anchor.KindGenesis
	genesis.Ordinal = 0
	// The two lineages, built exactly as their own tools build them. A v2 root
	// is producer-anchored (legacy 8-file batch slots, anchor identities in
	// matrix.env); a v3 root is controller-anchored (7-file slots, identities
	// in controller.env). The schema and the mode move together, which is what
	// the verifier now requires as a pair.
	slotProfile := anchorSlotLegacyV2
	anchorMode := anchorModeDualProvider
	if relative {
		slotProfile = anchorSlotControllerV3
		anchorMode = deferredAnchorMode
	}
	genesisSlot := newAnchorSlotFixtureIn(
		t,
		makeFixtureDirectory(t, filepath.Join(committed, "000000-genesis")),
		genesis,
		anchorZeroDigest,
		anchorZeroDigest,
		slotProfile,
	)
	previousOne, previousTwo := genesisSlot.receiptDigests(t)

	batch := identity
	batch.Kind = phase1anchor.KindBatch
	batch.Ordinal = 1
	batch.BatchKey = fixture.batchKey
	batch.ScheduleRowDigest = hex.EncodeToString(rowSum[:])
	batch.Profile = fixture.profileID
	batch.Readiness = fixture.readiness
	batch.AttemptCount = 100
	batch.ArchiveDigest = archiveDigest
	batch.EvidenceManifestDigest = evidenceDigests["evidence-manifest.sha256"]
	batch.AttemptLogDigest = evidenceDigests["attempts.jsonl"]
	batch.AttemptAnchorDigest = evidenceDigests["attempts.jsonl.anchor"]
	batchSlot := newAnchorSlotFixtureIn(
		t,
		makeFixtureDirectory(
			t, filepath.Join(committed, "000001-"+fixture.batchKey),
		),
		batch,
		previousOne,
		previousTwo,
		slotProfile,
	)
	batchOne, batchTwo := batchSlot.receiptDigests(t)
	batchRequestDigest, err := batch.Digest()
	if err != nil {
		t.Fatal(err)
	}

	inventoryDigest := fixtureDigest("execution-inventory")
	doneSchema := batchSchemaV2
	matrixSchema, completeSchema := matrixSchemaV2, completeSchemaV2
	if relative {
		doneSchema = batchSchemaV3
		matrixSchema, completeSchema = matrixSchemaV3, completeSchemaV3
	}
	done := map[string]string{
		"schema":           doneSchema,
		"batch_key":        fixture.batchKey,
		"randomized_block": "1",
		"order_digest":     orderDigest,
		"profile":          fixture.profileID,
		"readiness":        fixture.readiness,
		"attempts":         "100",
		"started_at_utc":   anchorSlotTimestamp,
		"finished_at_utc":  anchorSlotTimestamp,
		// The absolute path of the machine that sealed this batch. A copy of
		// this root will not have it, which is exactly the case under test.
		"archive": filepath.Join(
			fixture.root, "evidence", fixture.archiveName,
		),
		"archive_sha256":             archiveDigest,
		"execution_inventory_sha256": inventoryDigest,
		// The .done record states the mode that was PERFORMED, which is
		// dual-provider in both lineages; only matrix.env distinguishes who
		// performed it.
		"anchor_mode":                        anchorModeDualProvider,
		"anchor_request_sha256":              batchRequestDigest,
		"anchor_provider_one_receipt_sha256": batchOne,
		"anchor_provider_two_receipt_sha256": batchTwo,
	}
	if relative {
		done["archive_relative"] = "evidence/" + fixture.archiveName
	}
	writeKeyValueFixture(t, fixture.donePath(fixture.root), done)
	doneSum := sha256.Sum256(readFixtureFile(t, fixture.donePath(fixture.root)))

	aggregate := fmt.Sprintf(
		"%06d\t%s\t%s\t%s\t%s\n",
		1,
		batchRequestDigest,
		batchOne,
		batchTwo,
		hex.EncodeToString(doneSum[:]),
	)
	writeFixtureFile(
		t,
		filepath.Join(fixture.root, "anchors", "terminal-aggregate.list"),
		[]byte(aggregate),
	)
	aggregateSum := sha256.Sum256([]byte(aggregate))

	seal := identity
	seal.Kind = phase1anchor.KindSeal
	seal.Ordinal = 2
	seal.AggregateDigest = hex.EncodeToString(aggregateSum[:])
	sealSlot := newAnchorSlotFixtureIn(
		t,
		makeFixtureDirectory(
			t, filepath.Join(committed, "000002-terminal-seal"),
		),
		seal,
		batchOne,
		batchTwo,
		slotProfile,
	)
	sealOne, sealTwo := sealSlot.receiptDigests(t)

	environment := map[string]string{
		"schema":                     matrixSchema,
		"matrix_id":                  fixture.matrixID,
		"protocol_version":           connectivity.Version,
		"source_digest":              identity.SourceDigest,
		"auto_artifact_sha256":       identity.AutoArtifactDigest,
		"profile_sha256":             identity.ProfileDigest,
		"schedule_sha256":            identity.ScheduleDigest,
		"execution_inventory_sha256": inventoryDigest,
		"expected_batch_count":       "1",
		"partial":                    "0",
		"anchor_mode":                anchorMode,
		"anchor_schema":              phase1anchor.RequestSchema,
	}
	if relative {
		environment["intended_anchor_mode"] = anchorModeDualProvider
	} else {
		// Legacy lineage: the producer anchored, so matrix.env carries the
		// identities and there is no controller state at all.
		environment["anchor_provider_one_id"] = fixture.trust.providerOneID
		environment["anchor_provider_two_id"] = fixture.trust.providerTwoID
		environment["anchor_provider_one_key_id"] =
			phase1anchor.PublicKeyID(publicOne)
		environment["anchor_provider_two_key_id"] =
			phase1anchor.PublicKeyID(publicTwo)
		environment["anchor_known_hosts_sha256"] =
			hex.EncodeToString(knownHostsSum[:])
	}
	writeKeyValueFixture(t, filepath.Join(fixture.root, "matrix.env"), environment)

	if relative {
		// Controller lineage. The producer inputs are written first, because a
		// completed controller root RETAINS them and the verifier recomputes
		// the producer snapshot from exactly those files — a fixture without
		// them would be testing a root shape that cannot occur. The snapshot is
		// then measured over the finished producer state, and only afterwards
		// signed into CONTROLLER_START.
		writeProducerArtifactsFixture(
			t, fixture, evidenceDirectory, inventoryDigest,
		)
		snapshot, snapshotErr := producersnapshot.Digest(fixture.root)
		if snapshotErr != nil {
			t.Fatalf(
				"the fixture producer state is not measurable: %v", snapshotErr,
			)
		}
		fixture.finalizerKeyID = writeControllerStartFixture(
			t, fixture, identity, inventoryDigest,
			phase1anchor.PublicKeyID(publicOne),
			phase1anchor.PublicKeyID(publicTwo),
			hex.EncodeToString(knownHostsSum[:]),
			snapshot,
		)
		writeKeyValueFixture(
			t, filepath.Join(fixture.root, controllerEnvName),
			map[string]string{
				"schema":                     controllerEnvSchema,
				"matrix_id":                  fixture.matrixID,
				"source_digest":              identity.SourceDigest,
				"anchor_mode":                anchorModeDualProvider,
				"anchor_schema":              phase1anchor.RequestSchema,
				"anchor_provider_one_id":     fixture.trust.providerOneID,
				"anchor_provider_two_id":     fixture.trust.providerTwoID,
				"anchor_provider_one_key_id": phase1anchor.PublicKeyID(publicOne),
				"anchor_provider_two_key_id": phase1anchor.PublicKeyID(publicTwo),
				"anchor_known_hosts_sha256":  hex.EncodeToString(knownHostsSum[:]),
				"expected_batch_count":       "1",
				"finalizer_key_id":           fixture.finalizerKeyID,
			},
		)
	}
	writeKeyValueFixture(t, filepath.Join(fixture.root, "COMPLETE"), map[string]string{
		"schema":                          completeSchema,
		"matrix_id":                       fixture.matrixID,
		"attempts":                        "100",
		"schedule_sha256":                 identity.ScheduleDigest,
		"execution_inventory_sha256":      inventoryDigest,
		"anchor_mode":                     anchorModeDualProvider,
		"terminal_aggregate_sha256":       seal.AggregateDigest,
		"anchor_provider_one_seal_sha256": sealOne,
		"anchor_provider_two_seal_sha256": sealTwo,
	})
	return fixture
}

func (fixture *matrixRootFixture) donePath(root string) string {
	return filepath.Join(root, "batches", fixture.batchKey+".done")
}

func (fixture *matrixRootFixture) archivePath(root string) string {
	return filepath.Join(root, "evidence", fixture.archiveName)
}

func (fixture *matrixRootFixture) evidencePath(root string) string {
	return strings.TrimSuffix(fixture.archivePath(root), archiveSuffix)
}

// shapedEdgeQdiscDocument is the post-run qdisc evidence a 250ms/3%/10Mbps
// cell leaves behind, so sealBatchEvidence clears verifyBatch's shaping check
// and the tests that use it are about the sealed environment and nothing else.
const shapedEdgeQdiscDocument = `[{
	"kind":"netem",
	"root":true,
	"options":{
		"delay":{"delay":0.125},
		"loss-random":{"loss":0.0151142},
		"rate":{"rate":1250000}
	},
	"packets":1234
}]`

// shapedProfile is the frozen cell the sealed batch claims to have run, paired
// with shapedEdgeQdiscDocument.
func (fixture *matrixRootFixture) shapedProfile() networkProfile {
	return networkProfile{
		ID:           fixture.profileID,
		RTTMillis:    250,
		LossFraction: 0.03,
		CapacityMbps: 10,
	}
}

// formalEnvironment is the environment.txt a clean formal batch writes. Tests
// take a copy and change exactly the key under examination.
func (fixture *matrixRootFixture) formalEnvironment() map[string]string {
	return map[string]string{
		"awg_engine_sha256":           fixtureDigest("awg-engine"),
		"awg_handshake_hedge_offsets": "700ms,1100ms,1500ms,1900ms",
		"direct_initial_outer_drop":   "0s",
		"direct_click_delay":          "0s",
		"force_carrier":               "",
		"execution_inventory_sha256":  fixtureDigest("execution-inventory"),
	}
}

// sealBatchEvidence completes the fixture's batch evidence directory far
// enough for verifyBatch to reach the environment gate: a passing result, the
// shaped qdisc counters, the supplied environment, and a manifest recomputed
// over the real bytes. Rewriting the manifest changes its digest, so a root
// prepared this way is deliberately no longer the one the committed batch
// anchor commits to; it exists for the batch-level checks, not the chain.
func (fixture *matrixRootFixture) sealBatchEvidence(
	t *testing.T,
	environment map[string]string,
) {
	t.Helper()
	directory := fixture.evidencePath(fixture.root)
	writeFixtureFile(
		t, filepath.Join(directory, "result.txt"), []byte("PASS\n"),
	)
	for _, side := range []string{"client", "server"} {
		writeFixtureFile(
			t,
			filepath.Join(directory, side+"-post-run-qdisc.json"),
			[]byte(shapedEdgeQdiscDocument),
		)
	}
	writeKeyValueFixture(
		t, filepath.Join(directory, "environment.txt"), environment,
	)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	for _, entry := range entries {
		if entry.Name() == "evidence-manifest.sha256" {
			continue
		}
		sum := sha256.Sum256(
			readFixtureFile(t, filepath.Join(directory, entry.Name())),
		)
		manifest.WriteString(hex.EncodeToString(sum[:]))
		manifest.WriteString("  ./")
		manifest.WriteString(entry.Name())
		manifest.WriteString("\n")
	}
	writeFixtureFile(
		t,
		filepath.Join(directory, "evidence-manifest.sha256"),
		[]byte(manifest.String()),
	)
}

// verify runs the same two root-level checks the command runs, against whatever
// root the caller names. Everything is re-read from that root, so a passing
// result at a relocated copy is a genuine end-to-end relocation.
func (fixture *matrixRootFixture) verify(root string) error {
	environment, err := parseKeyValueFile(filepath.Join(root, "matrix.env"))
	if err != nil {
		return err
	}
	complete, err := parseKeyValueFile(filepath.Join(root, "COMPLETE"))
	if err != nil {
		return err
	}
	batches, err := loadBatches(root)
	if err != nil {
		return err
	}
	if err := verifyV2Schedule(
		root, fixture.profiles, environment, complete, batches,
	); err != nil {
		return err
	}
	return verifyDualProviderAnchors(
		root,
		fixture.profiles,
		environment,
		complete,
		batches,
		false,
		fixture.trust,
		false,
		auditCheckpointPin{finalizerKeyID: fixture.finalizerKeyID},
	)
}

// rewriteDone edits the sealed batch record in place. Every caller is a tamper
// case, so the resulting change of the record's own digest is intended.
func (fixture *matrixRootFixture) rewriteDone(
	t *testing.T,
	root string,
	edit func(map[string]string),
) {
	t.Helper()
	values, err := parseKeyValueFile(fixture.donePath(root))
	if err != nil {
		t.Fatal(err)
	}
	edit(values)
	writeKeyValueFixture(t, fixture.donePath(root), values)
}

func makeFixtureDirectory(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFixtureFile(t *testing.T, path string, content []byte) {
	t.Helper()
	// #nosec G306 -- disposable per-test temporary evidence root.
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	// #nosec G304 -- disposable per-test temporary evidence root.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// writeKeyValueFixture emits the sealer's key=value record format with keys in
// a stable order, which parseKeyValueFile accepts and which keeps the record's
// digest reproducible.
func writeKeyValueFixture(
	t *testing.T,
	path string,
	values map[string]string,
) {
	t.Helper()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(values[key])
		builder.WriteString("\n")
	}
	writeFixtureFile(t, path, []byte(builder.String()))
}

// copyFixtureTree reproduces a sealed root byte for byte, the way an auditor
// receives one. Directories are recreated so an intentionally empty one, such
// as anchors/pending, survives the copy.
func copyFixtureTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(
		source,
		func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			target := filepath.Join(destination, relative)
			if entry.IsDir() {
				return os.MkdirAll(target, 0o700)
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("sealed root holds a non-regular %s", relative)
			}
			return os.WriteFile(target, readFixtureFile(t, path), 0o600)
		},
	); err != nil {
		t.Fatal(err)
	}
}

// relocateFixture copies a sealed root to an unrelated directory and then
// destroys the original. Any read that still depended on the sealing machine's
// absolute paths fails after this, which is the point.
func relocateFixture(t *testing.T, fixture *matrixRootFixture) string {
	t.Helper()
	destination := t.TempDir()
	copyFixtureTree(t, fixture.root, destination)
	if err := os.RemoveAll(fixture.root); err != nil {
		t.Fatal(err)
	}
	return destination
}

func TestSealedMatrixRootVerifiesAfterByteExactRelocation(t *testing.T) {
	for _, sealed := range []struct {
		name     string
		relative bool
	}{
		{"legacy_v2_derived_archive_name", false},
		{"v3_recorded_relative_archive_path", true},
	} {
		t.Run(sealed.name, func(t *testing.T) {
			fixture := newMatrixRootFixture(t, sealed.relative)
			if err := fixture.verify(fixture.root); err != nil {
				t.Fatalf("the sealed root failed where it was sealed: %v", err)
			}
			relocated := relocateFixture(t, fixture)
			if err := fixture.verify(relocated); err != nil {
				t.Fatalf("the relocated copy failed to verify: %v", err)
			}
		})
	}
}

func TestRelocatedMatrixRootRejectsArchivePathAndDigestTampering(t *testing.T) {
	for _, test := range []struct {
		name     string
		relative bool
		tamper   func(*testing.T, *matrixRootFixture, string)
		want     string
	}{
		{
			// The archive is found at the derived name but is not the sealed
			// archive. Only the digest binding can catch this.
			name: "archive_digest_tampered",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				content := readFixtureFile(t, f.archivePath(root))
				content[0] ^= 0x01
				writeFixtureFile(t, f.archivePath(root), content)
			},
			want: "archive digest mismatch",
		},
		{
			// A different, entirely well-formed archive is moved into the
			// derived name. The name is right; the content belongs to another
			// batch, and the signed archive_sha256 says so.
			name: "another_archive_substituted_at_the_derived_name",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				other := filepath.Join(
					root, "evidence",
					"auto-e2e-"+f.matrixID+"-edge--cold--b001.tar.gz",
				)
				body := []byte("sealed archive of edge--cold--b001\n")
				writeFixtureFile(t, other, body)
				writeFixtureFile(t, f.archivePath(root), body)
			},
			want: "archive digest mismatch",
		},
		{
			// The link target holds byte-identical content, so every digest
			// check would pass. Only the root-scoped, no-symlink open rejects
			// it, which is what stops a copied tree reaching outside itself.
			name: "symbolic_link_escapes_the_auditor_root",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				outside := filepath.Join(t.TempDir(), "planted.tar.gz")
				writeFixtureFile(
					t, outside,
					[]byte("sealed archive of "+f.batchKey+"\n"),
				)
				if err := os.Remove(f.archivePath(root)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, f.archivePath(root)); err != nil {
					t.Fatal(err)
				}
			},
			want: "batch archive is absent or not a regular file",
		},
		{
			// Even a link that stays inside the root is refused, so the
			// archive that is hashed is always the archive that is named.
			name: "symbolic_link_inside_the_auditor_root",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				sibling := filepath.Join(root, "evidence", "sibling.tar.gz")
				writeFixtureFile(
					t, sibling,
					[]byte("sealed archive of "+f.batchKey+"\n"),
				)
				if err := os.Remove(f.archivePath(root)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					"sibling.tar.gz", f.archivePath(root),
				); err != nil {
					t.Fatal(err)
				}
			},
			want: "batch archive is absent or not a regular file",
		},
		{
			name: "archive_removed_from_the_copy",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				if err := os.Remove(f.archivePath(root)); err != nil {
					t.Fatal(err)
				}
			},
			want: "absent or not a regular file",
		},
		{
			// A decoy that exists, is readable, and holds exactly the sealed
			// bytes is named by the legacy absolute record while the copy's
			// own archive is corrupted. Verification must still fail, which
			// proves the recorded absolute path is never opened.
			name: "legacy_absolute_record_points_at_a_correct_decoy",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				decoy := filepath.Join(t.TempDir(), "evidence")
				if err := os.MkdirAll(decoy, 0o700); err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(
					t,
					filepath.Join(decoy, f.archiveName),
					[]byte("sealed archive of "+f.batchKey+"\n"),
				)
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive"] = filepath.Join(decoy, f.archiveName)
				})
				writeFixtureFile(t, f.archivePath(root), []byte("corrupt\n"))
			},
			want: "archive digest mismatch",
		},
		{
			// The recorded path is consistent with a different batch's
			// identity, so it no longer agrees with the name derived from this
			// batch's authenticated matrix_id and batch_key.
			name: "legacy_absolute_record_names_another_batch",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive"] = "/opt/winn-lab/matrices/" +
						f.matrixID + "/evidence/auto-e2e-" + f.matrixID +
						"-edge--cold--b001.tar.gz"
				})
			},
			want: "does not name the derived evidence file",
		},
		{
			name: "legacy_absolute_record_drops_the_evidence_directory",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive"] = "/opt/winn-lab/" + f.archiveName
				})
			},
			want: "does not name the derived evidence file",
		},
		{
			name:     "recorded_relative_path_traverses_upward",
			relative: true,
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive_relative"] =
						"evidence/../../../../etc/passwd.tar.gz"
				})
			},
			want: "relative archive path is invalid",
		},
		{
			name:     "recorded_relative_path_is_absolute",
			relative: true,
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive_relative"] = "/etc/evidence/" + f.archiveName
				})
			},
			want: "relative archive path is invalid",
		},
		{
			name:     "recorded_relative_path_leaves_the_evidence_directory",
			relative: true,
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive_relative"] = "../evidence/" + f.archiveName
				})
			},
			want: "relative archive path is invalid",
		},
		{
			name:     "recorded_relative_path_descends_a_subdirectory",
			relative: true,
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive_relative"] = "evidence/nested/" + f.archiveName
				})
			},
			want: "relative archive path is invalid",
		},
		{
			// A v2 record may not smuggle in the v3 field, and a v3 record may
			// not omit it, so the two resolution paths cannot be mixed.
			name: "v2_record_carries_a_relative_path",
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					values["archive_relative"] = "evidence/" + f.archiveName
				})
			},
			want: "does not carry the archive path its schema requires",
		},
		{
			name:     "v3_record_omits_its_relative_path",
			relative: true,
			tamper: func(t *testing.T, f *matrixRootFixture, root string) {
				f.rewriteDone(t, root, func(values map[string]string) {
					delete(values, "archive_relative")
				})
			},
			want: "does not carry the archive path its schema requires",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixRootFixture(t, test.relative)
			relocated := relocateFixture(t, fixture)
			if err := fixture.verify(relocated); err != nil {
				t.Fatalf("the untampered copy failed: %v", err)
			}
			test.tamper(t, fixture, relocated)
			err := fixture.verify(relocated)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"tampered relocated root error = %v, want %q",
					err, test.want,
				)
			}
		})
	}
}

func TestBatchArchiveNameRejectsEverythingButAPlainFileName(t *testing.T) {
	const (
		matrixID = "phase1-relocation-v1"
		batchKey = "edge--warm--b001"
	)
	derived := "auto-e2e-" + matrixID + "-" + batchKey + ".tar.gz"
	legacy := func(archive string) matrixBatch {
		return matrixBatch{key: batchKey, archive: archive}
	}
	for _, test := range []struct {
		name     string
		matrixID string
		batch    matrixBatch
		want     string
	}{
		{
			name:     "legacy_absolute_record_is_accepted_for_its_name_only",
			matrixID: matrixID,
			batch:    legacy("/opt/winn-lab/matrices/x/evidence/" + derived),
			want:     derived,
		},
		{
			name:     "recorded_relative_path_is_accepted",
			matrixID: matrixID,
			batch: matrixBatch{
				key:             batchKey,
				archiveRelative: "evidence/" + derived,
			},
			want: derived,
		},
		{
			name:     "matrix_identity_carrying_a_separator",
			matrixID: "../../etc",
			batch:    legacy("/evidence/auto-e2e-../../etc-" + batchKey + ".tar.gz"),
			want:     "",
		},
		{
			name:     "batch_key_carrying_a_separator",
			matrixID: matrixID,
			batch: matrixBatch{
				key:     "edge/../../etc/passwd",
				archive: "/evidence/x.tar.gz",
			},
			want: "",
		},
		{
			name:     "empty_matrix_identity",
			matrixID: "",
			batch:    legacy("/evidence/" + derived),
			want:     "",
		},
		{
			name:     "empty_batch_key",
			matrixID: matrixID,
			batch:    matrixBatch{archive: "/evidence/" + derived},
			want:     "",
		},
		{
			name:     "legacy_record_is_relative",
			matrixID: matrixID,
			batch:    legacy("evidence/" + derived),
			want:     "",
		},
		{
			name:     "legacy_record_names_a_different_file",
			matrixID: matrixID,
			batch:    legacy("/evidence/auto-e2e-other.tar.gz"),
			want:     "",
		},
		{
			name:     "relative_path_without_a_directory",
			matrixID: matrixID,
			batch: matrixBatch{
				key: batchKey, archiveRelative: derived,
			},
			want: "",
		},
		{
			name:     "relative_path_with_an_empty_stem",
			matrixID: matrixID,
			batch: matrixBatch{
				key: batchKey, archiveRelative: "evidence/.tar.gz",
			},
			want: "",
		},
		{
			name:     "relative_path_without_the_archive_suffix",
			matrixID: matrixID,
			batch: matrixBatch{
				key: batchKey, archiveRelative: "evidence/" + batchKey,
			},
			want: "",
		},
		{
			name:     "relative_path_naming_the_parent_directory",
			matrixID: matrixID,
			batch: matrixBatch{
				key: batchKey, archiveRelative: "evidence/..",
			},
			want: "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, err := batchArchiveName(test.matrixID, test.batch)
			if test.want == "" {
				if err == nil {
					t.Fatalf("unsafe archive name was accepted as %q", name)
				}
				return
			}
			if err != nil || name != test.want {
				t.Fatalf("archive name = %q, %v; want %q", name, err, test.want)
			}
		})
	}
}

// TestFormalBatchRequiresRecordedForcedCarrierState pins the rule that a batch
// is admitted into scored evidence only when its sealed environment states, in
// writing, that no carrier was forced. Silence is not consent: evidence from a
// harness that never recorded the knob is byte-indistinguishable from a run
// that restricted preparation to one carrier, so it is refused too.
func TestFormalBatchRequiresRecordedForcedCarrierState(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(map[string]string)
		want    string
		refused bool
	}{
		{
			name:   "recorded_as_unforced",
			mutate: func(map[string]string) {},
			// The gate is cleared, so the batch runs on into the execution
			// inventory check that this fixture deliberately cannot satisfy.
			want: "evidence execution inventory digest mismatch",
		},
		{
			name: "key_absent_entirely",
			mutate: func(values map[string]string) {
				delete(values, "force_carrier")
			},
			want:    "does not record its forced-carrier state",
			refused: true,
		},
		{
			name: "carrier_forced_to_direct_awg",
			mutate: func(values map[string]string) {
				values["force_carrier"] = "direct-awg"
			},
			want:    "restricted preparation to one carrier",
			refused: true,
		},
		{
			name: "carrier_forced_to_http3",
			mutate: func(values map[string]string) {
				values["force_carrier"] = "http3"
			},
			want:    "restricted preparation to one carrier",
			refused: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixRootFixture(t, true)
			environment := fixture.formalEnvironment()
			test.mutate(environment)
			fixture.sealBatchEvidence(t, environment)
			batches, err := loadBatches(fixture.root)
			if err != nil || len(batches) != 1 {
				t.Fatalf("sealed batches = %v, error = %v", batches, err)
			}
			_, err = verifyBatch(
				fixture.root,
				fixture.matrixID,
				batches[0],
				fixture.shapedProfile(),
				3000,
				fixtureDigest("source"),
				fixtureDigest("awg-engine"),
				true,
				fixtureDigest("execution-inventory"),
				auditCheckpointPin{},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("formal batch error = %v, want %q", err, test.want)
			}
			if !test.refused {
				return
			}
			// A legacy non-v2 profile scores nothing and treats measured
			// failures as harness faults, so it must never acquire a
			// requirement the harness that sealed its evidence predates.
			_, legacy := verifyBatch(
				fixture.root,
				fixture.matrixID,
				batches[0],
				fixture.shapedProfile(),
				3000,
				fixtureDigest("source"),
				fixtureDigest("awg-engine"),
				false,
				fixtureDigest("execution-inventory"),
				auditCheckpointPin{},
			)
			if legacy != nil &&
				strings.Contains(legacy.Error(), test.want) {
				t.Fatalf("unscored batch inherited the formal gate: %v", legacy)
			}
		})
	}
}

// writeControllerStartFixture signs a real CONTROLLER_START for a fixture and
// returns the finalizer identity an auditor would pin.
//
// A real ML-DSA signature, not a stub: the verifier checks it, so a fixture
// that faked it would test nothing.
func writeControllerStartFixture(
	t *testing.T,
	fixture *matrixRootFixture,
	identity phase1anchor.Request,
	inventoryDigest string,
	providerOneKeyID string,
	providerTwoKeyID string,
	knownHostsDigest string,
	producerSnapshot string,
) string {
	t.Helper()
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(auditcheckpoint.FinalizerAlgorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()

	record := controllerStartRecord{
		Schema:                controllerStartSchema,
		MatrixID:              fixture.matrixID,
		SourceDigest:          identity.SourceDigest,
		ScheduleDigest:        identity.ScheduleDigest,
		AutoArtifactDigest:    identity.AutoArtifactDigest,
		ProfileDigest:         identity.ProfileDigest,
		ExecutionInventory:    inventoryDigest,
		ProducerAttempts:      100,
		ExpectedBatchCount:    1,
		ProducerSnapshot:      producerSnapshot,
		AnchorProviderOneID:   fixture.trust.providerOneID,
		AnchorProviderOneKey:  providerOneKeyID,
		AnchorProviderTwoID:   fixture.trust.providerTwoID,
		AnchorProviderTwoKey:  providerTwoKeyID,
		AnchorKnownHostsSHA:   knownHostsDigest,
		FinalizerAlgorithm:    auditcheckpoint.FinalizerAlgorithm,
		FinalizerKeyID:        signer.KeyID(),
		FinalizerPublicKeyB64: base64.StdEncoding.EncodeToString(signer.PublicBytes()),
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.ControllerStartSignatureDomain,
		record.signingMessage(), signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t,
		filepath.Join(fixture.root, controllerStartName),
		append(encoded, '\n'))
	return signer.KeyID()
}

// writeProducerArtifactsFixture recreates the producer-side inputs a completed
// controller root retains, so the producer snapshot the verifier recomputes has
// something real to measure.
func writeProducerArtifactsFixture(
	t *testing.T,
	fixture *matrixRootFixture,
	evidenceDirectory string,
	inventoryDigest string,
) {
	t.Helper()
	writeFixtureFile(t,
		filepath.Join(fixture.root, "execution-inventory.sha256"),
		[]byte(inventoryDigest+"  /opt/winn-lab/bin/winn-auto-e2e\n"))

	evidenceName := filepath.Base(evidenceDirectory)
	producerArchive := filepath.Join(
		fixture.root, "evidence", evidenceName+".closed-pending.tar.gz")
	writeFixtureFile(t, producerArchive,
		buildProducerArchiveFixture(t, evidenceDirectory))
	archiveSum := sha256.Sum256(readFixtureFile(t, producerArchive))

	writeKeyValueFixture(t,
		filepath.Join(
			fixture.root, "batches", fixture.batchKey+".closed-pending"),
		map[string]string{
			"schema":           "winn-phase1-auto-matrix-batch-closed-pending/v3",
			"batch_key":        fixture.batchKey,
			"randomized_block": "1",
			"order_digest":     fixtureDigest("order"),
			"profile":          fixture.profileID,
			"readiness":        fixture.readiness,
			"attempts":         "100",
			"started_at_utc":   anchorSlotTimestamp,
			"finished_at_utc":  anchorSlotTimestamp,
			"archive":          producerArchive,
			"archive_relative": "evidence/" + evidenceName +
				".closed-pending.tar.gz",
			"archive_sha256":                     hex.EncodeToString(archiveSum[:]),
			"execution_inventory_sha256":         inventoryDigest,
			"anchor_mode":                        deferredAnchorMode,
			"anchor_request_sha256":              "",
			"anchor_provider_one_receipt_sha256": "",
			"anchor_provider_two_receipt_sha256": "",
		})

	writeKeyValueFixture(t,
		filepath.Join(fixture.root, "PRODUCER_CLOSED_PENDING"),
		map[string]string{
			"schema":                     "winn-phase1-auto-matrix-closed-pending/v3",
			"matrix_id":                  fixture.matrixID,
			"attempts":                   "100",
			"schedule_sha256":            fixtureDigest("schedule"),
			"execution_inventory_sha256": inventoryDigest,
			"anchor_mode":                deferredAnchorMode,
			"intended_anchor_mode":       anchorModeDualProvider,
			"partial":                    "0",
			"audit_close_state":          "pending-controller-finalization",
		})
}

// buildProducerArchiveFixture tars the evidence tree the way the producer's
// own `tar -czf` does, so the snapshot's archive-equivalence check has a
// faithful artifact to compare against.
func buildProducerArchiveFixture(t *testing.T, evidenceDirectory string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressor := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressor)
	base := filepath.Base(evidenceDirectory)
	if err := writer.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir, Name: base + "/", Mode: 0o700,
		Format: tar.FormatPAX,
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		content := readFixtureFile(t, filepath.Join(evidenceDirectory, name))
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: base + "/" + name, Mode: 0o600,
			Size: int64(len(content)), Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
