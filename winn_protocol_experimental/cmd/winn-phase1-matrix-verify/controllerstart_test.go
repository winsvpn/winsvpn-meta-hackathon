// Binding coverage for the controller's signed ownership record.
//
// Verifying the SIGNATURE proves the finalizer signed something. It does not
// prove that what it signed describes the matrix in front of the auditor — so
// a validly signed but entirely FALSE ownership record verified cleanly while
// several of its signed fields were bound to nothing at all.
//
// Each case below re-signs the record with the legitimate key after altering
// one field, so the signature is genuine and the pin matches. Only an
// independent cross-check against the evidence can reject them.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/pqauth"
)

// resignStartRecord rewrites the fixture's CONTROLLER_START with one field
// altered and a genuine signature over the altered content.
func resignStartRecord(
	t *testing.T,
	fixture *matrixRootFixture,
	mutate func(*controllerStartRecord),
) {
	t.Helper()
	path := filepath.Join(fixture.root, controllerStartName)
	content, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	var record controllerStartRecord
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	mutate(&record)

	// A fresh key would fail the pin, which would prove nothing about the
	// binding. The fixture's own signer is regenerated per fixture, so the
	// record is re-signed with a NEW key and the fixture's pin is updated to
	// match — leaving the binding as the only thing that can reject it.
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(auditcheckpoint.FinalizerAlgorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	record.FinalizerKeyID = signer.KeyID()
	record.FinalizerPublicKeyB64 = base64.StdEncoding.EncodeToString(
		signer.PublicBytes(),
	)
	signature, err := pqauth.SignDomainMessage(
		pqauth.ControllerStartSignatureDomain, record.signingMessage(), signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, path, append(encoded, '\n'))

	// controller.env records the finalizer too; keep them consistent so the
	// only defect is the mutated binding.
	controllerPath := filepath.Join(fixture.root, controllerEnvName)
	existing, err := os.ReadFile(controllerPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	var rebuilt []string
	for _, line := range strings.Split(
		strings.TrimSuffix(string(existing), "\n"), "\n",
	) {
		if strings.HasPrefix(line, "finalizer_key_id=") {
			line = "finalizer_key_id=" + signer.KeyID()
		}
		rebuilt = append(rebuilt, line)
	}
	writeFixtureFile(t, controllerPath,
		[]byte(strings.Join(rebuilt, "\n")+"\n"))
	fixture.finalizerKeyID = signer.KeyID()
}

// TestControllerStartBindsEverySignedField is the finding, stated as a test.
func TestControllerStartBindsEverySignedField(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*controllerStartRecord)
		want   string
	}{
		{
			name: "schedule_digest",
			mutate: func(r *controllerStartRecord) {
				r.ScheduleDigest = strings.Repeat("7", 64)
			},
			want: "schedule_sha256",
		},
		{
			name: "auto_artifact_digest",
			mutate: func(r *controllerStartRecord) {
				r.AutoArtifactDigest = strings.Repeat("7", 64)
			},
			want: "auto_artifact_sha256",
		},
		{
			name: "profile_digest",
			mutate: func(r *controllerStartRecord) {
				r.ProfileDigest = strings.Repeat("7", 64)
			},
			want: "profile_sha256",
		},
		{
			name: "execution_inventory",
			mutate: func(r *controllerStartRecord) {
				r.ExecutionInventory = strings.Repeat("7", 64)
			},
			want: "execution_inventory_sha256",
		},
		{
			name: "producer_attempts",
			mutate: func(r *controllerStartRecord) {
				r.ProducerAttempts = 999
			},
			want: "producer_attempts",
		},
		{
			name: "producer_snapshot",
			mutate: func(r *controllerStartRecord) {
				r.ProducerSnapshot = strings.Repeat("7", 64)
			},
			want: "producer snapshot",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixRootFixture(t, true)
			// The unmutated fixture must verify, or the rejection below could
			// be for any reason at all.
			if err := fixture.verify(fixture.root); err != nil {
				t.Fatalf("the positive control must verify: %v", err)
			}
			resignStartRecord(t, fixture, test.mutate)
			err := fixture.verify(fixture.root)
			if err == nil {
				t.Fatalf(
					"a validly signed record whose %s does not describe this "+
						"matrix was accepted; the signature proves only that "+
						"the finalizer signed SOMETHING", test.name,
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestControllerStartRejectsDuplicateJSONKeys covers the parser hardening.
// encoding/json keeps the last occurrence, so a record could state one field
// twice — one value for a reader, another for the decoder.
func TestControllerStartRejectsDuplicateJSONKeys(t *testing.T) {
	fixture := newMatrixRootFixture(t, true)
	path := filepath.Join(fixture.root, controllerStartName)
	content, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	doubled := strings.Replace(string(content),
		`"producer_snapshot_sha256":`,
		`"producer_snapshot_sha256": "`+strings.Repeat("0", 64)+`",`+
			"\n  "+`"producer_snapshot_sha256":`, 1)
	if doubled == string(content) {
		t.Fatalf("failed to build the duplicate-key fixture:\n%s", content)
	}
	writeFixtureFile(t, path, []byte(doubled))
	err = fixture.verify(fixture.root)
	if err == nil {
		t.Fatal("a record stating one field twice was accepted")
	}
	if !strings.Contains(err.Error(), "repeats the key") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestControllerStartEnforcesCanonicalInvariants pins the verifier's acceptance
// criteria to the controller's production criteria. A looser independent
// reimplementation would accept records the controller would never emit.
func TestControllerStartEnforcesCanonicalInvariants(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*controllerStartRecord)
		want   string
	}{
		{
			name:   "foreign_algorithm",
			mutate: func(r *controllerStartRecord) { r.FinalizerAlgorithm = "HMAC-SHA-256" },
			want:   "finalizer algorithm",
		},
		{
			name:   "unsafe_matrix_id",
			mutate: func(r *controllerStartRecord) { r.MatrixID = "matrix id/../x" },
			want:   "not a safe identifier",
		},
		{
			name:   "unsafe_provider_id",
			mutate: func(r *controllerStartRecord) { r.AnchorProviderOneID = "a b" },
			want:   "not a safe identifier",
		},
		{
			name:   "uppercase_digest",
			mutate: func(r *controllerStartRecord) { r.SourceDigest = strings.ToUpper(strings.Repeat("ab", 32)) },
			want:   "lower-hex",
		},
		{
			name:   "short_digest",
			mutate: func(r *controllerStartRecord) { r.ProducerSnapshot = "abc" },
			want:   "lower-hex",
		},
		{
			name:   "zero_batches",
			mutate: func(r *controllerStartRecord) { r.ExpectedBatchCount = 0 },
			want:   "no batches",
		},
		{
			name:   "zero_attempts",
			mutate: func(r *controllerStartRecord) { r.ProducerAttempts = 0 },
			want:   "no attempts",
		},
		{
			name:   "unknown_schema",
			mutate: func(r *controllerStartRecord) { r.Schema = "winn-phase1-controller-start/v2" },
			want:   "declares schema",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixRootFixture(t, true)
			resignStartRecord(t, fixture, test.mutate)
			err := fixture.verify(fixture.root)
			if err == nil {
				t.Fatalf(
					"a record violating the controller's own %s invariant was "+
						"accepted", test.name,
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestControllerStartIdentifierBoundMatchesTheController is the divergence
// itself, stated as a test.
//
// The verifier's regex allowed {1,256} while the controller's signingMessage
// enforces {1,128}. That gap accepted signed records the controller could never
// emit — and, worse, could never resume: a 200-character matrix id would pass an
// auditor and then be refused by the tool that supposedly produced it. A
// verifier whose acceptance criteria are looser than production's is not
// verifying production.
func TestControllerStartIdentifierBoundMatchesTheController(t *testing.T) {
	// The controller's own bound, restated here so a change to either side has
	// to be made deliberately in both.
	const controllerIdentifierLimit = 128

	t.Run("at_the_bound_is_accepted", func(t *testing.T) {
		fixture := newMatrixRootFixture(t, true)
		atLimit := strings.Repeat("m", controllerIdentifierLimit)
		if len(atLimit) != controllerIdentifierLimit {
			t.Fatalf("fixture identifier is %d characters", len(atLimit))
		}
		// Only the identifier's SHAPE is under test here, so the record is
		// re-signed with a matrix id at exactly the limit and the resulting
		// binding mismatch is the expected outcome — what must NOT happen is a
		// rejection for length.
		resignStartRecord(t, fixture, func(r *controllerStartRecord) {
			r.MatrixID = atLimit
		})
		err := fixture.verify(fixture.root)
		if err == nil {
			t.Fatal("a record naming a different matrix was accepted")
		}
		if strings.Contains(err.Error(), "not a safe identifier") {
			t.Fatalf(
				"an identifier of exactly %d characters was rejected for "+
					"length; the controller accepts this: %v",
				controllerIdentifierLimit, err,
			)
		}
	})

	t.Run("one_past_the_bound_is_rejected", func(t *testing.T) {
		fixture := newMatrixRootFixture(t, true)
		tooLong := strings.Repeat("m", controllerIdentifierLimit+1)
		if len(tooLong) != 129 {
			t.Fatalf("fixture identifier is %d characters", len(tooLong))
		}
		// Legitimately re-signed: the signature is genuine and the pin matches,
		// so only the identifier bound can reject it.
		resignStartRecord(t, fixture, func(r *controllerStartRecord) {
			r.MatrixID = tooLong
		})
		err := fixture.verify(fixture.root)
		if err == nil {
			t.Fatalf(
				"a validly signed record with a %d-character matrix id was "+
					"accepted; the controller could never emit or resume it",
				len(tooLong),
			)
		}
		if !strings.Contains(err.Error(), "not a safe identifier") {
			t.Fatalf(
				"the over-length identifier was refused, but not for its "+
					"length: %v", err,
			)
		}
	})

	t.Run("over_length_provider_identifiers_are_rejected", func(t *testing.T) {
		for _, field := range []string{"one", "two"} {
			t.Run("provider_"+field, func(t *testing.T) {
				fixture := newMatrixRootFixture(t, true)
				tooLong := strings.Repeat("p", controllerIdentifierLimit+1)
				resignStartRecord(t, fixture, func(r *controllerStartRecord) {
					if field == "one" {
						r.AnchorProviderOneID = tooLong
					} else {
						r.AnchorProviderTwoID = tooLong
					}
				})
				err := fixture.verify(fixture.root)
				if err == nil {
					t.Fatal("an over-length provider identifier was accepted")
				}
				if !strings.Contains(err.Error(), "not a safe identifier") {
					t.Fatalf("refused for the wrong reason: %v", err)
				}
			})
		}
	})
}
