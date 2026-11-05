// Schema/mode pairing for anchor-slot verification.
//
// The profile is chosen from the matrix schema AND the anchor mode together.
// Choosing on either alone leaves the cross-pairs silently accepted, and the
// consequence is not cosmetic: a v3 root declaring the legacy mode would be
// routed to the legacy profile, which never reads controller.env — so the
// controller's anchor identities, its finalizer binding, and the entire
// deferred-anchor commitment would go unchecked while the root still reported
// as anchored.
package main

import (
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

func TestAnchorSlotProfileRequiresAMatchingSchemaAndMode(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment map[string]string
		want        anchorSlotProfile
		wantError   string
	}{
		{
			name: "legacy_v2_with_producer_anchoring",
			environment: map[string]string{
				"schema":      matrixSchemaV2,
				"anchor_mode": anchorModeDualProvider,
			},
			want: anchorSlotLegacyV2,
		},
		{
			name: "controller_v3_with_deferred_anchoring",
			environment: map[string]string{
				"schema":               matrixSchemaV3,
				"anchor_mode":          deferredAnchorMode,
				"intended_anchor_mode": anchorModeDualProvider,
			},
			want: anchorSlotControllerV3,
		},
		{
			name: "v2_with_deferred_mode",
			environment: map[string]string{
				"schema":               matrixSchemaV2,
				"anchor_mode":          deferredAnchorMode,
				"intended_anchor_mode": anchorModeDualProvider,
			},
			wantError: "not a recognised anchoring layout",
		},
		{
			name: "v3_with_producer_anchoring",
			environment: map[string]string{
				"schema":      matrixSchemaV3,
				"anchor_mode": anchorModeDualProvider,
			},
			// The dangerous cross-pair: mode alone would have routed this to
			// the legacy profile and skipped controller.env entirely.
			wantError: "not a recognised anchoring layout",
		},
		{
			name: "v3_deferred_without_the_committed_intent",
			environment: map[string]string{
				"schema":      matrixSchemaV3,
				"anchor_mode": deferredAnchorMode,
			},
			wantError: "committed",
		},
		{
			name: "unknown_schema",
			environment: map[string]string{
				"schema":      "winn-phase1-auto-matrix/v9",
				"anchor_mode": deferredAnchorMode,
			},
			wantError: "not a recognised anchoring layout",
		},
		{
			name: "unknown_mode",
			environment: map[string]string{
				"schema":      matrixSchemaV3,
				"anchor_mode": "some-future-anchoring",
			},
			wantError: "not a recognised anchoring layout",
		},
		{
			name:        "absent_fields",
			environment: map[string]string{},
			wantError:   "not a recognised anchoring layout",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, err := selectAnchorSlotProfile(test.environment)
			if test.wantError != "" {
				if err == nil {
					t.Fatalf(
						"schema=%q mode=%q was accepted and mapped to %q; a "+
							"mismatched pair must be refused rather than "+
							"verified under whichever profile matches one field",
						test.environment["schema"],
						test.environment["anchor_mode"], profile,
					)
				}
				if !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("refused for the wrong reason: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a valid pair was refused: %v", err)
			}
			if profile != test.want {
				t.Fatalf("profile = %q, want %q", profile, test.want)
			}
		})
	}
}

// TestAnchorSlotFileSetsMatchTheToolsThatWriteThem pins each profile's artifact
// set to what its own tool actually produces.
//
// The legacy count assumed a batch-meta.env that winn-phase1-anchor-pin has
// never written, so every controller-produced batch slot would have failed the
// eight-file rule — after the providers had already signed it.
func TestAnchorSlotFileSetsMatchTheToolsThatWriteThem(t *testing.T) {
	// The seven artifacts the real pin tool creates, enumerated here so a
	// change to either side has to be made deliberately in both.
	pinToolArtifacts := []string{
		"provider-config.json",
		"provider-one.receipt.json",
		"provider-one.receipt.json.sha256",
		"provider-two.receipt.json",
		"provider-two.receipt.json.sha256",
		"request.json",
		"request.json.sha256",
	}

	for _, kind := range []string{
		phase1anchor.KindGenesis,
		phase1anchor.KindBatch,
		phase1anchor.KindSeal,
	} {
		t.Run("controller_v3_"+kind, func(t *testing.T) {
			names, err := anchorSlotFileSet(anchorSlotControllerV3, kind)
			if err != nil {
				t.Fatal(err)
			}
			if len(names) != len(pinToolArtifacts) {
				t.Fatalf(
					"the controller profile expects %d artifacts, the pin tool "+
						"writes %d", len(names), len(pinToolArtifacts),
				)
			}
			for _, artifact := range pinToolArtifacts {
				if _, ok := names[artifact]; !ok {
					t.Fatalf("the controller profile omits %s", artifact)
				}
			}
			if _, ok := names["batch-meta.env"]; ok {
				t.Fatal(
					"the controller profile expects batch-meta.env, which the " +
						"pin tool has never written",
				)
			}
		})
	}

	t.Run("legacy_v2_batch_keeps_batch_meta", func(t *testing.T) {
		names, err := anchorSlotFileSet(
			anchorSlotLegacyV2, phase1anchor.KindBatch)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := names["batch-meta.env"]; !ok {
			t.Fatal(
				"the legacy profile dropped batch-meta.env; historical sealed " +
					"evidence would stop verifying",
			)
		}
		if len(names) != len(pinToolArtifacts)+1 {
			t.Fatalf("the legacy batch profile expects %d artifacts", len(names))
		}
	})

	t.Run("legacy_v2_non_batch_has_no_batch_meta", func(t *testing.T) {
		for _, kind := range []string{
			phase1anchor.KindGenesis, phase1anchor.KindSeal,
		} {
			names, err := anchorSlotFileSet(anchorSlotLegacyV2, kind)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := names["batch-meta.env"]; ok {
				t.Fatalf("the legacy %s profile expects batch-meta.env", kind)
			}
		}
	})

	t.Run("unknown_profile_is_refused", func(t *testing.T) {
		if _, err := anchorSlotFileSet(
			anchorSlotProfile("something-else"), phase1anchor.KindBatch,
		); err == nil {
			t.Fatal("an unrecognised slot profile was given a file set")
		}
	})
}
