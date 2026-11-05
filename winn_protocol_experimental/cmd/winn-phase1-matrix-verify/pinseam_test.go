// The pin-tool-to-verifier seam, with no fake on either side of it.
//
// This is the test whose absence produced the batch-meta.env P0. The formal
// verifier's exact-set check required a file the real pin tool never wrote;
// both sides had thorough tests, each written against its own hand-built idea
// of what an anchor slot is, and nothing ever fed one side's actual OUTPUT to
// the other side's actual INPUT. An independent reviewer later confirmed the
// gap in one sentence: no test anywhere executed the real pin tool.
//
// So here the slot is produced by the actual winn-phase1-anchor-pin binary and
// consumed by the actual verifyAnchorSlot. Neither side is stubbed, and neither
// side's expectations are restated: the file set comes from the single shared
// definition in internal/phase1anchor, and the acceptance criteria come from
// the verifier's own production code path.
//
// The anchor PROVIDER is stubbed, because it is an external host outside this
// seam — but its receipts are produced by the real phase1anchor.NewReceipt
// under real Ed25519 keys, so the bytes crossing the seam are genuine.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/anchorfixture"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// verifySlotProducedByTheRealPinTool runs the verifier's real acceptance path
// over a real slot.
func verifySlotProducedByTheRealPinTool(
	t *testing.T, slot *anchorfixture.Slot, directory string,
) (string, string, string, error) {
	t.Helper()
	return verifyAnchorSlotAtPath(
		directory,
		slot.Request,
		anchorTrust{
			providerOneID: slot.ProviderOneID,
			providerTwoID: slot.ProviderTwoID,
		},
		slot.ProviderOnePublic,
		slot.ProviderTwoPublic,
		slot.PreviousOne,
		slot.PreviousTwo,
		anchorSlotControllerV3,
		// The authenticated known-hosts digest, computed from the very bytes
		// the fixture handed the real pin tool. The two sides must agree on it
		// without either being told what the other used.
		slot.KnownHostsDigest,
	)
}

// TestRealPinToolOutputIsAcceptedByTheRealVerifier is the seam itself.
func TestRealPinToolOutputIsAcceptedByTheRealVerifier(t *testing.T) {
	for _, test := range []struct {
		name    string
		request phase1anchor.Request
		one     string
		two     string
	}{
		{
			name:    "genesis",
			request: anchorfixture.GenesisRequest("m1"),
			one:     phase1anchor.ZeroDigest,
			two:     phase1anchor.ZeroDigest,
		},
		{
			name:    "batch",
			request: anchorfixture.BatchRequest("m1", "b0001-edge-warm", 1),
			one:     strings.Repeat("a", 64),
			two:     strings.Repeat("b", 64),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			slot := anchorfixture.Produce(t, test.request, test.one, test.two)
			one, two, requestDigest, err := verifySlotProducedByTheRealPinTool(
				t, slot, slot.Directory,
			)
			if err != nil {
				t.Fatalf(
					"the formal verifier refused a slot the real pin tool "+
						"produced: %v", err,
				)
			}
			if one == "" || two == "" || requestDigest == "" {
				t.Fatalf(
					"the verifier accepted the slot but returned empty "+
						"digests: one=%q two=%q request=%q",
					one, two, requestDigest,
				)
			}
			if one == two {
				t.Fatal(
					"the two provider receipts digest identically; they are " +
						"not independent witnesses",
				)
			}
			// The verifier's own view of the request must be the fixture's.
			expected, err := test.request.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if requestDigest != expected {
				t.Fatalf(
					"the verifier read request digest %q from the slot, the "+
						"request it was given digests to %q",
					requestDigest, expected,
				)
			}
		})
	}
}

// TestRealPinToolWritesExactlyTheSetTheVerifierRequires compares the two sides
// directly, rather than comparing each against a list written by hand.
//
// This is the specific comparison that was missing. The verifier's expectation
// comes from anchorSlotFileSet — its real production function — and the pin
// tool's output is read off the directory the real binary just wrote. Neither
// is enumerated here.
func TestRealPinToolWritesExactlyTheSetTheVerifierRequires(t *testing.T) {
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	entries, err := os.ReadDir(slot.Directory)
	if err != nil {
		t.Fatal(err)
	}
	var produced []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatalf(
				"the pin tool wrote %q, which is not a regular file",
				entry.Name(),
			)
		}
		produced = append(produced, entry.Name())
	}
	required, err := anchorSlotFileSet(
		anchorSlotControllerV3, phase1anchor.KindGenesis,
	)
	if err != nil {
		t.Fatal(err)
	}
	var wanted []string
	for name := range required {
		wanted = append(wanted, name)
	}
	sort.Strings(produced)
	sort.Strings(wanted)
	if strings.Join(produced, "\n") != strings.Join(wanted, "\n") {
		t.Fatalf(
			"the real pin tool and the real verifier disagree about what an "+
				"anchor slot contains.\npin tool wrote: %v\nverifier "+
				"requires: %v\nThis is the exact disagreement that produced "+
				"the batch-meta.env P0.", produced, wanted,
		)
	}
}

// TestRealPinToolAndVerifierAgreeOnCanonicalBytes pins the byte-level half of
// the seam.
//
// Digest() and Canonical() both hash a re-marshal, so a slot whose sealed files
// carry reordered keys, duplicate keys or extra whitespace still verifies every
// signature and still digests identically — while the verifier separately
// requires the sealed bytes to BE the canonical encoding plus one newline. A
// pin tool that wrote a provider's raw output verbatim could therefore produce
// a slot that passes every cryptographic check and is still refused. This
// asserts the two agree on the bytes, not merely on the values.
func TestRealPinToolAndVerifierAgreeOnCanonicalBytes(t *testing.T) {
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	read := func(name string) []byte {
		t.Helper()
		content, err := os.ReadFile( // #nosec G304 -- fixture temp directory
			filepath.Join(slot.Directory, name),
		)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}

	// The request the pin tool sealed is byte-identical to the canonical
	// encoding of the request it was handed.
	if got := read(phase1anchor.SlotRequestName); string(got) !=
		string(slot.RequestBytes) {
		t.Fatalf(
			"the pin tool sealed request bytes that are not the canonical "+
				"encoding.\nsealed:    %q\ncanonical: %q",
			got, slot.RequestBytes,
		)
	}

	// Each sealed receipt is byte-identical to its own canonical encoding plus
	// exactly one newline — the form verifyAnchorReceipt demands.
	for _, name := range []string{
		phase1anchor.SlotProviderOneReceiptName,
		phase1anchor.SlotProviderTwoReceiptName,
	} {
		data := read(name)
		receipt, err := phase1anchor.DecodeReceipt(strings.NewReader(string(data)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		canonical, err := receipt.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != string(canonical)+"\n" {
			t.Fatalf(
				"%s is not the canonical sealed encoding; the verifier "+
					"would refuse this slot after the signatures are "+
					"irreversible.\nsealed:    %q\ncanonical: %q",
				name, data, string(canonical)+"\n",
			)
		}
	}

	// And each sidecar is byte-exact.
	//
	// Asserting only that the parsed value is non-empty was not enough, and the
	// weakness was precisely the thing this test is named for: it passed no
	// matter how much surrounding whitespace the verifier silently tolerated.
	// What has to hold is that the bytes the pin tool wrote and the bytes the
	// verifier will accept are the SAME bytes — 64 lowercase hex and one
	// newline, nothing else.
	for _, name := range []string{
		phase1anchor.SlotRequestName,
		phase1anchor.SlotProviderOneReceiptName,
		phase1anchor.SlotProviderTwoReceiptName,
	} {
		sidecar := name + phase1anchor.SlotDigestSuffix
		raw := read(sidecar)
		stored, err := readDigestFile(filepath.Join(slot.Directory, sidecar))
		if err != nil {
			t.Fatalf("%s: %v", sidecar, err)
		}
		// The sidecar records the PROTOCOL digest: the domain-separated digest
		// over the canonical request or receipt beside it, per Request.Digest
		// and Receipt.Digest. It is NOT a raw sha256 of the file's bytes, and
		// the two are not interchangeable — the sealed file also carries a
		// trailing newline, so a raw-bytes comparison would not line up even
		// before domain separation. Recomputed from the decoded artifact so
		// that a future divergence from the real protocol digest is visible
		// here rather than encoded into this test.
		expected, err := artifactDigest(t, name, read(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if stored != expected {
			t.Fatalf(
				"%s records %q, the canonical %s digests to %q",
				sidecar, stored, name, expected,
			)
		}
		// And for the request, the same value the fixture's own request
		// produces — so the sealed artifact and the request the pin tool was
		// handed are the same document, not merely two self-consistent ones.
		if name == phase1anchor.SlotRequestName {
			fromFixture, err := slot.Request.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if stored != fromFixture {
				t.Fatalf(
					"%s records %q, the request handed to the pin tool "+
						"digests to %q", sidecar, stored, fromFixture,
				)
			}
		}
		// Separately, and about a different property: the FILE's framing.
		// Its bytes are exactly the shared canonical encoding of that digest —
		// 64 lowercase hex and one newline — through the same function the pin
		// tool writes with. What the digest VALUE is and how the sidecar FILE
		// is framed are two independent guarantees and are asserted as such.
		want := phase1anchor.SidecarDigestBytes(stored)
		if !bytes.Equal(raw, want) {
			t.Fatalf(
				"%s is not the canonical sidecar encoding.\nsealed: %q\n"+
					"canonical: %q", sidecar, raw, want,
			)
		}
	}
}

// TestVerifierRefusesRealSlotsThatWereTamperedWith proves the acceptance above
// is a decision rather than a formality: the same real slot, minimally altered,
// must be refused. Without this the seam test could pass over a verifier that
// accepted anything.
func TestVerifierRefusesRealSlotsThatWereTamperedWith(t *testing.T) {
	for _, test := range []struct {
		name   string
		damage func(t *testing.T, directory string)
	}{
		{
			name: "member_removed",
			damage: func(t *testing.T, directory string) {
				if err := os.Remove(filepath.Join(
					directory, phase1anchor.SlotProviderTwoReceiptName+
						phase1anchor.SlotDigestSuffix,
				)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra_member_added",
			damage: func(t *testing.T, directory string) {
				if err := os.WriteFile(filepath.Join(
					directory, "batch-meta.env",
				), []byte("planted=1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "request_reserialised_non_canonically",
			damage: func(t *testing.T, directory string) {
				path := filepath.Join(directory, phase1anchor.SlotRequestName)
				content, err := os.ReadFile(path) // #nosec G304 -- test temp
				if err != nil {
					t.Fatal(err)
				}
				// Semantically identical, byte-different: one extra newline.
				// Every signature and every digest still matches.
				if err := os.WriteFile(
					path, append(content, '\n'), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "receipt_reserialised_non_canonically",
			damage: func(t *testing.T, directory string) {
				path := filepath.Join(
					directory, phase1anchor.SlotProviderOneReceiptName,
				)
				content, err := os.ReadFile(path) // #nosec G304 -- test temp
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(
					path, append([]byte(" "), content...), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Only the config's CLAIMED known-hosts digest is changed. It is
			// well-formed 64-lower-hex, the archived known_hosts file is
			// untouched, the signed controller state is untouched, and every
			// signature and sidecar digest still matches. The verifier holds
			// the authenticated value, so the only way this passes is if the
			// verifier declines to compare against an answer it already has.
			name: "config_claims_a_different_known_hosts_digest",
			damage: func(t *testing.T, directory string) {
				path := filepath.Join(
					directory, phase1anchor.SlotProviderConfigName,
				)
				content, err := os.ReadFile(path) // #nosec G304 -- test temp
				if err != nil {
					t.Fatal(err)
				}
				config, err := phase1anchor.DecodeSlotConfig(content)
				if err != nil {
					t.Fatal(err)
				}
				substitute := strings.Repeat("c", 64)
				if config.KnownHostsDigest == substitute {
					t.Fatal("the substituted digest equals the original")
				}
				config.KnownHostsDigest = substitute
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, sealed, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// A symbolic link whose target is ANOTHER MEMBER OF THE SAME SLOT,
			// so the entry count is unchanged and nothing escapes the slot. The
			// sidecar digest would otherwise be read out of the very artifact
			// it is supposed to describe.
			name: "member_symlinked_to_a_sibling_inside_the_slot",
			damage: func(t *testing.T, directory string) {
				sidecar := filepath.Join(
					directory,
					phase1anchor.SlotRequestName+phase1anchor.SlotDigestSuffix,
				)
				if err := os.Remove(sidecar); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					phase1anchor.SlotRequestName, sidecar,
				); err != nil {
					t.Skipf("this platform cannot create symlinks: %v", err)
				}
			},
		},
		{
			// The case the sibling link above does NOT cover, and the one that
			// matters most.
			//
			// Every byte the link points at is correct: it is a copy of the
			// member it replaces, so the content parses, verifies, digests
			// identically, and satisfies every downstream check. The sibling
			// case above is refused because request.json does not parse as a
			// digest sidecar — a SYNTAX failure that would occur with no type
			// checking at all, so it proves nothing about symlink rejection.
			//
			// Mutation evidence for this case, recorded precisely because it
			// is not what one would guess: the property is enforced three
			// times over, by os.Root refusing a component that leaves the
			// slot, by requireExactSlotMembers'"'"' per-member Lstat, and by
			// readRootRegular'"'"'s. Removing any ONE of the three leaves this
			// test green. What flips it is reverting to the pre-fix shape —
			// ambient os.ReadDir plus readSecureRegular, whose
			// filepath.EvalSymlinks FOLLOWS the link — and under that shape
			// the verifier accepts this slot. So the assertion is meaningful
			// against the defect that was actually present, and the
			// individual checks are redundant defence in depth rather than
			// three separately load-bearing controls.
			name: "member_symlinked_to_an_external_identical_copy",
			damage: func(t *testing.T, directory string) {
				name := phase1anchor.SlotProviderOneReceiptName
				path := filepath.Join(directory, name)
				content, err := os.ReadFile(path) // #nosec G304 -- test temp
				if err != nil {
					t.Fatal(err)
				}
				elsewhere := filepath.Join(t.TempDir(), "identical-copy")
				if err := os.WriteFile(
					elsewhere, content, 0o600,
				); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(elsewhere, path); err != nil {
					t.Skipf("this platform cannot create symlinks: %v", err)
				}
			},
		},
		{
			// Same principle for a special file, on a member whose downstream
			// bytes would otherwise be valid: the rejection has to come from
			// the type check, not incidentally from a parse failure.
			name: "member_replaced_by_a_fifo",
			damage: func(t *testing.T, directory string) {
				path := filepath.Join(
					directory, phase1anchor.SlotProviderTwoReceiptName,
				)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := makeFIFO(path); err != nil {
					t.Skipf("this platform cannot create a FIFO: %v", err)
				}
			},
		},
		{
			name: "member_replaced_by_directory",
			damage: func(t *testing.T, directory string) {
				path := filepath.Join(
					directory, phase1anchor.SlotProviderConfigName,
				)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			slot := anchorfixture.Produce(
				t, anchorfixture.GenesisRequest("m1"),
				phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
			)
			if _, _, _, err := verifySlotProducedByTheRealPinTool(
				t, slot, slot.Directory,
			); err != nil {
				t.Fatalf("the undamaged real slot was refused: %v", err)
			}
			test.damage(t, slot.Directory)
			if _, _, _, err := verifySlotProducedByTheRealPinTool(
				t, slot, slot.Directory,
			); err == nil {
				t.Fatal(
					"the verifier accepted a tampered slot; the acceptance " +
						"above is not a decision",
				)
			}
		})
	}
}

// TestVerifierRequiresByteCanonicalSidecarDigests covers a divergence that was
// invisible to every value-level check.
//
// The pin tool writes each *.sha256 sidecar as exactly 64 lowercase hex bytes
// and one newline, and compares exact bytes when it resumes. The verifier read
// the same file through strings.TrimSpace — so a sidecar carrying the CORRECT
// digest, padded with a leading space, a tab, an extra blank line or no
// terminating newline at all, was refused by the producer and accepted by the
// auditor. Both sides now go through one shared encoding.
func TestVerifierRequiresByteCanonicalSidecarDigests(t *testing.T) {
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	path := filepath.Join(
		slot.Directory,
		phase1anchor.SlotRequestName+phase1anchor.SlotDigestSuffix,
	)
	original, err := os.ReadFile(path) // #nosec G304 -- fixture temp path
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimSpace(string(original))

	// The control, first: the untouched slot is accepted.
	if _, _, _, err := verifySlotProducedByTheRealPinTool(
		t, slot, slot.Directory,
	); err != nil {
		t.Fatalf("the undamaged real slot was refused: %v", err)
	}

	for _, padded := range []string{
		" " + digest + "\n",
		"\t" + digest + "\n",
		digest + "\n\n",
		digest,
		digest + " \n",
		"\n" + digest + "\n",
	} {
		t.Run(fmt.Sprintf("%q", padded), func(t *testing.T) {
			if err := os.WriteFile(
				path, []byte(padded), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatal(err)
				}
			})
			// The digest itself is unchanged; only the surrounding bytes are.
			if strings.TrimSpace(padded) != digest {
				t.Fatalf(
					"this case altered the digest as well as the padding, so " +
						"it does not isolate the byte-canonical rule",
				)
			}
			if _, _, _, err := verifySlotProducedByTheRealPinTool(
				t, slot, slot.Directory,
			); err == nil {
				t.Fatalf(
					"the verifier accepted a sidecar encoded as %q; its "+
						"digest is correct and only the surrounding bytes "+
						"differ, and the pin tool that wrote the file would "+
						"refuse exactly this", padded,
				)
			}
		})
	}
}

// artifactDigest recomputes a slot artifact's own digest from its sealed bytes.
// Requests and receipts both digest a domain-separated re-marshal, so this
// decodes rather than hashing the file.
func artifactDigest(t *testing.T, name string, data []byte) (string, error) {
	t.Helper()
	if name == phase1anchor.SlotRequestName {
		request, err := phase1anchor.DecodeRequest(bytes.NewReader(data))
		if err != nil {
			return "", err
		}
		return request.Digest()
	}
	receipt, err := phase1anchor.DecodeReceipt(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return receipt.Digest()
}

// TestVerifyAnchorSlotNeverReopensAMemberByPath is a structural invariant, and
// it exists because the behavioural tests above cannot distinguish "refused
// because the member is not a regular file" from "refused because the bytes
// behind the link happened not to parse".
//
// The rule: inside verifyAnchorSlot, the slot directory is opened exactly once
// with os.OpenRoot and every member is reached through that handle. No
// filepath.Join(directory, ...), no readSecureRegular, no os.ReadDir on the
// pathname. Each of those reintroduces either symlink RESOLUTION — which
// readSecureRegular performs via filepath.EvalSymlinks, and which is not the
// same thing as symlink rejection — or a swap window between enumerating the
// set and reading the bytes.
func TestVerifyAnchorSlotNeverReopensAMemberByPath(t *testing.T) {
	source, err := os.ReadFile("anchors.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := protocolFunctionBody(string(source), "func verifyAnchorSlot(")
	if !ok {
		t.Fatal("verifyAnchorSlot is no longer present in anchors.go")
	}
	requireWholeFunctionBody(t, "verifyAnchorSlot", body)
	code := stripProtocolComments(body)

	for _, forbidden := range []struct {
		call string
		why  string
	}{
		{
			call: "filepath.Join(directory",
			why: "composes an ambient pathname for a slot member, which " +
				"reopens it outside the confined root",
		},
		{
			call: "readSecureRegular(",
			why: "resolves the member with filepath.EvalSymlinks, so a " +
				"substituted member is FOLLOWED rather than refused",
		},
		{
			call: "os.ReadDir(",
			why: "enumerates the pathname rather than the open root, which " +
				"lets the set check and the member reads describe different " +
				"directories",
		},
		{
			call: "os.Open(",
			why:  "opens a member outside the confined root",
		},
		{
			call: "EvalSymlinks",
			why:  "resolving a symbolic link is not rejecting it",
		},
		{
			call: "os.OpenRoot(",
			why: "opens the slot from an ambient pathname instead of through " +
				"the caller's already-open anchors/committed handle, which is " +
				"what let a symbolic link on a PARENT component escape the " +
				"audited matrix root",
		},
		{
			call: "os.Lstat(",
			why: "inspects an ambient pathname; the slot must be classified " +
				"through its parent descriptor so the inode checked is the " +
				"inode opened",
		},
	} {
		if strings.Contains(code, forbidden.call) {
			t.Fatalf(
				"verifyAnchorSlot uses %s, which %s:\n%s",
				forbidden.call, forbidden.why, body,
			)
		}
	}
	if !strings.Contains(code, "openConfinedSubdirectory(committed, name)") {
		t.Fatalf(
			"verifyAnchorSlot no longer opens the slot through its parent's "+
				"open handle; taking the parent as a pathname would let a "+
				"symbolic link at anchors/committed place the slot outside the "+
				"audited root:\n%s",
			body,
		)
	}
	// And the readers it delegates to must be the root-relative ones.
	for _, required := range []string{
		"requireExactSlotMembers(root",
		"readRootRegular(",
		"readRootDigestFile(",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"verifyAnchorSlot no longer calls %s:\n%s", required, body,
			)
		}
	}
}
