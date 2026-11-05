// Adopting an incumbent committed anchor slot.
//
// When a run is interrupted after the providers have signed, the controller
// restarts and finds a committed slot already there. Adopting it is the only
// way to resume without asking two external providers to sign a second,
// conflicting statement about the same ordinal — so the adoption path has to be
// exactly as strict as the audit that comes later. Anything it accepts and the
// formal verifier refuses is a run that anchors successfully and then fails
// verification, with the receipts already irreversible.
//
// The slots here are produced by the REAL winn-phase1-anchor-pin binary, for
// the same reason the verifier's seam test is: a hand-built fixture only ever
// proves that this code agrees with whoever wrote the fixture.
package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/anchorfixture"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// runnerForSlot wires a pinAnchorRunner to the fixture's provider identities and
// frozen keys, so verifyIncumbent runs on its production path.
func runnerForSlot(slot *anchorfixture.Slot) *pinAnchorRunner {
	runner := &pinAnchorRunner{
		providerOneID: slot.ProviderOneID,
		providerTwoID: slot.ProviderTwoID,
		providerOne:   slot.ProviderOneHost,
		providerTwo:   slot.ProviderTwoHost,
	}
	runner.UseFrozenTrust(frozenTrust{
		providerOneKey: []byte(
			base64.StdEncoding.EncodeToString(slot.ProviderOnePublic) + "\n",
		),
		providerTwoKey: []byte(
			base64.StdEncoding.EncodeToString(slot.ProviderTwoPublic) + "\n",
		),
		// The controller holds the frozen known-hosts bytes, so the sealed
		// configuration's digest is checked for EQUALITY rather than shape.
		knownHosts: slot.KnownHosts,
	})
	return runner
}

func realIncumbent(t *testing.T) (*pinAnchorRunner, *anchorfixture.Slot) {
	t.Helper()
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	return runnerForSlot(slot), slot
}

func adopt(
	runner *pinAnchorRunner, slot *anchorfixture.Slot,
) (Receipts, error) {
	return runner.verifyIncumbent(
		slot.Directory, slot.Request, slot.PreviousOne, slot.PreviousTwo,
	)
}

// TestControllerAdoptsARealPinProducedSlot is the control: the adoption path
// must accept what the real pin tool actually writes. Every refusal below is
// only meaningful against this.
func TestControllerAdoptsARealPinProducedSlot(t *testing.T) {
	runner, slot := realIncumbent(t)
	receipts, err := adopt(runner, slot)
	if err != nil {
		t.Fatalf(
			"the controller refused an incumbent the real pin tool produced: %v",
			err,
		)
	}
	if receipts.RequestSHA256 == "" ||
		receipts.ProviderOneSHA25 == "" || receipts.ProviderTwoSHA25 == "" {
		t.Fatalf("adoption returned empty digests: %+v", receipts)
	}
	if receipts.ProviderOneSHA25 == receipts.ProviderTwoSHA25 {
		t.Fatal("both provider receipts digest identically")
	}
}

// TestControllerRequiresTheExactSlotSet covers the subset match that used to be
// here.
//
// The previous version opened only the four files it happened to name, so a
// slot missing its provider-config, or carrying an extra planted file, was
// adopted as complete — while the formal verifier this controller exists to
// satisfy demands set equality and refuses exactly those slots. The two now
// consult one definition, so this asserts that behaviour rather than a second
// copy of the list.
func TestControllerRequiresTheExactSlotSet(t *testing.T) {
	for _, name := range phase1anchor.SlotArtifactNames() {
		t.Run("missing_"+name, func(t *testing.T) {
			runner, slot := realIncumbent(t)
			if err := os.Remove(
				filepath.Join(slot.Directory, name),
			); err != nil {
				t.Fatal(err)
			}
			_, err := adopt(runner, slot)
			if err == nil {
				t.Fatalf(
					"a slot missing %s was adopted as a complete anchor", name,
				)
			}
			if !strings.Contains(err.Error(), "complete anchor slot") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
	t.Run("extra_member", func(t *testing.T) {
		runner, slot := realIncumbent(t)
		// batch-meta.env specifically: the legacy-profile artifact whose
		// absence from the pin tool's output was the original P0. Under the
		// controller-deferred profile it does not belong in a slot at all.
		if err := os.WriteFile(
			filepath.Join(slot.Directory, "batch-meta.env"),
			[]byte("planted=1\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := adopt(runner, slot); err == nil {
			t.Fatal("a slot carrying an extra member was adopted")
		}
	})
}

// TestControllerValidatesTheSealedProviderConfiguration covers a file that used
// to be required by NAME and never read.
//
// The formal verifier checks the sealed configuration's schema, provider
// identities, key IDs, predecessor links, host distinctness and known-hosts
// digest. The controller checked none of it — so an incumbent produced for a
// different provider pair, under a different signing key, or chained to
// different predecessors was adopted, every later anchor was chained onto it,
// and the disagreement surfaced only when the auditor refused the finished
// matrix with the receipts already irreversible.
func TestControllerValidatesTheSealedProviderConfiguration(t *testing.T) {
	// A configuration belonging to a genuinely DIFFERENT run: produced by the
	// real pin tool, with its own providers, keys and known-hosts file. It is
	// internally consistent and canonically encoded — the only thing wrong with
	// it is that it does not describe this run.
	foreign := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m2"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	foreignConfig, err := os.ReadFile( // #nosec G304 -- fixture temp path
		filepath.Join(foreign.Directory, phase1anchor.SlotProviderConfigName),
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		rewrite func(t *testing.T, original []byte) []byte
		want    string
		// expectHosts, when set, substitutes the runner's own provider
		// addresses so that a case can isolate one check from the others.
		expectHosts [2]string
	}{
		{
			name: "malformed",
			rewrite: func(_ *testing.T, _ []byte) []byte {
				return []byte("{not json at all\n")
			},
		},
		{
			name: "truncated",
			rewrite: func(_ *testing.T, original []byte) []byte {
				return original[:len(original)/2]
			},
		},
		{
			name: "unknown_field",
			rewrite: func(_ *testing.T, original []byte) []byte {
				return append(
					[]byte(`{"planted":1,`), original[1:]...,
				)
			},
		},
		{
			name: "foreign_run",
			rewrite: func(_ *testing.T, _ []byte) []byte {
				return foreignConfig
			},
		},
		{
			name: "non_canonical_bytes",
			rewrite: func(_ *testing.T, original []byte) []byte {
				// Semantically identical, byte-different. Every field decodes
				// to exactly the right value.
				return append(append([]byte(" "), original...), '\n')
			},
			want: "canonical sealed encoding",
		},
		{
			name: "wrong_schema",
			rewrite: func(t *testing.T, original []byte) []byte {
				config, err := phase1anchor.DecodeSlotConfig(original)
				if err != nil {
					t.Fatal(err)
				}
				config.Schema = "winn-phase1-anchor-pending-config/v2"
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				return sealed
			},
			want: "schema",
		},
		{
			name: "wrong_known_hosts_digest",
			rewrite: func(t *testing.T, original []byte) []byte {
				config, err := phase1anchor.DecodeSlotConfig(original)
				if err != nil {
					t.Fatal(err)
				}
				config.KnownHostsDigest = strings.Repeat("c", 64)
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				return sealed
			},
			want: "known-hosts",
		},
		{
			// Two hosts that are non-empty and distinct from each other, so
			// the distinctness check is satisfied — and that are not the
			// providers this run actually contacted. Distinctness alone says
			// only that a configuration is not self-contradictory.
			name: "wrong_but_distinct_hosts",
			rewrite: func(t *testing.T, original []byte) []byte {
				config, err := phase1anchor.DecodeSlotConfig(original)
				if err != nil {
					t.Fatal(err)
				}
				config.ProviderOneHost = "198.51.100.7"
				config.ProviderTwoHost = "198.51.100.8"
				if config.ProviderOneHost == config.ProviderTwoHost {
					t.Fatal("the substituted hosts are not distinct")
				}
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				return sealed
			},
			want: "this run uses",
		},
		{
			// Two hostnames: well-formed, non-empty, distinct from each other,
			// and — because the runner's own hosts are substituted to match
			// them — equal to what this consumer expects. Every check except
			// well-formedness passes. winn-phase1-anchor-pin refuses anything
			// but a literal IP, so a configuration recording a name was never
			// written by it, whoever is reading it.
			name: "hosts_are_names_not_addresses",
			rewrite: func(t *testing.T, original []byte) []byte {
				config, err := phase1anchor.DecodeSlotConfig(original)
				if err != nil {
					t.Fatal(err)
				}
				config.ProviderOneHost = "provider-one.example"
				config.ProviderTwoHost = "provider-two.example"
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				return sealed
			},
			// The runner is pointed at the same names, so the expected-host
			// equality check is satisfied and only the IP parse can refuse it.
			expectHosts: [2]string{
				"provider-one.example", "provider-two.example",
			},
			want: "not an IP address",
		},
		{
			name: "hosts_collapsed_to_one",
			rewrite: func(t *testing.T, original []byte) []byte {
				config, err := phase1anchor.DecodeSlotConfig(original)
				if err != nil {
					t.Fatal(err)
				}
				config.ProviderTwoHost = config.ProviderOneHost
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				return sealed
			},
			want: "same host",
		},
		{
			name: "predecessor_rewritten",
			rewrite: func(t *testing.T, original []byte) []byte {
				config, err := phase1anchor.DecodeSlotConfig(original)
				if err != nil {
					t.Fatal(err)
				}
				config.ProviderOnePrior = strings.Repeat("9", 64)
				sealed, err := config.SealedBytes()
				if err != nil {
					t.Fatal(err)
				}
				return sealed
			},
			want: "predecessor",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner, slot := realIncumbent(t)
			if test.expectHosts[0] != "" {
				runner.providerOne = test.expectHosts[0]
				runner.providerTwo = test.expectHosts[1]
			}
			path := filepath.Join(
				slot.Directory, phase1anchor.SlotProviderConfigName,
			)
			original, err := os.ReadFile(path) // #nosec G304 -- test temp path
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				path, test.rewrite(t, original), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			_, err = adopt(runner, slot)
			if err == nil {
				t.Fatal(
					"the controller adopted an incumbent whose sealed " +
						"provider configuration it never validated",
				)
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestControllerRefusesUnsafeSlotMembers proves a slot member that is not a
// regular file is refused. os.ReadFile followed symbolic links and happily read
// a FIFO or a device node; nothing here does.
//
// What this test does NOT prove, stated because the opposite would be easy to
// assume: it does not isolate the explicit Mode().IsRegular() checks. Three
// mechanisms refuse these cases independently — os.Root's confinement (for a
// link whose target leaves the slot), the Lstat-versus-descriptor os.SameFile
// comparison (for any link, since Lstat sees the link and Open sees the target),
// and the type checks themselves. Deleting the type checks alone leaves every
// case below still refused, by a worse error message.
//
// The type checks are therefore defence in depth and better diagnostics, not
// the load-bearing control, and they are recorded as such rather than credited
// with a property the mutation evidence does not support.
func TestControllerRefusesUnsafeSlotMembers(t *testing.T) {
	for _, test := range []struct {
		name    string
		replace func(t *testing.T, path string)
	}{
		{
			name: "symlink_to_a_valid_copy",
			replace: func(t *testing.T, path string) {
				// The link target holds byte-identical content, so only the
				// TYPE of the member is wrong. A check that read the bytes and
				// compared them would pass.
				content, err := os.ReadFile(path) // #nosec G304 -- test temp
				if err != nil {
					t.Fatal(err)
				}
				elsewhere := filepath.Join(t.TempDir(), "copy")
				if err := os.WriteFile(elsewhere, content, 0o600); err != nil {
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
			name: "directory",
			replace: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// A link whose target is another member of the SAME slot, so
			// os.Root's confinement permits it and the entry count is
			// unchanged. It is refused by the Lstat-versus-descriptor
			// os.SameFile comparison — Lstat sees the link, Open sees the
			// target — with the explicit type check behind that.
			name: "symlink_to_a_sibling_inside_the_slot",
			replace: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				sibling := phase1anchor.SlotProviderConfigName
				if filepath.Base(path) == sibling {
					sibling = phase1anchor.SlotRequestName
				}
				if err := os.Symlink(sibling, path); err != nil {
					t.Skipf("this platform cannot create symlinks: %v", err)
				}
			},
		},
	} {
		for _, member := range []string{
			phase1anchor.SlotRequestName,
			phase1anchor.SlotProviderOneReceiptName,
			phase1anchor.SlotRequestName + phase1anchor.SlotDigestSuffix,
		} {
			t.Run(test.name+"_"+member, func(t *testing.T) {
				runner, slot := realIncumbent(t)
				test.replace(t, filepath.Join(slot.Directory, member))
				if _, err := adopt(runner, slot); err == nil {
					t.Fatalf(
						"the controller adopted a slot whose %s is not a "+
							"regular file", member,
					)
				}
			})
		}
	}
}

// TestControllerRequiresByteCanonicalSlotContents covers the TrimSpace
// comparison that used to be here.
//
// Canonical() and Digest() both hash a re-marshal, so leading and trailing
// whitespace compare equal under TrimSpace AND digest identically. A slot
// altered this way passed the old adoption check and is refused by the formal
// verifier, which requires the sealed bytes to be exactly the canonical
// encoding plus one newline.
func TestControllerRequiresByteCanonicalSlotContents(t *testing.T) {
	for _, test := range []struct {
		name   string
		member string
		mangle func([]byte) []byte
	}{
		{
			name:   "request_trailing_newline",
			member: phase1anchor.SlotRequestName,
			mangle: func(data []byte) []byte { return append(data, '\n') },
		},
		{
			name:   "request_leading_space",
			member: phase1anchor.SlotRequestName,
			mangle: func(data []byte) []byte {
				return append([]byte(" "), data...)
			},
		},
		{
			name:   "receipt_trailing_newline",
			member: phase1anchor.SlotProviderOneReceiptName,
			mangle: func(data []byte) []byte { return append(data, '\n') },
		},
		{
			name:   "receipt_leading_space",
			member: phase1anchor.SlotProviderTwoReceiptName,
			mangle: func(data []byte) []byte {
				return append([]byte(" "), data...)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner, slot := realIncumbent(t)
			path := filepath.Join(slot.Directory, test.member)
			content, err := os.ReadFile(path) // #nosec G304 -- test temp path
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				path, test.mangle(content), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := adopt(runner, slot); err == nil {
				t.Fatalf(
					"the controller adopted a slot whose %s is not the "+
						"canonical sealed encoding; the formal verifier "+
						"refuses exactly this slot", test.member,
				)
			}
		})
	}
}

// TestControllerBoundsSlotMemberReads proves an oversize member is refused
// rather than read.
func TestControllerBoundsSlotMemberReads(t *testing.T) {
	runner, slot := realIncumbent(t)
	path := filepath.Join(slot.Directory, phase1anchor.SlotRequestName)
	oversize := make([]byte, 64<<10+1)
	for index := range oversize {
		oversize[index] = ' '
	}
	if err := os.WriteFile(path, oversize, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := adopt(runner, slot)
	if err == nil {
		t.Fatal("an oversize slot member was accepted")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestControllerRefusesASlotThatIsNotARealDirectory covers the container
// itself: a root opened on a symbolic link is a root somewhere else.
func TestControllerRefusesASlotThatIsNotARealDirectory(t *testing.T) {
	runner, slot := realIncumbent(t)
	link := filepath.Join(t.TempDir(), "committed-slot")
	if err := os.Symlink(slot.Directory, link); err != nil {
		t.Skipf("this platform cannot create symlinks: %v", err)
	}
	if _, err := runner.verifyIncumbent(
		link, slot.Request, slot.PreviousOne, slot.PreviousTwo,
	); err == nil {
		t.Fatal("a symbolic link was adopted as a committed anchor slot")
	}
}

// TestSetValidationAndReadsCannotDescribeDifferentDirectories closes the
// directory-swap window between the two halves of adoption.
//
// The set check and the artifact reads answer different questions about the
// same directory, and they are only meaningful together. If the set check
// listed the PATHNAME while the reads went through an already-open ROOT, a
// rename landing between them would let the check describe a replacement
// directory and the reads take their bytes from the original — so a slot could
// be certified complete on the strength of a directory none of its contents
// came from.
//
// The window is a race and cannot be triggered on demand, so this asserts the
// structural property instead: the enumeration is performed on the root
// descriptor. Renaming the whole slot away after the root is open must leave
// adoption entirely unaffected, because at that point no pathname is consulted
// again.
func TestSetValidationAndReadsCannotDescribeDifferentDirectories(t *testing.T) {
	runner, slot := realIncumbent(t)

	// The decoy must produce a DIFFERENT verdict from the real slot, or this
	// test cannot tell the two enumerations apart. It therefore carries all
	// seven expected names — so it is a plausible slot — plus one extra member,
	// which the exact-set rule refuses. A descriptor-based enumeration reports
	// success (it is looking at the real slot); a pathname-based one reports
	// the extra member (it is looking at the decoy).
	decoy := filepath.Join(filepath.Dir(slot.Directory), "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range phase1anchor.SlotArtifactNames() {
		if err := os.WriteFile(
			filepath.Join(decoy, name), []byte("planted\n"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(decoy, "planted-extra"), []byte("x\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	// The premise, stated rather than assumed: the decoy really is refused when
	// it IS the directory under examination.
	decoyRoot, err := openSlotRoot(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireExactSlotSet(decoyRoot); err == nil {
		t.Fatal(
			"the decoy passes the exact-set check, so this test cannot " +
				"distinguish a pathname enumeration from a descriptor one",
		)
	}
	if err := decoyRoot.Close(); err != nil {
		t.Fatal(err)
	}

	root, err := openSlotRoot(slot.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := requireExactSlotSet(root); err != nil {
		t.Fatalf("the real slot was refused before any swap: %v", err)
	}

	// Swap the decoy onto the pathname the root was opened from. A
	// pathname-based enumeration now describes the decoy; a descriptor-based
	// one still describes the real slot.
	moved := filepath.Join(filepath.Dir(slot.Directory), "moved-away")
	if err := os.Rename(slot.Directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(decoy, slot.Directory); err != nil {
		t.Fatal(err)
	}

	if err := requireExactSlotSet(root); err != nil {
		t.Fatalf(
			"the set check followed the pathname rather than the open root, "+
				"so it described a directory the artifact reads never touch: %v",
			err,
		)
	}
	// And the artifacts read through that same root are still the real ones.
	content, err := readSlotArtifact(root, phase1anchor.SlotRequestName, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) == "planted\n" {
		t.Fatal("the read followed the pathname into the decoy")
	}
	if string(content) != string(slot.RequestBytes) {
		t.Fatalf("the read returned unexpected content: %q", content)
	}

	// Whole-path adoption is likewise unaffected once the root is open, because
	// verifyIncumbent opens the root first and consults nothing else by name.
	if err := os.Rename(slot.Directory, decoy); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, slot.Directory); err != nil {
		t.Fatal(err)
	}
	if _, err := adopt(runner, slot); err != nil {
		t.Fatalf("the restored real slot was refused: %v", err)
	}
}

// TestProviderHostsAreValidatedBeforeAnyIncumbentWork closes the asymmetry
// between the two anchor paths.
//
// winn-phase1-anchor-pin validates its host arguments itself — present,
// distinct, parsable as IP addresses — but the incumbent branch never invokes
// it. A resume therefore reached adoption with host configuration nothing had
// checked, and the sealed configuration's host comparison was made against
// runner values that were themselves unvalidated. Matching an unvalidated
// expectation proves nothing.
//
// Asserting that "an error eventually surfaces" would not be enough: the point
// is that the refusal happens BEFORE any incumbent is examined. So the ordering
// is observed directly — the committed root is made un-statable, which produces
// a distinctive error of its own, and the host failure must still be the one
// reported.
func TestProviderHostsAreValidatedBeforeAnyIncumbentWork(t *testing.T) {
	slot := anchorfixture.Produce(
		t, anchorfixture.GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	request, err := slot.Request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	request = append(request, '\n')

	// A committed root whose Lstat cannot succeed: a path UNDER a regular file,
	// which yields ENOTDIR. If any incumbent work ran first, the error would
	// name that instead.
	notADirectory := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(
		notADirectory, []byte("x\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	unstattable := filepath.Join(notADirectory, "committed")

	for _, test := range []struct {
		name string
		one  string
		two  string
		want string
	}{
		{name: "both_missing", one: "", two: "", want: "both anchor provider hosts"},
		{name: "first_missing", one: "", two: "127.0.0.2",
			want: "both anchor provider hosts"},
		{name: "second_missing", one: "127.0.0.1", two: "",
			want: "both anchor provider hosts"},
		{name: "identical", one: "127.0.0.1", two: "127.0.0.1",
			want: "share a host"},
		{name: "not_an_ip", one: "provider-one.example", two: "127.0.0.2",
			want: "not an IP address"},
		{name: "hostname_pair", one: "one.example", two: "two.example",
			want: "not an IP address"},
		{name: "partial_ip", one: "127.0.0", two: "127.0.0.2",
			want: "not an IP address"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := runnerForSlot(slot)
			runner.providerOne = test.one
			runner.providerTwo = test.two
			runner.committedRoot = unstattable
			runner.pendingRoot = t.TempDir()

			_, err := runner.Anchor(
				"000000-genesis", request,
				slot.PreviousOne, slot.PreviousTwo,
			)
			if err == nil {
				t.Fatal("the anchor step ran with invalid provider hosts")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			// The committed-root lookup would have produced this instead, so
			// its absence is what proves the ordering.
			if strings.Contains(
				err.Error(), "cannot determine whether anchor slot",
			) {
				t.Fatalf(
					"incumbent work ran before the hosts were validated: %v",
					err,
				)
			}
		})
	}

	// The control: with valid, distinct hosts the same call proceeds past the
	// host check and fails on the committed-root lookup instead. Without this,
	// every case above could be satisfied by a runner that refused everything.
	runner := runnerForSlot(slot)
	runner.committedRoot = unstattable
	runner.pendingRoot = t.TempDir()
	_, err = runner.Anchor(
		"000000-genesis", request, slot.PreviousOne, slot.PreviousTwo,
	)
	if err == nil {
		t.Fatal("the control run unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "cannot determine whether anchor slot") {
		t.Fatalf(
			"valid hosts did not reach the committed-slot lookup, so the "+
				"cases above may be passing for an unrelated reason: %v", err,
		)
	}
}

// TestPendingDirectoryMustBeARealPrivateDirectory covers the pre-anchor side.
// os.MkdirAll reports success when the name already exists as a symbolic link
// to a directory, so the pin tool would have written the slot somewhere else
// entirely and this process would then have committed that link.
func TestPendingDirectoryMustBeARealPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "pending")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("this platform cannot create symlinks: %v", err)
	}
	// MkdirAll is content with this, which is the whole problem.
	if err := os.MkdirAll(link, 0o700); err != nil {
		t.Fatalf("MkdirAll refused a symlinked directory: %v", err)
	}
	if err := requirePrivateRealDirectory(link); err == nil {
		t.Fatal("a symbolic link was accepted as the pending directory")
	}

	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := requirePrivateRealDirectory(real); err != nil {
		t.Fatalf("a real private directory was refused: %v", err)
	}
	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := requirePrivateRealDirectory(real); err == nil {
		t.Fatal("a world-writable pending directory was accepted")
	}
}

// TestPendingRequestReadIsHardened covers the resume comparison. os.ReadFile
// followed a symbolic link planted at the pending request name and was
// unbounded, so the "is this the same request" comparison could have been made
// against a file the controller never wrote.
func TestPendingRequestReadIsHardened(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "request.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this platform cannot create symlinks: %v", err)
	}
	if _, err := readBoundedRegularFile(link, 64<<10); err == nil {
		t.Fatal("a symbolic link was read as the pending request")
	}

	oversize := filepath.Join(base, "big.json")
	if err := os.WriteFile(
		oversize, make([]byte, 1025), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegularFile(oversize, 1024); err == nil {
		t.Fatal("an oversize pending request was read")
	}
	if content, err := readBoundedRegularFile(target, 64<<10); err != nil ||
		string(content) != "{}" {
		t.Fatalf("a regular file was not read: %q %v", content, err)
	}
}
