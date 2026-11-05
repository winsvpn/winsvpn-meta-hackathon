// The matrix root's own confinement, not just the slot's.
//
// verifyAnchorSlot has confined the FINAL slot directory for a while. That was
// never enough: verifyAnchorChain still composed anchors, anchors/pending and
// anchors/committed as ambient pathnames and handed them to os.ReadDir,
// loadAnchorPublicKey and sha256File, all of which follow symbolic links on
// every component. A link at any one of those three names was FOLLOWED before
// the final Lstat ever ran, so the committed slots, the archived provider keys
// and the known-hosts file could live entirely outside the root the auditor
// believes it audited, and the verifier still reported PASS.
//
// The tests here are about the components ABOVE the slot.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// moveAside relocates a path and leaves a symbolic link behind in its place,
// which is exactly the substitution these tests are about.
//
// The link is written RELATIVE whenever the target is a sibling, and that is
// load-bearing rather than tidy. os.Root refuses every ABSOLUTE symlink outright
// — "path escapes from parent" — even one whose target is inside the root, so a
// test built on absolute links would be satisfied by containment alone and would
// say nothing about whether this code refuses links. A relative sibling link is
// exactly the case os.Root FOLLOWS, so it is the case that isolates the
// explicit refusal.
func moveAside(t *testing.T, original, destination string) {
	t.Helper()
	if err := os.Rename(original, destination); err != nil {
		t.Fatal(err)
	}
	target := destination
	if filepath.Dir(destination) == filepath.Dir(original) {
		target = filepath.Base(destination)
	}
	if err := os.Symlink(target, original); err != nil {
		t.Fatal(err)
	}
}

// TestVerifierRefusesSymlinkedAnchorParentComponents is the behavioural half of
// the fix.
//
// Two escape shapes are covered for each of the three components, and they are
// NOT redundant — they fail for different reasons and are detected by different
// mutations:
//
//   - OUTSIDE the matrix root, via an absolute link. This is the real-world
//     attack: the sealed evidence the auditor holds contains a link, and the
//     bytes that satisfy it are somewhere else on the machine entirely. Once the
//     component is opened through a descriptor, os.Root refuses this on its own,
//     so this case flips only under the genuine pre-fix shape (ambient
//     filepath.Join plus os.ReadDir/sha256File/loadAnchorPublicKey).
//   - INSIDE the matrix root, via a RELATIVE link to a sibling. Containment does
//     NOT refuse this — it is the one symlink shape os.Root follows — so only
//     the explicit refusal in openConfinedSubdirectory rejects it. This case is
//     the one that independently proves the refusal is present, and it is why
//     moveAside writes relative links for siblings.
func TestVerifierRefusesSymlinkedAnchorParentComponents(t *testing.T) {
	for _, component := range []struct {
		name     string
		relative string
	}{
		{"anchors", "anchors"},
		{"anchors_pending", filepath.Join("anchors", "pending")},
		{"anchors_committed", filepath.Join("anchors", "committed")},
	} {
		for _, placement := range []struct {
			name    string
			outside bool
		}{
			{"target_outside_the_matrix_root", true},
			{"target_inside_the_matrix_root", false},
		} {
			t.Run(component.name+"/"+placement.name, func(t *testing.T) {
				fixture := newMatrixRootFixture(t, true)
				// The fixture has to be sound first, or a refusal below would
				// prove nothing about the substitution.
				if err := fixture.verify(fixture.root); err != nil {
					t.Fatalf("the intact sealed root did not verify: %v", err)
				}
				original := filepath.Join(fixture.root, component.relative)
				destination := filepath.Join(
					t.TempDir(), filepath.Base(component.relative)+"-elsewhere",
				)
				if !placement.outside {
					destination = original + "-elsewhere"
				}
				moveAside(t, original, destination)

				err := fixture.verify(fixture.root)
				if err == nil {
					t.Fatalf(
						"the verifier certified a matrix whose %s is a symbolic "+
							"link to %s; the committed anchor state it read is "+
							"not the state this root contains",
						component.relative, destination,
					)
				}
				// The refusal has to be the component check, not some later
				// consequence of it. Every one of these strings is produced by
				// verifyAnchorChain's own descent.
				if !strings.Contains(err.Error(), "anchor root") &&
					!strings.Contains(err.Error(), "anchor pending directory") &&
					!strings.Contains(err.Error(), "committed anchors") {
					t.Fatalf("refused for the wrong reason: %v", err)
				}
			})
		}
	}
}

// TestVerifierRefusesSymlinkedArchivedAnchorFiles covers the FILES that hang off
// the anchors directory rather than the directories themselves.
//
// These went through loadAnchorPublicKey/sha256File/readSecureRegular, all of
// which call filepath.EvalSymlinks. A link here was resolved and the target
// hashed, so the digest bound into every slot check described a file the
// evidence does not contain.
func TestVerifierRefusesSymlinkedArchivedAnchorFiles(t *testing.T) {
	for _, name := range []string{
		"provider-one.ed25519.pub",
		"provider-two.ed25519.pub",
		"known_hosts",
		"terminal-aggregate.list",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newMatrixRootFixture(t, true)
			if err := fixture.verify(fixture.root); err != nil {
				t.Fatalf("the intact sealed root did not verify: %v", err)
			}
			original := filepath.Join(fixture.root, "anchors", name)
			// Deliberately byte-identical, and deliberately inside the audited
			// root. Content-based checks cannot tell the difference; only
			// refusing the link can, and containment does not refuse a target
			// that never leaves the root.
			destination := original + "-elsewhere"
			moveAside(t, original, destination)

			if err := fixture.verify(fixture.root); err == nil {
				t.Fatalf(
					"the verifier accepted anchors/%s as a symbolic link to a "+
						"byte-identical copy; the sealed root does not contain "+
						"the artifact it was certified on", name,
				)
			}
		})
	}
}

// TestAnchorChainNeverReachesTheAnchorSubtreeByPathname is the structural half.
//
// It exists for the same reason the equivalent invariant on verifyAnchorSlot
// does: a behavioural refusal cannot distinguish "refused because the component
// is a link" from "refused because whatever was behind the link failed a later
// check". The rule is that the anchor subtree is reached only through
// descriptors descended from the matrix root.
func TestAnchorChainNeverReachesTheAnchorSubtreeByPathname(t *testing.T) {
	source, err := os.ReadFile("anchors.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := protocolFunctionBody(string(source), "func verifyAnchorChain(")
	if !ok {
		t.Fatal("verifyAnchorChain is no longer present in anchors.go")
	}
	requireWholeFunctionBody(t, "verifyAnchorChain", body)
	code := stripProtocolComments(body)

	for _, forbidden := range []struct {
		call string
		why  string
	}{
		{
			call: `filepath.Join(root, "anchors"`,
			why: "composes the anchor root as an ambient pathname, so every " +
				"component below it is resolved rather than confined",
		},
		{
			call: "filepath.Join(anchorRoot",
			why: "composes a path under the anchor root, which follows a " +
				"symbolic link at anchors before anything type-checks it",
		},
		{
			call: "filepath.Join(committed",
			why: "composes a slot path, which follows a symbolic link at " +
				"anchors/committed and puts the slots outside the audited root",
		},
		{
			call: "os.ReadDir(",
			why: "enumerates a pathname rather than an open descriptor, so " +
				"the enumeration and the reads can describe different inodes",
		},
		{
			call: "EvalSymlinks",
			why:  "resolving a symbolic link is not rejecting it",
		},
		{
			call: "readSecureRegular(",
			why:  "resolves its argument with filepath.EvalSymlinks",
		},
		{
			call: "sha256File(filepath.Join(anchorRoot",
			why:  "hashes an anchor artifact through a resolved ambient path",
		},
		{
			call: "loadAnchorPublicKey(filepath.Join",
			why: "reads an ARCHIVED provider key by pathname; the archived " +
				"copies are matrix content and must come through the " +
				"confined anchor root, unlike the auditor's own trust roots",
		},
	} {
		if strings.Contains(code, forbidden.call) {
			t.Fatalf(
				"verifyAnchorChain uses %s, which %s:\n%s",
				forbidden.call, forbidden.why, body,
			)
		}
	}
	for _, required := range []string{
		"os.OpenRoot(root)",
		`openConfinedSubdirectory(matrixRoot, "anchors")`,
		`openConfinedSubdirectory(anchorRoot, "pending")`,
		`openConfinedSubdirectory(anchorRoot, "committed")`,
		"readConfinedDirectory(",
		"loadRootAnchorPublicKey(",
		"sha256RootRegular(",
		"readRootRegular(",
	} {
		if !strings.Contains(code, required) {
			t.Fatalf(
				"verifyAnchorChain no longer calls %s, so some part of the "+
					"anchor subtree is reached outside the confined "+
					"descent:\n%s", required, body,
			)
		}
	}
}

// TestCommittedDirectorySwapCannotMixGenerations is the parent-swap stress test.
//
// A descriptor on anchors/committed makes a rename over that NAME irrelevant to
// the reads already going through it. A pathname does not: the exact-count
// enumeration would describe one directory and the per-slot reads another.
//
// The decoy is a complete copy of the anchor subtree whose committed/ is EMPTY,
// which gives the two consistent outcomes distinct, recognisable signatures:
//
//	real tree throughout   -> PASS
//	decoy tree throughout  -> "matrix has 0 committed anchor slots, want N"
//
// A mid-chain slot-absence error ("anchor slot is absent or unsafe" reached
// under "anchor genesis"/"anchor batch"/"terminal anchor seal") is reachable
// ONLY if the count was taken from one directory and the slots from another, so
// it is the signature this test forbids. Under the confined descent it cannot
// occur; under an ambient filepath.Join plus os.ReadDir it can.
//
// The renamer has an unavoidable window in which the name does not exist at all
// — POSIX rename cannot replace a non-empty directory atomically — so ENOENT is
// an accepted consistent outcome too. It is not a mixed read: it happens before
// any descriptor is held.
func TestCommittedDirectorySwapCannotMixGenerations(t *testing.T) {
	fixture := newMatrixRootFixture(t, true)
	if err := fixture.verify(fixture.root); err != nil {
		t.Fatalf("the intact sealed root did not verify: %v", err)
	}
	anchors := filepath.Join(fixture.root, "anchors")
	committed := filepath.Join(anchors, "committed")
	decoy := filepath.Join(anchors, "committed-decoy")
	spare := filepath.Join(anchors, "committed-spare")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}

	// Deterministic bracket FIRST, so both consistent signatures are proved
	// reachable and proved to be what the loop below assumes. An earlier
	// version asserted these by requiring the racing loop to observe each
	// outcome at least once, which made the test depend on the scheduler: an
	// unlucky or simply biased run could starve one side, and the test would
	// then either fail for no reason or pass while exercising nothing.
	if err := fixture.verify(fixture.root); err != nil {
		t.Fatalf("the real committed directory did not verify: %v", err)
	}
	if err := os.Rename(committed, spare); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(decoy, committed); err != nil {
		t.Fatal(err)
	}
	decoyErr := fixture.verify(fixture.root)
	if decoyErr == nil ||
		!strings.Contains(decoyErr.Error(), "committed anchor slots, want") {
		t.Fatalf(
			"the empty decoy did not produce the expected count refusal: %v",
			decoyErr,
		)
	}
	if err := os.Rename(committed, decoy); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(spare, committed); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Three renames, because a non-empty directory cannot be replaced
			// in one step. Errors are ignored deliberately: the loser of a
			// partially applied cycle simply retries.
			if os.Rename(committed, spare) != nil {
				continue
			}
			_ = os.Rename(decoy, committed)
			_ = os.Rename(spare, decoy)
		}
	}()

	forbidden := []string{
		"anchor genesis",
		"anchor batch",
		"terminal anchor seal",
	}
	var passes, empties, absent int
	for attempt := 0; attempt < 400; attempt++ {
		err := fixture.verify(fixture.root)
		if err == nil {
			passes++
			continue
		}
		message := err.Error()
		for _, signature := range forbidden {
			if strings.Contains(message, signature) {
				close(stop)
				swapper.Wait()
				t.Fatalf(
					"attempt %d read the committed slot set from one directory "+
						"and a slot from another: %v", attempt, err,
				)
			}
		}
		switch {
		case strings.Contains(message, "committed anchor slots, want"):
			empties++
		case strings.Contains(message, "committed anchors"):
			// The name did not exist, or was not a directory, at the moment
			// the descent reached it. Consistent, and never a mixed read.
			absent++
		default:
			close(stop)
			swapper.Wait()
			t.Fatalf("attempt %d failed in an unexpected way: %v", attempt, err)
		}
	}
	close(stop)
	swapper.Wait()
	// No coverage assertion on the racing loop, deliberately. Requiring it to
	// observe both sides makes the result depend on the scheduler, and a
	// scheduler that consistently favours one side would turn this into a
	// flaky failure rather than a finding. The deterministic bracket above
	// proves both signatures are reachable; the invariant proved HERE is the
	// negative one, and a negative invariant does not need the loop to have
	// covered any particular distribution to be meaningful.
	//
	// The property this loop can genuinely be starved of is CONFIDENCE, not
	// correctness, so the distribution is reported rather than asserted.
	t.Logf(
		"swap stress: %d real-tree passes, %d decoy counts, %d absent",
		passes, empties, absent,
	)
}

// TestConfinedHandleIgnoresALaterParentSwap is the deterministic proof that the
// stress loop above can only sample.
//
// It exercises the guarantee directly: once openConfinedSubdirectory has
// returned, the caller holds a descriptor, and renaming an entirely different
// directory over that NAME cannot change which inode its reads reach. That is
// the whole reason verifyAnchorChain descends through handles instead of
// recomposing anchors/committed/<slot> for every read, and it is a fact about
// file descriptors rather than about timing, so it can be asserted exactly.
func TestConfinedHandleIgnoresALaterParentSwap(t *testing.T) {
	base := t.TempDir()
	original := filepath.Join(base, "child")
	if err := os.MkdirAll(original, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(original, "member"), []byte("original\n"))

	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	handle, err := openConfinedSubdirectory(root, "child")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	// Swap a completely different directory into the same name, with a
	// same-named member holding different bytes.
	moved := filepath.Join(base, "child-moved")
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(base, "child")
	if err := os.MkdirAll(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(
		t, filepath.Join(replacement, "member"), []byte("substituted\n"),
	)
	writeFixtureFile(t, filepath.Join(replacement, "extra"), []byte("stray\n"))

	entries, err := readConfinedDirectory(handle)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "member" {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf(
			"the held handle enumerated %v; it must still describe the "+
				"directory it was opened on, not whatever now occupies the "+
				"name", names,
		)
	}
	content, err := readRootRegular(handle, "member", 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original\n" {
		t.Fatalf(
			"the held handle read %q; a rename over the name changed what its "+
				"reads reach, which is exactly the mixing the confined descent "+
				"exists to prevent", content,
		)
	}
	digest, err := sha256RootRegular(handle, "member")
	if err != nil {
		t.Fatal(err)
	}
	if digest != sha256OfFixture("original\n") {
		t.Fatalf("the held handle hashed the substituted member: %s", digest)
	}

	// And the ambient pathname now genuinely resolves elsewhere, so the
	// assertions above are about the descriptor rather than about nothing
	// having happened.
	ambient := readFixtureFile(t, filepath.Join(base, "child", "member"))
	if string(ambient) != "substituted\n" {
		t.Fatalf(
			"the swap did not take effect (%q); the test would have proved "+
				"nothing", ambient,
		)
	}
}

func sha256OfFixture(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
