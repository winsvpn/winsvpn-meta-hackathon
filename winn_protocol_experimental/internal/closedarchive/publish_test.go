// Crash-boundary suite for closed-archive publication.
//
// The rule every test here enforces: at no instant may the destination name
// exist while holding something other than the complete, final artifact, and no
// interruption may leave a state a retry cannot recover from.
//
// The second half of that is the part the previous two-link shell version got
// wrong, and it is the reason these tests fail-inject rather than merely
// asserting the happy path. A crash between publishing the archive and
// publishing its pin file left the archive in place and the pin missing; the
// next run's preflight then saw an occupied output path and refused forever.
// That is a permanent stuck state produced by an ordinary interruption, and
// nothing short of injecting the interruption finds it.
package closedarchive

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func evidenceFixture(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	// Nested directories are ordinary evidence: the producer seals its manifest
	// with a recursive walk, so a diagnostics subtree is normal content and an
	// archiver that refused it would reject valid evidence outright.
	for name, content := range map[string]string{
		"carrier-audit.jsonl":         "{\"sequence\":1}\n",
		"evidence-manifest.sha256":    "abc  ./carrier-audit.jsonl\n",
		"environment.txt":             "source_digest=deadbeef\n",
		"audit-checkpoint.json":       "{\"schema\":\"winn-audit-checkpoint/v1\"}\n",
		"diagnostics/client/root.txt": "client namespace\n",
		"diagnostics/server/root.txt": "server namespace\n",
		"diagnostics/qdisc.json":      "{}\n",
	} {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An empty subdirectory: no manifest lists it, and a round-trip should
	// still reproduce the tree it was part of.
	if err := os.MkdirAll(
		filepath.Join(directory, "diagnostics", "empty"), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	return directory
}

// readArchive extracts the published archive into a name -> content map plus
// the set of directory members, so round-trip fidelity can be asserted.
func readArchive(t *testing.T, path string) (map[string]string, []string) {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decompressor, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer decompressor.Close()
	reader := tar.NewReader(decompressor)
	files := make(map[string]string)
	var directories []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			directories = append(directories, strings.TrimSuffix(header.Name, "/"))
		case tar.TypeReg:
			content, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			files[header.Name] = string(content)
		default:
			t.Fatalf("archive carries a %v member %q", header.Typeflag, header.Name)
		}
	}
	sort.Strings(directories)
	return files, directories
}

func destinationFor(t *testing.T, evidence string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "evidence.closed.tar.gz")
}

func TestPublishIsDeterministicAndComplete(t *testing.T) {
	evidence := evidenceFixture(t)
	first, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destinationFor(t, evidence),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destinationFor(t, evidence),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Determinism is not cosmetic here: the already-published recovery path
	// compares a rebuilt digest against what is on disk, and that comparison is
	// meaningless if two builds of the same evidence differ.
	if first.SHA256 != second.SHA256 {
		t.Fatalf(
			"two publications of identical evidence differ (%s vs %s); the "+
				"crash-recovery comparison cannot work",
			first.SHA256, second.SHA256,
		)
	}
	info, err := os.Lstat(first.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("published archive is %v, %d bytes", info.Mode(), info.Size())
	}
}

// TestCrashAtEveryStageLeavesARecoverableState is the requirement stated
// directly: fail-inject at each boundary, then retry, and require the retry to
// complete with exactly one published artifact.
func TestCrashAtEveryStageLeavesARecoverableState(t *testing.T) {
	for _, stage := range []Stage{
		StageAfterBuild, StageAfterSync, StageAfterLink, StageAfterUnlink,
	} {
		t.Run(string(stage), func(t *testing.T) {
			evidence := evidenceFixture(t)
			destination := destinationFor(t, evidence)

			// Establish what a clean publication produces, so the retry's
			// output can be compared against it rather than merely inspected.
			reference, err := Publish(Input{
				EvidenceDirectory: evidence,
				Destination: filepath.Join(
					t.TempDir(), "reference.closed.tar.gz",
				),
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = Publish(Input{
				EvidenceDirectory: evidence,
				Destination:       destination,
				crashAt:           stage,
			})
			if err == nil {
				t.Fatalf("the injected crash at %s did not abort", stage)
			}
			if !strings.Contains(err.Error(), "injected crash") {
				t.Fatalf("aborted for an unexpected reason: %v", err)
			}

			// Whatever the crash left behind, the destination must either not
			// exist or hold the complete final artifact. A partial file under
			// the final name is the failure this design exists to prevent.
			if info, statErr := os.Lstat(destination); statErr == nil {
				if !info.Mode().IsRegular() {
					t.Fatalf("destination is %v after a crash", info.Mode())
				}
				digest, err := sha256File(destination)
				if err != nil {
					t.Fatal(err)
				}
				if digest != reference.SHA256 {
					t.Fatalf(
						"a crash at %s left a partial or foreign artifact under "+
							"the final name (%s, want %s)",
						stage, digest, reference.SHA256,
					)
				}
			}

			// The retry must complete. This is the whole point: an interruption
			// is recoverable, never terminal.
			retry, err := Publish(Input{
				EvidenceDirectory: evidence,
				Destination:       destination,
			})
			if err != nil {
				t.Fatalf(
					"a retry after a crash at %s could not complete (%v); an "+
						"ordinary interruption has produced a permanently "+
						"stuck state", stage, err,
				)
			}
			if retry.SHA256 != reference.SHA256 {
				t.Fatalf(
					"the retry published a different artifact: %s, want %s",
					retry.SHA256, reference.SHA256,
				)
			}
			// A crash after the link means the artifact was already complete,
			// so the retry must recognise it rather than rebuild it.
			expectAlready := stage == StageAfterLink || stage == StageAfterUnlink
			if retry.AlreadyPublished != expectAlready {
				t.Fatalf(
					"retry after %s reported AlreadyPublished=%v, want %v",
					stage, retry.AlreadyPublished, expectAlready,
				)
			}

			// And exactly one artifact exists: no double publication, and no
			// second copy under another name.
			if err := CleanTemporaries(
				filepath.Dir(destination), time.Nanosecond,
			); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Dir(destination))
			if err != nil {
				t.Fatal(err)
			}
			archives := 0
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".tar.gz") {
					archives++
				}
			}
			if archives != 1 {
				t.Fatalf(
					"%d archives exist after a crash at %s and a retry, want 1",
					archives, stage,
				)
			}
		})
	}
}

// TestPublishRefusesADanglingSymlink is finding (3). [ -e ] is false for a
// dangling link, so the shell preflight read a stale entry from an earlier
// crash as "absent" and would have clobbered or misjudged it.
func TestPublishRefusesADanglingSymlink(t *testing.T) {
	evidence := evidenceFixture(t)
	directory := t.TempDir()
	destination := filepath.Join(directory, "evidence.closed.tar.gz")
	if err := os.Symlink(
		filepath.Join(directory, "gone"), destination,
	); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Prove the premise: a plain existence test really does miss this.
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("fixture is not a dangling link: %v", err)
	}
	_, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destination,
	})
	if err == nil {
		t.Fatal("a dangling symlink at the destination was published through")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestPublishRefusesAForeignIncumbent is the limit of the recovery rule: an
// occupied destination is a success only when it holds the artifact this run
// would itself have produced.
func TestPublishRefusesAForeignIncumbent(t *testing.T) {
	evidence := evidenceFixture(t)
	directory := t.TempDir()
	destination := filepath.Join(directory, "evidence.closed.tar.gz")
	if err := os.WriteFile(
		destination, []byte("someone else's archive\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destination,
	})
	if err == nil {
		t.Fatal("a foreign incumbent archive was accepted as this run's own")
	}
	if !strings.Contains(err.Error(), "different archive") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestPublishRefusesANonRegularDestination covers the remaining destination
// shapes a crash or a hostile filesystem could leave.
func TestPublishRefusesANonRegularDestination(t *testing.T) {
	evidence := evidenceFixture(t)
	directory := t.TempDir()
	destination := filepath.Join(directory, "evidence.closed.tar.gz")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destination,
	})
	if err == nil {
		t.Fatal("a directory at the destination was published over")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestPublishRefusesNonRegularEvidenceMembers keeps the archive's contents to
// things whose bytes are what they appear to be.
func TestPublishRefusesNonRegularEvidenceMembers(t *testing.T) {
	evidence := evidenceFixture(t)
	if err := os.Symlink(
		"/etc/passwd", filepath.Join(evidence, "sneaky.txt"),
	); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destinationFor(t, evidence),
	})
	if err == nil {
		t.Fatal("evidence containing a symlink was archived")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestNestedDirectoriesArchiveAndRoundTrip is the compatibility requirement.
// The producer's manifest is sealed with a recursive walk, so evidence
// subdirectories are valid content; an archiver that treated every non-regular
// entry as an error rejected all of them.
func TestNestedDirectoriesArchiveAndRoundTrip(t *testing.T) {
	evidence := evidenceFixture(t)
	result, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destinationFor(t, evidence),
	})
	if err != nil {
		t.Fatalf("evidence with nested directories was refused: %v", err)
	}
	base := filepath.Base(evidence)
	files, directories := readArchive(t, result.Destination)

	// Every file on disk, at its own path, with its own bytes.
	want := map[string]string{
		base + "/carrier-audit.jsonl":         "{\"sequence\":1}\n",
		base + "/evidence-manifest.sha256":    "abc  ./carrier-audit.jsonl\n",
		base + "/environment.txt":             "source_digest=deadbeef\n",
		base + "/audit-checkpoint.json":       "{\"schema\":\"winn-audit-checkpoint/v1\"}\n",
		base + "/diagnostics/client/root.txt": "client namespace\n",
		base + "/diagnostics/server/root.txt": "server namespace\n",
		base + "/diagnostics/qdisc.json":      "{}\n",
	}
	if len(files) != len(want) {
		t.Fatalf("archive holds %d files, want %d: %v", len(files), len(want), files)
	}
	for name, content := range want {
		got, present := files[name]
		if !present {
			t.Fatalf("archive is missing %s", name)
		}
		if got != content {
			t.Fatalf("%s round-tripped as %q, want %q", name, got, content)
		}
	}

	// Directory structure survives, including the subdirectory no manifest
	// would list.
	wantDirectories := []string{
		base + "/diagnostics",
		base + "/diagnostics/client",
		base + "/diagnostics/empty",
		base + "/diagnostics/server",
	}
	if strings.Join(directories, ",") != strings.Join(wantDirectories, ",") {
		t.Fatalf(
			"archive directories are %v, want %v", directories, wantDirectories,
		)
	}
}

// TestNestedArchiveIsByteIdentical pins determinism over a nested tree. The
// already-published crash-recovery path compares a rebuilt digest against the
// artifact on disk, and that comparison is meaningless unless two builds of the
// same tree produce the same bytes — including the same member ORDER, which a
// raw directory walk does not guarantee.
func TestNestedArchiveIsByteIdentical(t *testing.T) {
	evidence := evidenceFixture(t)
	digests := make([]string, 3)
	for index := range digests {
		result, err := Publish(Input{
			EvidenceDirectory: evidence,
			Destination:       destinationFor(t, evidence),
		})
		if err != nil {
			t.Fatal(err)
		}
		digests[index] = result.SHA256
	}
	for index := 1; index < len(digests); index++ {
		if digests[index] != digests[0] {
			t.Fatalf(
				"publication %d of an identical nested tree produced %s, "+
					"publication 0 produced %s; crash recovery cannot compare "+
					"digests", index, digests[index], digests[0],
			)
		}
	}
}

// TestArchiveRefusesSpecialFilesButNotDirectories keeps the distinction sharp:
// directories are structure, links and devices are indirection.
func TestArchiveRefusesSpecialFilesButNotDirectories(t *testing.T) {
	t.Run("symlink_inside_a_subdirectory", func(t *testing.T) {
		evidence := evidenceFixture(t)
		if err := os.Symlink(
			"/etc/passwd", filepath.Join(evidence, "diagnostics", "sneaky.txt"),
		); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, err := Publish(Input{
			EvidenceDirectory: evidence,
			Destination:       destinationFor(t, evidence),
		})
		if err == nil {
			t.Fatal("a symlink nested in a subdirectory was archived")
		}
		if !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		evidence := evidenceFixture(t)
		fifo := filepath.Join(evidence, "diagnostics", "pipe")
		if err := makeFIFO(fifo); err != nil {
			t.Skipf("fifos unavailable: %v", err)
		}
		_, err := Publish(Input{
			EvidenceDirectory: evidence,
			Destination:       destinationFor(t, evidence),
		})
		if err == nil {
			t.Fatal("a fifo was archived")
		}
		if !strings.Contains(err.Error(), "named pipe") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})
}

// TestArchiveBoundsTotalBytes covers the aggregate ceiling. Per-member and
// per-count limits are individually satisfiable by an input that is unbounded
// in total, so the whole-archive bound is the one that actually caps the work.
func TestArchiveBoundsTotalBytes(t *testing.T) {
	evidence := t.TempDir()
	// Two members, each far under the per-member limit, whose sum is over the
	// archive limit for this test's purposes. The production ceiling is 8 GiB,
	// so the arithmetic is exercised through archiveOneFile directly rather
	// than by writing eight gigabytes to a temp directory.
	if err := os.WriteFile(
		filepath.Join(evidence, "a.bin"), make([]byte, 1024), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writer := tar.NewWriter(io.Discard)
	_, err = archiveOneFile(writer, root, "base", "a.bin", maximumArchiveBytes)
	if err == nil {
		t.Fatal("a member that overflows the archive ceiling was accepted")
	}
	if !strings.Contains(err.Error(), "archive limit") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// Just under the ceiling still passes, so the bound is a bound and not a
	// blanket refusal.
	if _, err := archiveOneFile(
		writer, root, "base", "a.bin", maximumArchiveBytes-4096,
	); err != nil {
		t.Fatalf("a member within the ceiling was refused: %v", err)
	}
}

// TestCleanTemporariesSpares an in-flight publisher's file. A sweep that
// removed by name alone would unlink the temporary another publication is
// still writing, and the name is what that publication's link() needs.
func TestCleanTemporariesSparesConcurrentPublishers(t *testing.T) {
	directory := t.TempDir()
	fresh := filepath.Join(directory, temporaryPrefix+"in-flight.tar.gz")
	if err := os.WriteFile(fresh, []byte("being written\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(directory, temporaryPrefix+"abandoned.tar.gz")
	if err := os.WriteFile(stale, []byte("crashed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	if err := CleanTemporaries(directory, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatal(
			"the sweep deleted a temporary a concurrent publication was still " +
				"writing; that publication's link() would now fail spuriously",
		)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatal("the sweep left an abandoned temporary behind")
	}

	// A zero threshold is refused rather than treated as "delete everything".
	if err := CleanTemporaries(directory, 0); err == nil {
		t.Fatal("a zero age threshold was accepted")
	}
}

// TestConcurrentPublishersProduceOneArtifact exercises the real race: several
// publications of identical evidence to one destination.
func TestConcurrentPublishersProduceOneArtifact(t *testing.T) {
	evidence := evidenceFixture(t)
	directory := t.TempDir()
	destination := filepath.Join(directory, "evidence.closed.tar.gz")

	const publishers = 8
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	results := make([]Result, publishers)
	failures := make([]error, publishers)
	for index := 0; index < publishers; index++ {
		done.Add(1)
		go func(index int) {
			defer done.Done()
			start.Wait()
			results[index], failures[index] = Publish(Input{
				EvidenceDirectory: evidence,
				Destination:       destination,
			})
		}(index)
	}
	start.Done()
	done.Wait()

	digest := ""
	for index, err := range failures {
		if err != nil {
			t.Fatalf("publisher %d failed: %v", index, err)
		}
		if digest == "" {
			digest = results[index].SHA256
		} else if results[index].SHA256 != digest {
			t.Fatalf("publishers disagree on the artifact digest")
		}
	}
	if err := CleanTemporaries(directory, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d entries remain after concurrent publication, want 1", len(entries))
	}
}

// TestPublishRecognisesByteIdenticalIncumbent covers the already-published
// path without crash injection: a second Publish of the same evidence to the
// same destination, which is the controller-close retry after a first attempt
// that already linked. The crash-boundary suite reaches this path too; this
// test is the same sequence a production caller actually writes.
func TestPublishRecognisesByteIdenticalIncumbent(t *testing.T) {
	evidence := evidenceFixture(t)
	destination := destinationFor(t, evidence)
	first, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.AlreadyPublished {
		t.Fatal("the first publication reported AlreadyPublished")
	}
	second, err := Publish(Input{
		EvidenceDirectory: evidence,
		Destination:       destination,
	})
	if err != nil {
		t.Fatalf("republishing a byte-identical incumbent failed: %v", err)
	}
	if !second.AlreadyPublished {
		t.Fatal("the second publication did not recognise the incumbent")
	}
	if second.SHA256 != first.SHA256 {
		t.Fatalf("republish digest %s, want %s", second.SHA256, first.SHA256)
	}
}
