// SHA256Regular's two properties, tested separately.
//
// TYPE: the thing hashed has to be a real regular file, because a symbolic
// link, a FIFO or a directory in that position makes the manifest digest
// describe something other than the file the manifest names.
//
// STABILITY: the digest has to describe a byte sequence the file actually held.
// os.SameFile at open time cannot provide that — it proves inode identity, and
// an in-place rewrite preserves inode identity while changing every byte under
// a walk that is already in progress.
package securefile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestSHA256RegularHashesARealRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	content := []byte("sealed evidence artifact\n")
	writeTestFile(t, path, content)

	digest, err := SHA256Regular(path)
	if err != nil {
		t.Fatalf("hashing an ordinary regular file failed: %v", err)
	}
	if digest != digestOf(content) {
		t.Fatalf("digest = %s, want %s", digest, digestOf(content))
	}
	// Repeated calls over an unchanging file must agree, or the two-pass
	// stability contract would make ordinary hashing nondeterministic.
	again, err := SHA256Regular(path)
	if err != nil || again != digest {
		t.Fatalf("second call returned (%s, %v), want (%s, nil)",
			again, err, digest)
	}
}

func TestSHA256RegularRefusesEverythingThatIsNotARegularFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	writeTestFile(t, target, []byte("real content\n"))

	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is privileged on Windows")
		}
		link := filepath.Join(directory, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		// A symbolic link is REFUSED, not resolved. The target here is
		// byte-identical, so a content check could not tell the difference:
		// only the type check can, and what matters is that the sealed
		// directory does not contain the artifact its manifest names.
		if _, err := SHA256Regular(link); err == nil ||
			!strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("symlink error = %v, want a symbolic-link refusal", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		if _, err := SHA256Regular(directory); err == nil ||
			!strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("directory error = %v, want a regular-file refusal", err)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no POSIX FIFOs")
		}
		fifo := filepath.Join(directory, "fifo")
		if err := makeTestFIFO(fifo, 0o600); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		// This case is why the refusal happens BEFORE the open. A FIFO with
		// no writer blocks forever on open, so a version of this function that
		// opened first and type-checked afterwards would hang here rather than
		// report anything. The test would then time out instead of failing,
		// which is why it is stated explicitly.
		done := make(chan error, 1)
		go func() {
			_, err := SHA256Regular(fifo)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("fifo error = %v, want a regular-file refusal", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal(
				"SHA256Regular blocked on a FIFO; the type check must happen " +
					"before the open, or an unwritten FIFO wedges the harness",
			)
		}
	})

	t.Run("absent", func(t *testing.T) {
		if _, err := SHA256Regular(
			filepath.Join(directory, "no-such-file"),
		); !os.IsNotExist(err) {
			t.Fatalf("absent-file error = %v, want ErrNotExist", err)
		}
	})
}

// rewriteInPlace overwrites a file through an already-open descriptor, so the
// inode never changes. This is the exact shape that defeated the open-time
// os.SameFile proof: every identity check still agrees.
func rewriteInPlace(t *testing.T, path string, content []byte, keepTimes bool) {
	t.Helper()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(content, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if keepTimes {
		// Forging the metadata back is cheap for anyone who can write the
		// file, so the stability contract must not rest on it alone.
		if err := os.Chtimes(
			path, before.ModTime(), before.ModTime(),
		); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSHA256RegularNeverReturnsAMixedGenerationDigest is the stability test.
//
// The property asserted is exact: whatever comes back must be a digest the file
// genuinely had at some instant, or an error. A value that is neither — the
// digest of a first-half-of-A, second-half-of-B chimera — is the defect, and it
// is what a single streamed pass guarded only by an open-time os.SameFile
// produces.
//
// Both variants are run because they are caught by different halves of the
// contract. The plain rewrite changes the modification time, so the descriptor
// stat bracket refuses it. The restored-times rewrite forges size and mtime
// back, so only the second digest disagreeing catches it.
func TestSHA256RegularNeverReturnsAMixedGenerationDigest(t *testing.T) {
	for _, variant := range []struct {
		name      string
		keepTimes bool
	}{
		{"rewrite_updates_modification_time", false},
		{"rewrite_forges_size_and_modification_time_back", true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			// Large enough that a full pass is not instantaneous, so the
			// writer has a window to land inside it.
			const size = 12 << 20
			generationA := make([]byte, size)
			generationB := make([]byte, size)
			for index := range generationA {
				generationA[index] = byte(index)
				generationB[index] = byte(index) ^ 0xff
			}
			digestA := digestOf(generationA)
			digestB := digestOf(generationB)

			path := filepath.Join(t.TempDir(), "artifact")
			var mixed, errors, pureA, pureB int
			for attempt := 0; attempt < 24; attempt++ {
				writeTestFile(t, path, generationA)
				var writer sync.WaitGroup
				writer.Add(1)
				go func() {
					defer writer.Done()
					// Deliberately unsynchronised: the point is an ordinary
					// racing rewrite, not a precisely aimed one.
					time.Sleep(time.Duration(attempt%6) * time.Millisecond)
					rewriteInPlace(t, path, generationB, variant.keepTimes)
				}()
				digest, err := SHA256Regular(path)
				writer.Wait()

				switch {
				case err != nil:
					errors++
				case digest == digestA:
					pureA++
				case digest == digestB:
					pureB++
				default:
					mixed++
					t.Errorf(
						"attempt %d returned %s, which is neither the digest "+
							"of the file before the rewrite (%s) nor after it "+
							"(%s); this digest describes a byte sequence the "+
							"file never held",
						attempt, digest, digestA, digestB,
					)
				}
			}
			if mixed != 0 {
				t.FailNow()
			}
			t.Logf(
				"stable-read outcomes: %d refused, %d pre-rewrite, %d "+
					"post-rewrite, %d mixed",
				errors, pureA, pureB, mixed,
			)
			// Deliberately NO coverage assertion here, and that is a
			// correction rather than an omission. An earlier version failed
			// the test unless errors+pureA was nonzero, and called that proof
			// that the writer had interleaved with the hash. It is not: an
			// error also results from a rewrite that completed entirely
			// between the open and the first pass, which is not an
			// interleaving at all, and a pre-rewrite digest results from a
			// writer that lost the race outright. The predicate was satisfied
			// by runs that never exercised the property.
			//
			// The interleaving proof now lives in
			// TestSHA256RegularDetectsARewriteInsideTheHashingWindow, which
			// drives the rewrite from inside the hash and asserts where it
			// landed. This loop stays for opportunistic breadth over real
			// scheduling, and its counters are diagnostics.
		})
	}
}

// TestSHA256RegularRefusesATruncationDuringTheHash covers the other in-place
// shape: same inode, DIFFERENT length. The digest of a truncated read is a
// perfectly ordinary-looking value, and without the size bracket it would be
// sealed as the artifact's digest.
func TestSHA256RegularRefusesATruncationDuringTheHash(t *testing.T) {
	const size = 12 << 20
	content := make([]byte, size)
	for index := range content {
		content[index] = byte(index * 7)
	}
	path := filepath.Join(t.TempDir(), "artifact")
	full := digestOf(content)
	short := digestOf(content[:1024])

	var refused, whole, truncated int
	for attempt := 0; attempt < 24; attempt++ {
		writeTestFile(t, path, content)
		var writer sync.WaitGroup
		writer.Add(1)
		go func() {
			defer writer.Done()
			time.Sleep(time.Duration(attempt%6) * time.Millisecond)
			if err := os.Truncate(path, 1024); err != nil {
				t.Error(err)
			}
		}()
		digest, err := SHA256Regular(path)
		writer.Wait()
		switch {
		case err != nil:
			refused++
		case digest == full:
			whole++
		case digest == short:
			truncated++
		default:
			t.Fatalf(
				"attempt %d returned %s, which is the digest of neither the "+
					"whole file (%s) nor the truncated one (%s)",
				attempt, digest, full, short,
			)
		}
	}
	t.Logf("truncation outcomes: %d refused, %d whole, %d truncated",
		refused, whole, truncated)
	// No coverage assertion, for the reason given in the test above: an
	// outcome count cannot distinguish "the truncation landed mid-hash" from
	// "it landed just before the hash started". The deterministic proof is in
	// TestSHA256RegularDetectsARewriteInsideTheHashingWindow.
}

// TestSHA256RegularDetectsARewriteInsideTheHashingWindow is the deterministic
// proof, and it is what the two loops above cannot be.
//
// The mutation is driven FROM INSIDE the hash, through the package's test seam,
// after a chunk has been consumed and before the pass has finished. The test
// then asserts WHERE it landed — strictly after the first pass began and
// strictly before it read the whole file — so the precondition the property
// depends on is proved rather than hoped for. With that established, the
// outcome assertion can be exact instead of a set of acceptable answers: the
// first pass necessarily sees a mixture, the second necessarily sees the new
// content whole, and a refusal is therefore mandatory.
func TestSHA256RegularDetectsARewriteInsideTheHashingWindow(t *testing.T) {
	const size = 4 << 20
	generationA := make([]byte, size)
	generationB := make([]byte, size)
	for index := range generationA {
		generationA[index] = byte(index)
		generationB[index] = byte(index) ^ 0xff
	}

	for _, variant := range []struct {
		name    string
		keep    bool
		rewrite func(t *testing.T, path string, keep bool)
	}{
		{
			name: "in_place_rewrite",
			keep: false,
			rewrite: func(t *testing.T, path string, keep bool) {
				rewriteInPlace(t, path, generationB, keep)
			},
		},
		{
			// The variant the descriptor stat bracket is blind to. Only the
			// second digest can refuse this one, so it isolates that check.
			name: "in_place_rewrite_with_forged_size_and_mtime",
			keep: true,
			rewrite: func(t *testing.T, path string, keep bool) {
				rewriteInPlace(t, path, generationB, keep)
			},
		},
		{
			name: "truncation",
			keep: false,
			rewrite: func(t *testing.T, path string, _ bool) {
				if err := os.Truncate(path, 1024); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(variant.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact")
			writeTestFile(t, path, generationA)

			var firedPass int
			var firedAt int64
			var fired bool
			sha256RegularProgress = func(pass int, consumed int64) {
				if fired {
					return
				}
				fired = true
				firedPass, firedAt = pass, consumed
				variant.rewrite(t, path, variant.keep)
			}
			t.Cleanup(func() { sha256RegularProgress = nil })

			digest, err := SHA256Regular(path)

			// The precondition, asserted rather than assumed.
			if !fired {
				t.Fatal(
					"the seam never fired; the rewrite was not driven from " +
						"inside the hash and this test proved nothing",
				)
			}
			if firedPass != 1 {
				t.Fatalf(
					"the rewrite landed during pass %d; it must land inside "+
						"the FIRST pass for that pass to observe a mixture",
					firedPass,
				)
			}
			if firedAt <= 0 || firedAt >= size {
				t.Fatalf(
					"the rewrite landed after %d of %d bytes; it must land "+
						"strictly inside the hashing window", firedAt, size,
				)
			}

			if err == nil {
				t.Fatalf(
					"a rewrite that provably landed after %d of %d bytes of "+
						"the first pass produced the clean digest %s; that "+
						"digest describes a byte sequence the file never held",
					firedAt, size, digest,
				)
			}
			if digest != "" {
				t.Fatalf("a refusal returned a digest as well: %q", digest)
			}
			t.Logf(
				"rewrite landed at byte %d of %d in pass %d; refused: %v",
				firedAt, size, firedPass, err,
			)
		})
	}
}

// TestSHA256RegularProgressSeamIsInertInProduction pins that the seam is off
// unless a test turns it on. A hook left armed by a previous test would make
// every later result meaningless.
func TestSHA256RegularProgressSeamIsInertInProduction(t *testing.T) {
	if sha256RegularProgress != nil {
		t.Fatal(
			"the progress seam is armed outside a test that armed it; some " +
				"test is leaking it and every hash after that point is being " +
				"interfered with",
		)
	}
	path := filepath.Join(t.TempDir(), "artifact")
	content := []byte("ordinary content\n")
	writeTestFile(t, path, content)
	digest, err := SHA256Regular(path)
	if err != nil || digest != digestOf(content) {
		t.Fatalf("SHA256Regular = (%s, %v)", digest, err)
	}
}
