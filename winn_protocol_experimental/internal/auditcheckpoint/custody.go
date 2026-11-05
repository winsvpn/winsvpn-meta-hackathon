package auditcheckpoint

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Known-leak detection for finalizer key material.
//
// WHAT THE SECURITY BOUNDARY ACTUALLY IS — read this before reading the code,
// because the code below is NOT it.
//
// The checkpoint's value rests on the process that writes audit records being
// unable to produce a checkpoint. On the producing host that process is the
// carrier server, launched as root. A finalizer seed stored anywhere on that
// host would be readable by it whatever the permission bits said, and its
// environment readable whatever was scrubbed before exec: mode 0600 and
// `env -u` defend against a DIFFERENT, lesser identity and are worth nothing
// against a party that already holds the credential owner's privilege.
//
// The boundary is therefore this, and only this: provisioning and orchestration
// never transfer the seed to the producing host at all, and the controller that
// holds it is a separate machine with a separate identity and no shared
// privilege domain. That is what makes the separation real.
//
// DetectKnownFinalizerLeaks is a SECONDARY check, not that boundary. It is a
// heuristic scan for the obvious ways a credential gets left somewhere it
// should not be — a seed copied into a deployment directory, an environment
// variable pointing at one. It looks only where it is told to look, and it
// recognises material only by name and by shape, so a seed renamed to something
// innocuous, or referenced through a variable whose name says nothing, passes it
// unnoticed. It can find a leak. It can never establish absence, and nothing in
// this package, its callers, or its tests may claim that it does.
//
// What it CAN do honestly is fail closed. A scan root it cannot read is not
// evidence of cleanliness; it is an unexamined region, and it is reported as an
// error rather than skipped.

// finalizerMarkers are the filename substrings that identify finalizer key
// material by name. Deliberately broad, and still trivially evaded by renaming:
// see the package note above on what this check is and is not.
var finalizerMarkers = []string{"finalizer", "audit-close", "auditclose"}

// seedSize is the finalizer seed length. A file of exactly this size whose name
// suggests a seed is treated as finalizer material even without a marker,
// because renaming a seed is the obvious way to hide one.
const seedSize = 32

// FinalizerLeak names one piece of finalizer material found somewhere it must
// not be.
type FinalizerLeak struct {
	Kind     string
	Location string
	Reason   string
}

func (v FinalizerLeak) String() string {
	return fmt.Sprintf("%s %s: %s", v.Kind, v.Location, v.Reason)
}

// DetectKnownFinalizerLeaks searches the places it is given for finalizer key
// material that a deployment mistake would plausibly have left there.
//
// It does NOT prove the host is clean — see the package note. A nil return
// means "none of the known leak shapes were found in the regions examined",
// which is weaker than absence and must be reported as such.
//
// scanRoots are directories the audit writer could read — the run root, the
// deployment directory, the binary directory. environ is the environment the
// writer will inherit, normally os.Environ().
//
// Two outcomes are errors, and both are fail-closed on purpose:
//
//   - a leak was found. The checkpoint that would later close this run's trail
//     could have been produced by the party it constrains.
//   - a scan root or subtree could not be read. That region is unexamined, and
//     an unexamined region is not a clean one.
func DetectKnownFinalizerLeaks(scanRoots []string, environ []string) error {
	var violations []FinalizerLeak

	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" {
			continue
		}
		lowered := strings.ToLower(name)
		if !containsMarker(lowered) {
			continue
		}
		violations = append(violations, FinalizerLeak{
			Kind:     "environment variable",
			Location: name,
			Reason: "the writer would inherit a reference to finalizer " +
				"material; the credential must not be reachable from this host",
		})
	}

	for _, root := range scanRoots {
		if root == "" {
			return fmt.Errorf(
				"leak scan root is empty, so it cannot be scanned; a root " +
					"the caller believes is being examined and is not is " +
					"worse than no scan at all",
			)
		}
		// Every configured root must be a directory this process can inspect.
		// A root that does not exist, or that turns out to be a regular file,
		// is a misconfiguration: the caller believes some region is being
		// examined and it is not. Continuing past either would report "no leaks
		// found" over ground nobody looked at, which is the one thing this
		// function must never do.
		info, err := os.Lstat(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf(
					"leak scan root %s does not exist, so it cannot be "+
						"scanned; a root the caller believes is being examined "+
						"and is not is worse than no scan at all", root,
				)
			}
			return fmt.Errorf("inspect leak scan root %s: %w", root, err)
		}
		if !info.IsDir() {
			return fmt.Errorf(
				"leak scan root %s is not a directory, so it cannot be scanned",
				root,
			)
		}
		err = filepath.WalkDir(root, func(
			path string, entry fs.DirEntry, err error,
		) error {
			if err != nil {
				// Fail closed. A directory this scan cannot read is a region it
				// cannot say anything about, and reporting "no leaks found"
				// over an unexamined subtree would be a false statement, not a
				// conservative one.
				return fmt.Errorf(
					"cannot examine %s, so this host cannot be scanned: %w",
					path, err,
				)
			}
			if entry.IsDir() {
				return nil
			}
			name := strings.ToLower(entry.Name())
			// Name markers apply to any non-directory dirent, including
			// symlinks. A finalizer.seed that points elsewhere is still
			// named as finalizer material; treating it as uninteresting
			// because it is not a regular file reported the host clean.
			if containsMarker(name) {
				violations = append(violations, FinalizerLeak{
					Kind:     "file",
					Location: path,
					Reason: "its name identifies finalizer key material, " +
						"which must exist only on the controller",
				})
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			if strings.HasSuffix(name, ".seed") {
				fileInfo, statErr := entry.Info()
				if statErr != nil {
					return fmt.Errorf(
						"cannot examine %s, so this host cannot be scanned: %w",
						path, statErr,
					)
				}
				if fileInfo.Size() == seedSize {
					violations = append(violations, FinalizerLeak{
						Kind:     "file",
						Location: path,
						Reason: fmt.Sprintf(
							"it is a %d-byte seed file, the exact shape of an "+
								"ML-DSA finalizer seed", seedSize,
						),
					})
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("scan %s for finalizer material: %w", root, err)
		}
	}

	if len(violations) == 0 {
		return nil
	}
	rendered := make([]string, 0, len(violations))
	for _, violation := range violations {
		rendered = append(rendered, violation.String())
	}
	sort.Strings(rendered)
	return fmt.Errorf(
		"audit finalizer material was found on the host that writes the audit "+
			"trail, so the checkpoint would be signed by a credential the "+
			"audited party can reach; finalization belongs on the controller, "+
			"and the seed must never be provisioned here. Found: %s",
		strings.Join(rendered, "; "),
	)
}

func containsMarker(lowered string) bool {
	for _, marker := range finalizerMarkers {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}
