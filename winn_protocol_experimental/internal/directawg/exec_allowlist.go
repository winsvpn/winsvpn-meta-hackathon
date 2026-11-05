package directawg

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// LinuxExecAllowList refuses any command PATH STRING that is not one of the
// exact strings a particular harness runner was configured with.
//
// WHAT THIS IS. Six harness command runners (winn-acceptance, winn-auto-e2e,
// winn-h3-e2e, winn-teardown-e2e, winn-leak-v2, winn-aicore-directawg-e2e) hold
// one of these and call Require at the top of their own Run and Start, before
// exec. Membership is EXACT string equality against the absolute paths the
// operator named on the command line. Normalising, resolving symbolic links or
// matching by basename would each admit a path the operator did not name, which
// is the class being excluded, so none of that is done.
//
// WHAT THIS IS NOT, STATED PLAINLY BECAUSE THE EARLIER WORDING OVERCLAIMED IT.
// The previous comment here described the result as making "this process only
// ever runs these binaries" an enforced property. That is false in three
// separate ways, and each one matters to a reviewer deciding how much weight to
// put on it:
//
//   - It pins NAMES, not executable objects. Nothing here binds an inode, a
//     device/inode pair, or a content digest. Anyone able to replace the file at
//     an allowed path — by rename, by rebuild, by package upgrade — produces a
//     different executable that this list still accepts, because the string did
//     not change. validateLinuxExecutable, which runs on the same paths, is a
//     shape check (absolute, regular, some execute bit) performed with os.Stat,
//     so it FOLLOWS symbolic links and likewise proves nothing about identity.
//   - It is per-runner, not per-process. It applies to the six harness runners
//     listed above and to nothing else in the process.
//   - Two other exec boundaries in this package are NOT covered by it at all:
//     execLinuxRunner in linux_exec.go, which is what newExecLinuxRunner returns
//     and therefore what the Core default controller and policy paths use; and
//     runBoundedStatusCommand in status_cli.go, which CLIStatusSource uses to
//     run the AWG CLI. Both take their path from configuration and check it with
//     validateLinuxExecutable only.
//
// So the accurate claim, and the only one this type should ever be cited for,
// is: SELECTED HARNESS RUNNERS REFUSE PATH NAMES THEY WERE NOT CONFIGURED WITH.
// It is a scoped, reviewable narrowing of one specific exec surface, not a
// project-wide execution control.
//
// WHY NOT PIN IDENTITY INSTEAD. That option was considered and rejected on
// purpose. Content-pinning would have to cover the two uncovered boundaries as
// well to mean anything, and those run the operator's own system binaries — ip,
// nft, resolvectl, awg/wg — which a routine package upgrade replaces. There is
// no place in the current design where an operator declares expected digests,
// so a pin would either be self-updating (and therefore not a pin) or would
// break every controller after an ordinary system update. Inode binding is
// weaker still: os/exec re-resolves the path at exec time, so binding an inode
// at check time narrows a race window without closing it. The honest choice is
// the narrow claim above, and it is written down rather than left implied.
//
// This is authorised-lab tooling operating on hosts the operator controls. The
// point is not to defend against the operator; it is to make one specific
// property — these runners launch only names the operator listed — enforced in
// one reviewable place instead of resting on every call site's good behaviour.
type LinuxExecAllowList struct {
	allowed map[string]struct{}
}

// NewLinuxExecAllowList builds an allow-list from the configured executable
// paths. Empty entries are ignored, so a harness that legitimately leaves an
// optional binary unset does not have to special-case it.
func NewLinuxExecAllowList(paths ...string) (*LinuxExecAllowList, error) {
	allowed := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf(
				"executable %q is not an absolute path; a relative name would "+
					"be resolved against PATH at exec time, which is not a "+
					"fixed set", path,
			)
		}
		allowed[path] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New(
			"an executable allow-list with no entries would refuse every " +
				"command; the runner's configured binaries are missing",
		)
	}
	return &LinuxExecAllowList{allowed: allowed}, nil
}

// Require reports whether this exact path STRING is one the runner was
// configured with. It says nothing about what currently lives at that path; see
// the type comment.
//
// A nil receiver is a refusal rather than a pass. A runner constructed without
// a list has no basis for the statement, and defaulting that to "allowed" would
// make forgetting to wire one up indistinguishable from being configured with
// everything.
func (list *LinuxExecAllowList) Require(path string) error {
	if list == nil {
		return errors.New(
			"this command runner was built without an executable allow-list, " +
				"so it cannot establish that the binary it is about to launch " +
				"is one of the configured ones",
		)
	}
	if _, ok := list.allowed[path]; ok {
		return nil
	}
	return fmt.Errorf(
		"refusing to execute %q: it is not one of this runner's configured "+
			"executables (%s)", path, strings.Join(list.Paths(), ", "),
	)
}

// Paths returns the allowed executables in a stable order, for diagnostics.
func (list *LinuxExecAllowList) Paths() []string {
	if list == nil {
		return nil
	}
	paths := make([]string, 0, len(list.allowed))
	for path := range list.allowed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
