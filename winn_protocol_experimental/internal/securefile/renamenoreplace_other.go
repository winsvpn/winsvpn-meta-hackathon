//go:build !linux && !darwin

package securefile

// renameNoReplace has no native atomic no-replace directory rename on this
// platform, so publication refuses rather than degrading.
//
// The alternative — claim the destination and move entries in one at a time —
// was implemented and removed. It exposes the real destination path while it is
// still incomplete, so a crash mid-move leaves a partial directory that every
// observer, including the next run, sees as an existing committed slot. Failing
// to publish is recoverable; publishing something that looks committed and is
// not is the failure atomic publication exists to prevent.
func renameNoReplace(oldPath, newPath string) error {
	return errRenameNoReplaceUnsupported
}
