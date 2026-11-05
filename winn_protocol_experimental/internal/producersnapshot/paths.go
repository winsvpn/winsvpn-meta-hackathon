package producersnapshot

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// requireEvidenceRelative enforces that a recorded archive path is canonical
// and strictly inside the matrix's evidence directory.
//
// This runs while batch records are loaded, which is before the first anchor.
// The verifier rejects an escaping path later, but "later" is after two
// external providers have signed — an irreversible step spent to learn
// something decidable from a string. Confinement belongs at the point the
// string is first believed.
//
// Substring checks for ".." are not sufficient on their own: they accept
// "evidence/..foo" while rejecting the legitimate "evidence/a..b", and they say
// nothing about absolute paths, backslashes, embedded NULs, or non-canonical
// forms like "evidence/./x". The path is therefore required to be exactly its
// own cleaned form, to begin with the evidence directory, and to name a single
// entry beneath it.
func requireEvidenceRelative(recorded string) error {
	if recorded == "" {
		return errors.New("the recorded path is empty")
	}
	if strings.ContainsRune(recorded, 0) ||
		strings.ContainsRune(recorded, '\\') {
		return errors.New("the recorded path contains an illegal character")
	}
	// path, not filepath, for the same reason canonicalLabel exists: `recorded`
	// is a canonical slash-separated PROTOCOL value read out of a signed record,
	// not a local pathname. On Windows filepath.Clean("evidence/x") returns
	// "evidence\\x", so a filepath-based canonicality check would reject every
	// legitimate record on that platform while this one accepts exactly the
	// same set everywhere.
	if path.IsAbs(recorded) || strings.HasPrefix(recorded, "/") {
		return errors.New("the recorded path is absolute")
	}
	if path.Clean(recorded) != recorded {
		return fmt.Errorf(
			"the recorded path is not canonical (cleans to %q)",
			path.Clean(recorded),
		)
	}
	if !strings.HasSuffix(recorded, pendingArchive) {
		return fmt.Errorf("the recorded path is not a %s archive", pendingArchive)
	}
	directory, name, found := strings.Cut(recorded, "/")
	if !found || directory != "evidence" {
		return errors.New(
			"the recorded path is not directly inside the evidence directory",
		)
	}
	if name == "" || strings.Contains(name, "/") {
		return errors.New(
			"the recorded path names something other than a single archive " +
				"directly under evidence/",
		)
	}
	if name == "." || name == ".." || strings.HasPrefix(name, "..") {
		return errors.New("the recorded path traverses upward")
	}
	return nil
}
