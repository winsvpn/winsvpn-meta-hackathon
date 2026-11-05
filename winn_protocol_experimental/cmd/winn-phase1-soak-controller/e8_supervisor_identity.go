//go:build winn_incomplete_e8

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// e8SupervisorIdentity is the rehearsal-time identity of the supervisor
// executable named by the E6 verification receipt.
//
// The identity is only admitted when the E6-declared path resolves, through a
// retained no-follow descriptor, to the exact file object that backs the
// running supervisor process. Byte equality alone is never sufficient: a copy
// of the supervisor with identical contents at a different device/inode is
// rejected, so a mutable path cannot be substituted for the running image.
//
// The retained descriptor is held for the lifetime of the identity so every
// measurement below is taken from the same object that was digested. The
// identity therefore owns an operating-system resource and implements
// io.Closer.
//
// Ownership contract: verifyE8SupervisorIdentity returns either a non-nil
// identity that the caller must Close exactly once, or a nil identity and a
// non-nil error with no descriptor retained. Close is nil-safe and idempotent,
// so a caller may defer Close unconditionally and may also close on an error
// path without double-close risk.
type e8SupervisorIdentity struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	Size         int64  `json:"size"`
	Mode         uint32 `json:"mode"`
	ObjectDigest string `json:"object_digest"`

	// retained is the held no-follow descriptor of the supervisor
	// executable. It is unexported so it never enters the canonical
	// encoding used for ObjectDigest.
	retained  *os.File
	closeOnce sync.Once
	closeErr  error
}

const e8SupervisorIdentityDomain = "winn-realcycle-e8-supervisor-identity/v1"

// e8SupervisorIdentityBody is the exact canonical encoding that backs
// ObjectDigest. Field order is protocol state and must not be reordered.
type e8SupervisorIdentityBody struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

// Close releases the retained supervisor descriptor. It is safe on a nil
// identity and safe to call more than once; only the first call closes.
func (identity *e8SupervisorIdentity) Close() error {
	if identity == nil {
		return nil
	}
	identity.closeOnce.Do(func() {
		if identity.retained != nil {
			identity.closeErr = identity.retained.Close()
			identity.retained = nil
		}
	})
	return identity.closeErr
}

// Reverify measures the retained kernel process-image descriptor again. It
// never reopens identity.Path, so pathname replacement after acceptance cannot
// substitute another executable object.
func (identity *e8SupervisorIdentity) Reverify() error {
	if identity == nil || identity.retained == nil {
		return errors.New("E8 retained supervisor image is unavailable")
	}
	info, err := identity.retained.Stat()
	if err != nil {
		return errors.New("E8 retained supervisor image is unmeasurable")
	}
	device, inode, ok := e8FileObjectIdentity(info)
	if !ok || device != identity.Device || inode != identity.Inode ||
		info.Size() != identity.Size ||
		uint32(info.Mode().Perm()) != identity.Mode {
		return errors.New("E8 retained supervisor image metadata changed")
	}
	if _, err := identity.retained.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	copied, err := io.Copy(
		hash,
		io.LimitReader(identity.retained, maximumDigestedFile+1),
	)
	if err != nil || copied != identity.Size ||
		hex.EncodeToString(hash.Sum(nil)) != identity.SHA256 {
		return errors.New("E8 retained supervisor image bytes changed")
	}
	if _, err := identity.retained.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return nil
}

// e8SupervisorIdentityDigest derives the identity digest over the exact
// measured supervisor identity body.
func e8SupervisorIdentityDigest(
	identity *e8SupervisorIdentity,
) (string, error) {
	if identity == nil {
		return "", errors.New("E8 supervisor identity is missing")
	}
	return admittedDigest(e8SupervisorIdentityDomain, e8SupervisorIdentityBody{
		Path:   identity.Path,
		SHA256: identity.SHA256,
		Device: identity.Device,
		Inode:  identity.Inode,
		Size:   identity.Size,
		Mode:   identity.Mode,
	})
}

// e8SupervisorDeclaredPath validates the E6-declared supervisor path shape
// before any filesystem operation is attempted.
func e8SupervisorDeclaredPath(path string) error {
	if path == "" || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return errors.New("E8 supervisor executable path is not canonical")
	}
	return nil
}

// e8SupervisorMeasure builds the identity from a retained descriptor whose
// digest already matched the E6 declaration. Callers pass the device and
// inode measured from that same descriptor.
func e8SupervisorMeasure(
	receipt e6VerificationReceipt,
	retained *os.File,
	info os.FileInfo,
	device, inode uint64,
) (*e8SupervisorIdentity, error) {
	if retained == nil || info == nil {
		return nil, errors.New("E8 supervisor identity measurement is missing")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("E8 supervisor executable is not a regular file")
	}
	mode := uint32(info.Mode().Perm())
	if device == 0 || inode == 0 || info.Size() <= 0 || mode&0o111 == 0 {
		return nil, errors.New("E8 retained supervisor identity is incomplete")
	}
	identity := &e8SupervisorIdentity{
		Path:     receipt.SupervisorExecutablePath,
		SHA256:   receipt.SupervisorExecutableSHA256,
		Device:   device,
		Inode:    inode,
		Size:     info.Size(),
		Mode:     mode,
		retained: retained,
	}
	digest, err := e8SupervisorIdentityDigest(identity)
	if err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(digest) {
		return nil, errors.New("E8 supervisor identity digest is malformed")
	}
	identity.ObjectDigest = digest
	return identity, nil
}
