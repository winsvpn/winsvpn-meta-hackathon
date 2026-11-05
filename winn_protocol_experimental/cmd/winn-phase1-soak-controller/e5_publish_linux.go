//go:build linux

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func publishE5Plan(
	directory *secureDirectory, encoded []byte, expected e5FourNodePlan,
) error {
	temporary, name, err := directory.Temp(0o400)
	if err != nil {
		return err
	}
	abandon := func() {
		_ = temporary.Close()
		_ = directory.Remove(name)
	}
	info, err := temporary.Stat()
	if err != nil || validateAdmittedPrivateFileInfo(
		info, temporary.Name(), 0o400,
	) != nil {
		abandon()
		return errors.New("E5 temporary plan lacks exact private identity")
	}
	if err := writeAllOperation(temporary, encoded); err != nil {
		abandon()
		return err
	}
	if err := syncFileOperation(temporary); err != nil {
		abandon()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = directory.Remove(name)
		return err
	}
	// #nosec G115 -- secureDirectory retains live Linux kernel descriptors,
	// which are represented by int in Renameat2.
	err = unix.Renameat2(
		int(directory.file.Fd()), name,
		int(directory.file.Fd()), e5PlanFile,
		unix.RENAME_NOREPLACE,
	)
	if err != nil {
		_ = directory.Remove(name)
		if errors.Is(err, unix.EEXIST) {
			return os.ErrExist
		}
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := verifyAdmittedDirectoryPath(directory); err != nil {
		return err
	}
	replayed, raw, err := readE5Plan(directory)
	if err != nil || replayed != expected || string(raw) != string(encoded) {
		return errors.New("E5 plan durable replay mismatch")
	}
	return nil
}
