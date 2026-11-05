//go:build linux

package main

import (
	"errors"
	"os"

	"winsvpn.local/winnprotocol/internal/realcycle"

	"golang.org/x/sys/unix"
)

var closeE6TemporaryOperation = func(file *os.File) error {
	return file.Close()
}

var renameE6NoReplaceOperation = func(
	directory *secureDirectory, temporaryName string,
) error {
	return unix.Renameat2(
		int(directory.file.Fd()), temporaryName,
		int(directory.file.Fd()), e6ReceiptFile,
		unix.RENAME_NOREPLACE,
	)
}

var syncE6DirectoryOperation = func(directory *secureDirectory) error {
	return directory.Sync()
}

var readAuthenticatedE6ReceiptOperation = readAuthenticatedE6Receipt

func publishE6Receipt(
	directory *secureDirectory,
	encoded []byte,
	expected e6VerificationReceipt,
	trustPath string,
	expectedResult realcycle.SealedHandoffResult,
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
		return errors.New("E6 temporary receipt lacks exact private identity")
	}
	if err := writeAllOperation(temporary, encoded); err != nil {
		abandon()
		return err
	}
	if err := syncFileOperation(temporary); err != nil {
		abandon()
		return err
	}
	if err := closeE6TemporaryOperation(temporary); err != nil {
		_ = temporary.Close()
		_ = directory.Remove(name)
		return err
	}
	err = renameE6NoReplaceOperation(directory, name)
	if err != nil {
		_ = directory.Remove(name)
		if errors.Is(err, unix.EEXIST) {
			return os.ErrExist
		}
		return err
	}
	if err := syncE6DirectoryOperation(directory); err != nil {
		return indeterminateE6Publication(
			"parent-directory-fsync", false, false, err,
		)
	}
	replayed, result, raw, err := readAuthenticatedE6ReceiptOperation(
		directory, trustPath,
	)
	if err != nil || replayed != expected || result != expectedResult ||
		string(raw) != string(encoded) {
		return indeterminateE6Publication(
			"durable-authenticated-readback", true, false,
			errors.New("E6 receipt durable authenticated replay mismatch"),
		)
	}
	if err := verifyAdmittedDirectoryPath(directory); err != nil {
		return indeterminateE6Publication(
			"postpublication-directory-identity", true, true, err,
		)
	}
	return nil
}
