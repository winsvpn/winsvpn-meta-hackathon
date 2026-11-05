//go:build linux

package main

import (
	"errors"
	"os"

	"winsvpn.local/winnprotocol/internal/realcycle"

	"golang.org/x/sys/unix"
)

var closeE7TemporaryOperation = func(file *os.File) error {
	return file.Close()
}

var renameE7NoReplaceOperation = func(
	directory *secureDirectory, temporaryName string,
) error {
	return unix.Renameat2(
		int(directory.file.Fd()), temporaryName,
		int(directory.file.Fd()), e7ReceiptFile,
		unix.RENAME_NOREPLACE,
	)
}

var syncE7DirectoryOperation = func(directory *secureDirectory) error {
	return directory.Sync()
}

var readAuthenticatedE7ReceiptOperation = readAuthenticatedE7Receipt
var verifyE7DirectoryOperation = verifyAdmittedDirectoryPath

func publishE7Receipt(
	directory *secureDirectory,
	encoded []byte,
	expected e7VerificationReceipt,
	expectation realcycle.ExecutionAuthorizationExpectation,
	expectedResult realcycle.ExecutionAuthorizationResult,
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
		return errors.New("E7 temporary receipt lacks exact private identity")
	}
	if err := writeAllOperation(temporary, encoded); err != nil {
		abandon()
		return err
	}
	if err := syncFileOperation(temporary); err != nil {
		abandon()
		return err
	}
	if err := closeE7TemporaryOperation(temporary); err != nil {
		_ = temporary.Close()
		_ = directory.Remove(name)
		return err
	}
	if err := renameE7NoReplaceOperation(directory, name); err != nil {
		_ = directory.Remove(name)
		if errors.Is(err, unix.EEXIST) {
			return os.ErrExist
		}
		return err
	}
	if err := syncE7DirectoryOperation(directory); err != nil {
		return indeterminateE6Publication(
			"E7-parent-directory-fsync", false, false, err,
		)
	}
	replayed, result, raw, err := readAuthenticatedE7ReceiptOperation(
		directory, expectation,
	)
	if err != nil || replayed != expected || result != expectedResult ||
		string(raw) != string(encoded) {
		return indeterminateE6Publication(
			"E7-durable-authenticated-readback", true, false,
			errors.New("E7 durable authenticated replay mismatch"),
		)
	}
	if err := verifyE7DirectoryOperation(directory); err != nil {
		return indeterminateE6Publication(
			"E7-postpublication-directory-identity", true, true, err,
		)
	}
	return nil
}
