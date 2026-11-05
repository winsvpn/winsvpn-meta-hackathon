package replaystore

import (
	"fmt"
	"io"
	"os"
)

func writeFull(f *os.File, raw []byte) error {
	for len(raw) > 0 {
		n, err := f.Write(raw)
		if n > 0 {
			raw = raw[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func verifyCompleteRecordFile(path string, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat complete record: %w", err)
	}
	if err := checkJournalFile(path, info); err != nil {
		return err
	}
	if info.Size() != RecordSize {
		return &RefusedError{Path: path, Why: fmt.Sprintf(
			"is %d bytes before publication, not one complete %d-byte record",
			info.Size(), RecordSize)}
	}
	return nil
}
