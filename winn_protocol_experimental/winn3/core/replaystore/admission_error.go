package replaystore

import "errors"

// ErrCapacity reports that the live WAL set is at its cap after expired-record
// GC. A later Append or Rewrite with a later nowUnix may succeed once expiry
// removes a live record. It is not stored as Writer.Err.
var ErrCapacity = errors.New("physical WAL capacity")

func isRetryableAdmissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrCapacity) {
		return true
	}
	return isTransientSpace(err)
}
