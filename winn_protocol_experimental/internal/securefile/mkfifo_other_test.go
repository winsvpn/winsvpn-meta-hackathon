//go:build !unix

package securefile

import "errors"

func makeTestFIFO(string, uint32) error {
	return errors.New("POSIX FIFOs are unavailable on this platform")
}
