//go:build !unix

package closedarchive

import "errors"

func makeFIFO(string) error {
	return errors.New("named pipes are unavailable on this platform")
}
