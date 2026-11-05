//go:build !unix

package main

import "errors"

func makeFIFO(string) error {
	return errors.New("named pipes are not available on this platform")
}
