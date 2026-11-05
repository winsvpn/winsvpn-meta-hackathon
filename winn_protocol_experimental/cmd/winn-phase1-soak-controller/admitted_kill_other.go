//go:build !unix

package main

import "errors"

var admittedKillGroup = func(int) error {
	return errors.New("admitted process-group termination requires a Unix platform")
}
