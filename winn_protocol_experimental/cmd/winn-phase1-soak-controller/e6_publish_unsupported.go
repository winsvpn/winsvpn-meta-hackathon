//go:build !linux

package main

import (
	"errors"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func publishE6Receipt(
	*secureDirectory,
	[]byte,
	e6VerificationReceipt,
	string,
	realcycle.SealedHandoffResult,
) error {
	return errors.New("E6 receipt publication is Linux-only")
}
