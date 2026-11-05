//go:build !linux

package main

import (
	"errors"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

func publishE7Receipt(
	*secureDirectory,
	[]byte,
	e7VerificationReceipt,
	realcycle.ExecutionAuthorizationExpectation,
	realcycle.ExecutionAuthorizationResult,
) error {
	return errors.New("E7 durable receipt publication is Linux-only")
}
