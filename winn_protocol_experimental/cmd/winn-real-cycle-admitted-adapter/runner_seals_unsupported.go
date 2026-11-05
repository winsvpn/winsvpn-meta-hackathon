//go:build !linux

package main

import (
	"errors"
	"os"
)

func requireRunnerSeals(_ *os.File) error {
	return errors.New("runner memfd seals require Linux")
}
