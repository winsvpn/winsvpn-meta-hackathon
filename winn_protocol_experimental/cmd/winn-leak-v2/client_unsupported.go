//go:build !linux

package main

import "errors"

func runClient(_ []string) error {
	return errors.New("winn-leak-v2 client is supported only on Linux")
}
