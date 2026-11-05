//go:build !linux

package main

import "errors"

func publishE5Plan(
	*secureDirectory, []byte, e5FourNodePlan,
) error {
	return errors.New("E5 plan publication is Linux-only")
}
