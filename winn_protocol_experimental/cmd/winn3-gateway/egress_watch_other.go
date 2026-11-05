//go:build !linux && !android

package main

import "errors"

// startRouteWatch has no rtnetlink here; the backstop sweep still runs.
func startRouteWatch() (<-chan struct{}, func(), error) {
	return nil, nil, errors.ErrUnsupported
}
