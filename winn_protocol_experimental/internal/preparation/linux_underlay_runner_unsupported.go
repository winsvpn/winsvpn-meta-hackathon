//go:build !linux

package preparation

import "errors"

func newDefaultLinuxUnderlayRunner(
	string,
	string,
) (LinuxUnderlayCommandRunner, error) {
	return nil, errors.New(
		"linux underlay authorization requires Linux or an injected test runner",
	)
}
