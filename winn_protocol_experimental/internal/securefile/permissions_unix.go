//go:build !windows

package securefile

import "os"

func validatePrivatePath(_ string, _ bool) error {
	return nil
}

func securePrivatePath(_ string) error { return nil }

func validateOpenedPrivateFile(_ *os.File) error { return nil }
