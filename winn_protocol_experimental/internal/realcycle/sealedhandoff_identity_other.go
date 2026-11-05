//go:build !unix

package realcycle

import "errors"

func readNoSymlinkRegular(
	string, int,
) ([]byte, fileSnapshot, error) {
	return nil, fileSnapshot{},
		errors.New("retained no-symlink descriptor walk is unsupported")
}

func recheckNoSymlinkRegular(string, fileSnapshot, int) error {
	return errors.New("retained no-symlink descriptor walk is unsupported")
}
