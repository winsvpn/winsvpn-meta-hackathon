//go:build windows

package replaystore

import "golang.org/x/sys/windows"

func atomicNoReplaceSupported() bool { return false }

func renameNoReplace(oldPath, newPath string) error {
	oldUTF16, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newUTF16, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldUTF16, newUTF16, windows.MOVEFILE_WRITE_THROUGH)
}
