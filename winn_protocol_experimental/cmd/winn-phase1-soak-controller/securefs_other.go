//go:build !unix

package main

import (
	"fmt"
	"os"
)

// secureDirectory retains only the fields platform-neutral cleanup can
// observe. It has no identity field: this backend cannot obtain a stable file
// identity and openSecureDirectory always fails closed before returning one.
type secureDirectory struct {
	path string
	file *os.File
}

func openSecureDirectory(path string) (*secureDirectory, error) {
	return nil, fmt.Errorf("stable descriptor-relative directory operations unsupported for %s", path)
}
func (d *secureDirectory) Open(string, int, os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("descriptor-relative open unsupported")
}
func (d *secureDirectory) OpenDirectory(string) (*secureDirectory, error) {
	return nil, fmt.Errorf("descriptor-relative directory open unsupported")
}
func (d *secureDirectory) Mkdir(string, os.FileMode) error {
	return fmt.Errorf("descriptor-relative mkdir unsupported")
}
func (d *secureDirectory) Temp(os.FileMode) (*os.File, string, error) {
	return nil, "", fmt.Errorf("descriptor-relative temporary unsupported")
}
func (d *secureDirectory) Rename(string, string) error {
	return fmt.Errorf("descriptor-relative rename unsupported")
}
func (d *secureDirectory) Remove(string) error {
	return fmt.Errorf("descriptor-relative remove unsupported")
}
func (d *secureDirectory) Sync() error { return fmt.Errorf("directory sync unsupported") }
func (d *secureDirectory) FreeBytes() (int64, error) {
	return 0, fmt.Errorf("descriptor free-space unsupported")
}
func (d *secureDirectory) ReadDir() ([]os.DirEntry, error) {
	return nil, fmt.Errorf("descriptor-relative readdir unsupported")
}
func (d *secureDirectory) Close() error      { return nil }
func (d *secureDirectory) VerifyPath() error { return fmt.Errorf("directory identity unsupported") }
func atomicWriteDirectory(*secureDirectory, string, []byte, os.FileMode) error {
	return fmt.Errorf("descriptor-relative atomic write unsupported")
}
