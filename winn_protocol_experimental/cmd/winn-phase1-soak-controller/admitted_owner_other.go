//go:build !unix

package main

import "os"

func admittedOwnedByCurrentUser(os.FileInfo) bool {
	return false
}
