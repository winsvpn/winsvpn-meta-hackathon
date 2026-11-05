//go:build !unix

package main

func isExtendedAttributeUnsupported(error) bool {
	return false
}
