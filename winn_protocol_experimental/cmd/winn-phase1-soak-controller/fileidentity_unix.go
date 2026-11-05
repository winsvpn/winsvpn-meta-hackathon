//go:build unix

package main

import (
	"fmt"
	"os"
	"reflect"
	"syscall"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	nlink  uint64
}

func identityFromInfo(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, fmt.Errorf("file identity is unavailable")
	}
	device, err := nonnegativeIdentityValue(stat.Dev, "device")
	if err != nil {
		return fileIdentity{}, err
	}
	inode, err := nonnegativeIdentityValue(stat.Ino, "inode")
	if err != nil {
		return fileIdentity{}, err
	}
	nlink, err := nonnegativeIdentityValue(stat.Nlink, "link count")
	if err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{device: device, inode: inode, nlink: nlink}, nil
}

func nonnegativeIdentityValue(value any, label string) (uint64, error) {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		signed := reflected.Int()
		if signed < 0 {
			return 0, fmt.Errorf("file %s identity is negative", label)
		}
		// #nosec G115 -- the negative signed range was rejected above.
		return uint64(signed), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return reflected.Uint(), nil
	default:
		return 0, fmt.Errorf(
			"file %s identity has an unsupported type", label,
		)
	}
}
