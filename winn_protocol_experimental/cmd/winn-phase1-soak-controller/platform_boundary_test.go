package main

import (
	"go/build"
	"slices"
	"testing"
)

func TestPlatformBoundaryFileSelection(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		tags     []string
		included []string
		excluded []string
	}{
		{
			name: "windows",
			goos: "windows",
			excluded: []string{
				"cgroup_unix.go",
				"cgroup_nonlinux.go",
				"fsutil_unix.go",
				"lock_atomic_unix.go",
				"resources_unix.go",
				"xattr_descriptor.go",
			},
		},
		{
			name: "darwin",
			goos: "darwin",
			tags: []string{"unix"},
			included: []string{
				"cgroup_unix.go",
				"cgroup_nonlinux.go",
				"fsutil_unix.go",
				"lock_atomic_unix.go",
				"resources_unix.go",
				"xattr_descriptor.go",
			},
		},
		{
			name: "linux",
			goos: "linux",
			tags: []string{"unix"},
			included: []string{
				"cgroup_unix.go",
				"cgroup_linux.go",
				"fsutil_unix.go",
				"lock_atomic_unix.go",
				"resources_unix.go",
				"xattr_descriptor.go",
			},
			excluded: []string{"cgroup_nonlinux.go"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := build.Default
			context.GOOS = test.goos
			context.GOARCH = "amd64"
			context.CgoEnabled = false
			context.BuildTags = append([]string(nil), test.tags...)
			pkg, err := context.ImportDir(".", 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range test.included {
				if !slices.Contains(pkg.GoFiles, file) {
					t.Errorf("%s did not select %s", test.goos, file)
				}
			}
			for _, file := range test.excluded {
				if slices.Contains(pkg.GoFiles, file) {
					t.Errorf("%s unexpectedly selected %s", test.goos, file)
				}
			}
		})
	}
}
