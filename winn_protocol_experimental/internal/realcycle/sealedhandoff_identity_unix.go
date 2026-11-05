//go:build unix

package realcycle

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// readNoSymlinkRegular resolves an absolute path one component at a time from
// a retained root descriptor. Every directory and the final file are opened
// with O_NOFOLLOW, so no pathname check is separated from the descriptor used
// to read the object.
func readNoSymlinkRegular(
	path string, limit int,
) ([]byte, fileSnapshot, error) {
	if !filepath.IsAbs(path) || path == string(filepath.Separator) ||
		filepath.Clean(path) != path || limit <= 0 {
		return nil, fileSnapshot{}, errors.New("physical path is invalid")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 0 {
		return nil, fileSnapshot{}, errors.New("physical path is empty")
	}
	parentFD, err := unix.Open(
		"/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, fileSnapshot{}, err
	}
	defer func() {
		if parentFD >= 0 {
			_ = unix.Close(parentFD)
		}
	}()
	for _, component := range components[:len(components)-1] {
		if component == "" || component == "." || component == ".." {
			return nil, fileSnapshot{}, errors.New("physical path component is invalid")
		}
		nextFD, openErr := unix.Openat(
			parentFD, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
		)
		if openErr != nil {
			return nil, fileSnapshot{}, errors.New("physical ancestor is unsafe")
		}
		if closeErr := unix.Close(parentFD); closeErr != nil {
			_ = unix.Close(nextFD)
			parentFD = -1
			return nil, fileSnapshot{}, closeErr
		}
		parentFD = nextFD
	}
	name := components[len(components)-1]
	if name == "" || name == "." || name == ".." {
		return nil, fileSnapshot{}, errors.New("physical file name is invalid")
	}
	fd, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0,
	)
	if err != nil {
		return nil, fileSnapshot{}, errors.New("physical file is unsafe")
	}
	// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fileSnapshot{}, errors.New("physical descriptor is invalid")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !safeRegular(before) {
		return nil, fileSnapshot{}, errors.New("physical object is not a safe regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, fileSnapshot{}, errors.New("physical object exceeds limit or is unreadable")
	}
	after, err := file.Stat()
	if err != nil || !sameSnapshot(before, after) {
		return nil, fileSnapshot{}, errors.New("physical object changed during read")
	}
	return data, fileSnapshot{
		info: before, sha256: sha256.Sum256(data),
	}, nil
}

func recheckNoSymlinkRegular(
	path string, snapshot fileSnapshot, limit int,
) error {
	_, current, err := readNoSymlinkRegular(path, limit)
	if err != nil || !sameSnapshot(snapshot.info, current.info) ||
		snapshot.sha256 != current.sha256 {
		return errors.New("physical object changed after validation")
	}
	return nil
}
